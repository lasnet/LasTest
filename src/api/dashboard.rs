use crate::api::projects::resolve_project;
use crate::api::{authenticate, require, ApiError, ApiResult, AppState};
use crate::domain::{JobStatus, Role};
use crate::report;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?;
    let observations = state
        .db
        .all_observations(&project.id, 100_000)
        .map_err(ApiError::internal)?;
    let findings = state
        .db
        .all_findings(&project.id)
        .map_err(ApiError::internal)?;
    let assets = state
        .db
        .list_assets(&project.id, 100_000)
        .map_err(ApiError::internal)?;
    let (jobs, total_jobs) = state
        .db
        .list_jobs(Some(&project.id), None, 20, 0)
        .map_err(ApiError::internal)?;
    let mut counts = serde_json::Map::new();
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut open_ports = 0u64;
    let mut candidate_ports = 0u64;
    let mut severity = BTreeMap::new();
    for observation in &observations {
        if let Some(value) = counts.get_mut(&observation.kind) {
            let current = value.as_u64().unwrap_or(0);
            *value = json!(current + 1);
        } else {
            counts.insert(observation.kind.clone(), json!(1));
        }
        *sources.entry(observation.source.clone()).or_insert(0) += 1;
        if observation.kind == "port" {
            match observation.data.get("state").and_then(Value::as_str) {
                Some("open") => open_ports += 1,
                Some("timeout") | Some("error") => candidate_ports += 1,
                _ => {}
            }
        }
    }
    for finding in &findings {
        *severity.entry(finding.severity.clone()).or_insert(0) += 1;
    }
    let hosts: Vec<Value> = assets
        .iter()
        .filter(|asset| asset["kind"] == "host")
        .take(300)
        .cloned()
        .collect();
    let ips: Vec<Value> = assets
        .iter()
        .filter(|asset| asset["kind"] == "ip")
        .take(300)
        .cloned()
        .collect();
    let urls: Vec<Value> = assets
        .iter()
        .filter(|asset| asset["kind"] == "url")
        .take(300)
        .cloned()
        .collect();
    let recent_http: Vec<Value> = observations
        .iter()
        .filter(|observation| observation.kind == "http")
        .take(100)
        .map(|observation| {
            json!({
                "url": observation.asset,
                "source": observation.source,
                "observed_at": observation.observed_at,
                "data": observation.data
            })
        })
        .collect();
    let recent_ports: Vec<Value> = observations
        .iter()
        .filter(|observation| observation.kind == "port")
        .take(200)
        .map(|observation| {
            json!({
                "ip": observation.asset,
                "data": observation.data,
                "observed_at": observation.observed_at
            })
        })
        .collect();
    let partial = jobs.iter().any(|job| {
        matches!(
            job.status,
            JobStatus::Partial | JobStatus::Failed | JobStatus::Interrupted
        )
    });
    let data_status = if observations.is_empty() && total_jobs == 0 {
        "empty"
    } else if partial {
        "partial"
    } else {
        "ready"
    };
    let coverage: Vec<Value> = jobs
        .iter()
        .filter(|job| job.task_type == "web.checks")
        .filter_map(|job| job.result.get("rules").and_then(Value::as_array).cloned())
        .flatten()
        .take(30)
        .collect();
    Ok(Json(json!({
        "project": project,
        "scope": scope.map(|value| value.to_json()),
        "data_status": data_status,
        "metrics": {
            "hosts": assets.iter().filter(|asset| asset["kind"] == "host").count(),
            "ips": assets.iter().filter(|asset| asset["kind"] == "ip").count(),
            "urls": assets.iter().filter(|asset| asset["kind"] == "url").count(),
            "observations": observations.len(),
            "findings": findings.len(),
            "open_ports": open_ports,
            "candidate_ports": candidate_ports,
            "jobs": total_jobs
        },
        "observation_counts": counts,
        "sources": sources,
        "severity_counts": severity,
        "assets": {"hosts": hosts, "ips": ips, "urls": urls},
        "findings": findings.iter().take(200).collect::<Vec<_>>(),
        "recent_http": recent_http,
        "recent_ports": recent_ports,
        "jobs": jobs.iter().map(|job| crate::api::jobs::job_json(&state, job)).collect::<Vec<_>>(),
        "web_check_coverage": coverage,
        "availability": task_availability(&state, &jobs),
        "worker": state.db.worker_health(state.config.worker_lease_seconds.saturating_mul(3))
            .unwrap_or_else(|_| json!({"state": "unknown"}))
    })))
}

fn task_availability(state: &AppState, jobs: &[crate::domain::Job]) -> Value {
    let mut failed = BTreeMap::new();
    for job in jobs {
        if matches!(job.status, JobStatus::Partial | JobStatus::Failed) {
            let message = job
                .error
                .clone()
                .unwrap_or_else(|| job.status.as_str().to_string());
            failed.insert(job.task_type.clone(), message);
        }
    }
    let types = crate::tasks::registry::task_types(&state.config);
    json!({
        "unavailable": types.iter().filter(|item| !item.available).map(|item| json!({
            "task_type": item.name,
            "reason": item.unavailable_reason
        })).collect::<Vec<_>>(),
        "recent_source_errors": failed
    })
}

pub async fn export_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, format)): Path<(String, String)>,
) -> ApiResult<Response> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let snapshot = report::build_report(&state.db, &project.id).map_err(ApiError::internal)?;
    let (data, content_type, extension) = match format.as_str() {
        "json" => (
            report::render_json(&snapshot).map_err(ApiError::internal)?,
            "application/json",
            "json",
        ),
        "csv" => (
            report::render_csv(&snapshot).map_err(ApiError::internal)?,
            "text/csv; charset=utf-8",
            "csv",
        ),
        "discovery-json" => (
            report::render_discovery_json(&snapshot).map_err(ApiError::internal)?,
            "application/json",
            "discovery.json",
        ),
        "discovery-csv" => (
            report::render_discovery_csv(&snapshot).map_err(ApiError::internal)?,
            "text/csv; charset=utf-8",
            "discovery.csv",
        ),
        _ => {
            return Err(ApiError::not_found(
                "unsupported report format; use json, csv, discovery-json or discovery-csv",
            ))
        }
    };
    state
        .db
        .audit(
            &session.user.username,
            "report.export",
            "project",
            Some(&project.id),
            &json!({"format": format}),
        )
        .map_err(ApiError::internal)?;
    let filename = format!("{}-report.{}", project.name, extension);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename.replace('"', "")),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from(data),
    )
        .into_response())
}
