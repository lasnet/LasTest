use crate::api::projects::resolve_project;
use crate::api::{authenticate, paged, require, validate_origin, ApiError, ApiResult, AppState};
use crate::db::jobs::EnqueueError;
use crate::domain::{Job, JobStatus, Role};
use crate::tasks::{self, registry};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitBody {
    pub task_type: String,
    #[serde(default = "empty_object")]
    pub params: Value,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

fn empty_object() -> Value {
    json!({})
}

#[derive(Debug, Deserialize)]
pub struct ChainBody {
    pub name: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

pub fn job_json(state: &AppState, job: &Job) -> Value {
    let artifacts = state.db.list_artifacts(&job.id).unwrap_or_default();
    let chain = job
        .chain_run_id
        .as_ref()
        .and_then(|id| state.db.chain_run_json(id).ok().flatten());
    let mut value = json!({
        "id": job.id,
        "project_id": job.project_id,
        "task_type": job.task_type,
        "params": job.params,
        "status": job.status.as_str(),
        "scope_version": job.scope_version,
        "scope_revision_id": job.scope_revision_id,
        "idempotency_key": job.idempotency_key,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
        "result": job.result,
        "counters": job.counters,
        "archived": job.archived,
        "chain_run_id": job.chain_run_id,
        "chain_order": job.chain_order,
        "artifacts": artifacts.iter().map(|artifact| json!({
            "id": artifact.id,
            "kind": artifact.kind,
            "size": artifact.size,
            "sha256": artifact.sha256,
            "created_at": artifact.created_at,
            "href": format!("/api/v2/evidence/{}", artifact.id)
        })).collect::<Vec<_>>(),
        "links": {
            "self": format!("/api/v2/jobs/{}", job.id),
            "cancel": format!("/api/v2/jobs/{}/cancel", job.id),
            "dashboard": format!("/api/v2/projects/{}/dashboard", job.project_id)
        }
    });
    if let Some(chain) = chain {
        value["chain"] = chain;
    }
    value
}

pub async fn task_types(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    Ok(Json(json!({
        "task_types": registry::task_types(&state.config),
        "web_check_rules": crate::tasks::web_checks::rules_catalog(),
        "providers": {
            "certspotter": {"configured": true, "token_configured": state.config.certspotter_token.is_some()},
            "shodan_internetdb": {"configured": true, "requires_key": false},
            "censys": {"configured": state.config.censys_api_id.is_some() && state.config.censys_api_secret.is_some(), "requires_key": true}
        },
        "excluded": [
            "full Nuclei template language and template catalog",
            "browser/JavaScript crawling",
            "scheduled runs",
            "OSINT and phishing stubs",
            "raw-packet, OS detection and NSE Nmap profiles"
        ],
        "limitations": {
            "max_concurrent_jobs": state.config.max_concurrent_jobs,
            "max_queue_targets": state.config.max_queue_targets,
            "http_timeout_seconds": state.config.http_timeout_seconds,
            "max_body_bytes": state.config.max_body_bytes,
            "tls_expiry_warning_days": state.config.tls_expiry_warning_days
        }
    })))
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<JobsQuery>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let status = match query.status.as_deref() {
        Some(value) => Some(
            JobStatus::parse(value).map_err(|err| ApiError::bad_request("invalid_status", err))?,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let (jobs, total) = state
        .db
        .list_jobs(Some(&project.id), status, limit, offset)
        .map_err(ApiError::internal)?;
    let items = jobs
        .iter()
        .map(|job| job_json(&state, job))
        .collect::<Vec<_>>();
    Ok(Json(paged(items, total, limit, offset)))
}

pub async fn submit_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SubmitBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    if body.task_type == registry::chain_task_type() {
        let chain = submit_chain_internal(
            &state,
            &session,
            &project,
            &body.params,
            None,
            body.idempotency_key.as_deref(),
        )
        .await?;
        return Ok((StatusCode::ACCEPTED, Json(chain)));
    }
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project scope is missing"))?;
    if scope.status != crate::domain::ScopeStatus::Approved {
        return Err(ApiError::conflict(
            "scope_not_approved",
            "the current scope revision must be approved before jobs can be submitted",
        ));
    }
    tasks::validate_submission(&body.task_type, &body.params, &state.config)
        .map_err(|err| ApiError::bad_request("invalid_params", format!("{err:#}")))?;
    tasks::validate_scope_targets(&body.task_type, &body.params, &scope.scope, &state.config)
        .map_err(|err| ApiError::bad_request("invalid_target", format!("{err:#}")))?;
    let key = body
        .idempotency_key
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    if key.is_some_and(|value| value.len() > 200) {
        return Err(ApiError::bad_request(
            "invalid_idempotency_key",
            "idempotency key is too long",
        ));
    }
    let job = state
        .db
        .enqueue_job(
            &project.id,
            &body.task_type,
            &body.params,
            &scope.id,
            scope.version,
            key,
            &session.user.username,
            None,
            None,
        )
        .map_err(map_enqueue_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"job": job_json(&state, &job)})),
    ))
}

fn map_enqueue_error(err: EnqueueError) -> ApiError {
    match err {
        EnqueueError::Conflict => ApiError::conflict(
            "idempotency_conflict",
            "the idempotency key was already used with different content",
        ),
        EnqueueError::ProjectNotFound => ApiError::not_found("project not found"),
        EnqueueError::Other(err) => ApiError::internal(format!("{err:#}")),
    }
}

pub async fn get_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let job = state
        .db
        .job_by_id(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    Ok(Json(json!({"job": job_json(&state, &job)})))
}

pub async fn cancel_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let job = state
        .db
        .cancel_job(&id, &session.user.username)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    Ok(Json(json!({
        "job": job_json(&state, &job),
        "message": if job.status == JobStatus::Running {
            "cancellation requested; the worker stops new requests at the next safe point"
        } else {
            "job is terminal or was cancelled in the queue"
        }
    })))
}

pub async fn submit_chain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ChainBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    let params = json!({"domains": body.domains, "targets": body.targets});
    let value = submit_chain_internal(
        &state,
        &session,
        &project,
        &params,
        body.name.as_deref(),
        body.idempotency_key.as_deref(),
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(value)))
}

async fn submit_chain_internal(
    state: &AppState,
    session: &crate::api::Session,
    project: &crate::domain::Project,
    params: &Value,
    name: Option<&str>,
    idempotency_key: Option<&str>,
) -> Result<Value, ApiError> {
    let domains: Vec<String> = params
        .get("domains")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| ApiError::bad_request("invalid_params", "domains must be strings"))?
        .unwrap_or_default();
    let targets: Vec<String> = params
        .get("targets")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| ApiError::bad_request("invalid_params", "targets must be strings"))?
        .unwrap_or_default();
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project scope is missing"))?;
    if scope.status != crate::domain::ScopeStatus::Approved {
        return Err(ApiError::conflict(
            "scope_not_approved",
            "the current scope revision must be approved before chains can be submitted",
        ));
    }
    let target_params = json!({"targets": targets, "domains": domains});
    tasks::validate_scope_targets("http.probe", &target_params, &scope.scope, &state.config)
        .map_err(|err| ApiError::bad_request("invalid_target", format!("{err:#}")))?;
    let key = idempotency_key.filter(|value| !value.trim().is_empty());
    if let Some(key) = key {
        if let Some(existing) = state
            .db
            .chain_run_by_idempotency(&project.id, key)
            .map_err(ApiError::internal)?
        {
            let value = state
                .db
                .chain_run_json(&existing)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::internal("chain disappeared"))?;
            return Ok(json!({"chain": value, "idempotent_replay": true}));
        }
    }
    let run_id = state
        .db
        .create_chain_run(
            &project.id,
            name.unwrap_or("All in one"),
            key,
            &session.user.username,
        )
        .map_err(ApiError::internal)?;
    let stages: Vec<(&str, Value)> = vec![
        (
            "subdomains.discover",
            json!({"domains": domains, "providers": ["certspotter"]}),
        ),
        ("dns.records", json!({})),
        (
            "http.probe",
            json!({"targets": targets, "mode": if targets.iter().any(|value| value.contains("://")) { "url" } else { "root" }}),
        ),
        ("urls.passive", json!({"domains": domains})),
        ("http.crawl", json!({})),
        (
            "web.checks",
            json!({"targets": targets.iter().filter(|value| value.starts_with("https://")).cloned().collect::<Vec<_>>()}),
        ),
    ];
    let mut jobs = Vec::new();
    for (position, (task_type, stage_params)) in stages.iter().enumerate() {
        let position = position as i64 + 1;
        if let Err(err) = state
            .db
            .add_chain_stage(&run_id, position, task_type, None, true)
        {
            let _ = state.db.cancel_chain(&run_id, &session.user.username);
            return Err(ApiError::internal(err));
        }
        let queued = state
            .db
            .enqueue_job(
                &project.id,
                task_type,
                stage_params,
                &scope.id,
                scope.version,
                Some(&format!(
                    "{}:{}:{}",
                    run_id,
                    position,
                    idempotency_key.unwrap_or("chain")
                )),
                &session.user.username,
                Some(&run_id),
                Some(position),
            )
            .map_err(|err| {
                let _ = state.db.cancel_chain(&run_id, &session.user.username);
                map_enqueue_error(err)
            })?;
        state
            .db
            .set_chain_stage_job(&run_id, position, &queued.id)
            .map_err(ApiError::internal)?;
        jobs.push(job_json(state, &queued));
    }
    let chain = state
        .db
        .chain_run_json(&run_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("chain disappeared"))?;
    Ok(json!({"chain": chain, "jobs": jobs}))
}

pub async fn list_chains(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let conn = state.db.connect().map_err(ApiError::internal)?;
    let mut stmt = conn
        .prepare(
            "SELECT id FROM chain_runs WHERE project_id = ?1 ORDER BY created_at DESC LIMIT 100",
        )
        .map_err(ApiError::internal)?;
    let ids = stmt
        .query_map(rusqlite::params![project.id], |row| row.get::<_, String>(0))
        .map_err(ApiError::internal)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;
    let mut items = Vec::new();
    for id in ids {
        if let Some(value) = state.db.chain_run_json(&id).map_err(ApiError::internal)? {
            items.push(value);
        }
    }
    Ok(Json(json!({"items": items, "total": items.len()})))
}

pub async fn get_chain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let chain = state
        .db
        .chain_run_json(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("chain run not found"))?;
    Ok(Json(json!({"chain": chain})))
}

pub async fn cancel_chain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    if state
        .db
        .chain_run_json(&id)
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found("chain run not found"));
    }
    state
        .db
        .cancel_chain(&id, &session.user.username)
        .map_err(ApiError::internal)?;
    let chain = state
        .db
        .chain_run_json(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("chain run not found"))?;
    Ok(Json(json!({"chain": chain})))
}

pub async fn get_evidence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let artifact = state
        .db
        .artifact_by_id(&id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("evidence not found"))?;
    let relative = crate::worker::normalize_relative_path(&artifact.relative_path)
        .map_err(|err| ApiError::bad_request("invalid_path", format!("{err:#}")))?;
    let path = state.config.evidence_dir().join(relative);
    let canonical_root =
        std::fs::canonicalize(state.config.evidence_dir()).map_err(ApiError::internal)?;
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| ApiError::not_found("evidence file is not available"))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(ApiError::forbidden(
            "invalid_path",
            "evidence path escapes the data directory",
        ));
    }
    let data = tokio::fs::read(&canonical)
        .await
        .map_err(|_| ApiError::not_found("evidence file is not available"))?;
    let content_type = match artifact.kind.as_str() {
        "nmap_xml" => "application/xml",
        "legacy_original" if artifact.relative_path.ends_with(".yaml") => "text/yaml",
        "legacy_original" if artifact.relative_path.ends_with(".txt") => "text/plain",
        _ => "application/json",
    };
    let filename = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("evidence");
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{}\"", filename.replace('"', "")),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from(data),
    )
        .into_response())
}
