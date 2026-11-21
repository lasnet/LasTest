//! Project-scoped discovery candidate list/detail and extended export.
use super::projects::resolve_project;
use super::{authenticate, paged, require, ApiError, ApiResult, AppState};
use crate::db::discovery::CandidateFilter;
use crate::domain::{DnsVerification, IpMatch, Role};
use crate::report::csv_cell;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
pub struct CandidateQuery {
    #[serde(default)]
    q: String,
    source: Option<String>,
    dns_status: Option<String>,
    ip_match: Option<String>,
    scope_status: Option<String>,
    confidence: Option<String>,
    interest: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

fn validate_label(value: &Option<String>, allowed: &[&str], field: &str) -> Result<(), ApiError> {
    if let Some(value) = value {
        if !allowed.contains(&value.as_str()) {
            return Err(ApiError::bad_request(
                "invalid_filter",
                format!("{field} must be one of: {}", allowed.join(", ")),
            ));
        }
    }
    Ok(())
}

impl CandidateQuery {
    fn filter(&self) -> Result<CandidateFilter, ApiError> {
        let query = self;
        validate_label(
            &query.source,
            &["ptr", "shodan_internetdb", "censys"],
            "source",
        )?;
        if let Some(value) = &query.dns_status {
            DnsVerification::parse(value).map_err(|err| {
                ApiError::bad_request("invalid_filter", format!("dns_status: {err}"))
            })?;
        }
        if let Some(value) = &query.ip_match {
            IpMatch::parse(value).map_err(|err| {
                ApiError::bad_request("invalid_filter", format!("ip_match: {err}"))
            })?;
        }
        validate_label(&query.scope_status, &["allowed", "denied"], "scope_status")?;
        validate_label(
            &query.confidence,
            &["high", "medium", "low", "unknown"],
            "confidence",
        )?;
        validate_label(
            &query.interest,
            &["high", "medium", "low", "unknown"],
            "interest",
        )?;
        Ok(CandidateFilter {
            query: query.q.clone(),
            source: query.source.clone(),
            dns_status: query.dns_status.clone(),
            ip_match: query.ip_match.clone(),
            confidence: query.confidence.clone(),
            interest: query.interest.clone(),
            scope_status: query.scope_status.clone(),
        })
    }
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<CandidateQuery>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let filter = query.filter()?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project scope is missing"))?;
    let limit = query.limit.unwrap_or(25).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let (items, total) = state
        .db
        .list_candidates(&project.id, &filter, &scope.scope, limit, offset)
        .map_err(ApiError::internal)?;
    Ok(Json(paged(items, total, limit, offset)))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, candidate_id)): Path<(String, String)>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project scope is missing"))?;
    let candidate = state
        .db
        .candidate_detail(&project.id, &candidate_id, &scope.scope)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("candidate not found in this project"))?;
    Ok(Json(json!({"candidate": candidate})))
}

pub async fn export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, format)): Path<(String, String)>,
    Query(query): Query<CandidateQuery>,
) -> ApiResult<Response> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project scope is missing"))?;
    let filter = query.filter()?;
    let (rows, total) = state
        .db
        .list_candidates(
            &project.id,
            &filter,
            &scope.scope,
            state.config.max_discovery_candidates as u32,
            0,
        )
        .map_err(ApiError::internal)?;
    let data = match format.as_str() {
        "csv" => {
            let mut writer = csv::Writer::from_writer(Vec::new());
            writer
                .write_record([
                    "hostname",
                    "sources",
                    "dns_status",
                    "ip_match",
                    "scope_status",
                    "confidence",
                    "interest",
                    "addresses",
                    "first_seen",
                    "last_seen",
                ])
                .map_err(ApiError::internal)?;
            for row in &rows {
                let classification = state
                    .db
                    .classification_for(&project.id, "candidate", row["id"].as_str().unwrap_or(""))
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| json!({}));
                writer
                    .write_record([
                        csv_cell(row["hostname"].as_str().unwrap_or("")),
                        csv_cell(&row["sources"].to_string()),
                        csv_cell(row["dns_status"].as_str().unwrap_or("")),
                        csv_cell(row["ip_match"].as_str().unwrap_or("")),
                        csv_cell(row["current_scope_status"].as_str().unwrap_or("")),
                        csv_cell(classification["confidence"].as_str().unwrap_or("unknown")),
                        csv_cell(classification["interest"].as_str().unwrap_or("unknown")),
                        csv_cell(&row["addresses"].to_string()),
                        csv_cell(row["first_seen"].as_str().unwrap_or("")),
                        csv_cell(row["last_seen"].as_str().unwrap_or("")),
                    ])
                    .map_err(ApiError::internal)?;
            }
            (
                "text/csv; charset=utf-8",
                writer.into_inner().map_err(ApiError::internal)?,
            )
        }
        "json" => {
            let mut data = serde_json::to_vec_pretty(&json!({
                "format_version": "1",
                "generated_at": crate::domain::now_rfc3339(),
                "project_id": project.id,
                "candidates": rows,
                "total": total,
                "truncated": total > rows.len() as i64,
            }))
            .map_err(ApiError::internal)?;
            data.push(b'\n');
            ("application/json", data)
        }
        _ => {
            return Err(ApiError::not_found(
                "unsupported discovery export format; use json or csv",
            ))
        }
    };
    state
        .db
        .audit(
            &session.user.username,
            "discovery.candidates.export",
            "project",
            Some(&project.id),
            &json!({"format": format, "rows": rows.len()}),
        )
        .map_err(ApiError::internal)?;
    Ok((
        [
            (header::CONTENT_TYPE, data.0.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"candidates.{format}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        data.1,
    )
        .into_response())
}
