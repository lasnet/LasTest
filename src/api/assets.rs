use super::projects::resolve_project;
use super::{authenticate, paged, require, validate_origin, ApiError, ApiResult, AppState};
use crate::db::assets::DeleteAssetResult;
use crate::domain::Role;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Default, Deserialize)]
pub struct InventoryQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    technology: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    offset: u32,
}

pub async fn targets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("project Scope is missing"))?;
    let items = state
        .db
        .asset_input_catalog(&project.id)
        .map_err(ApiError::internal)?;
    let has_dns = crate::db::asset_input::scope_has_dns(&scope.scope);
    let has_rules = scope.scope.rules.iter().any(|rule| !rule.exclusion);
    let next = if !has_rules {
        "scope_empty"
    } else if scope.status != crate::domain::ScopeStatus::Approved {
        "approve_scope"
    } else if !items.is_empty() {
        "ready"
    } else if has_dns {
        "enumerate_subdomains"
    } else {
        "import_scope"
    };
    let mut count = None;
    let mut import_error = None;
    if next == "import_scope" {
        match crate::db::asset_input::scope_import_ips(
            &scope.scope,
            &state.config.network_policy(),
            state.config.max_queue_targets,
        ) {
            Ok(ips) => count = Some(ips.len()),
            Err(error) => import_error = Some(error.to_string()),
        }
    }
    Ok(Json(
        json!({"items":items,"next":next,"scope_version":scope.version,"import_count":count,"import_error":import_error}),
    ))
}

#[derive(Deserialize)]
pub struct ImportScopeBody {
    pub scope_version: i64,
}

pub async fn import_scope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ImportScopeBody>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    let added = state
        .db
        .import_scope_assets(
            &project.id,
            body.scope_version,
            &state.config.network_policy(),
            state.config.max_queue_targets,
            &session.user.username,
        )
        .map_err(|error| ApiError::bad_request("asset_import_failed", error.to_string()))?;
    Ok(Json(json!({"added":added})))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<InventoryQuery>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let rows = state
        .db
        .inventory_rows_filtered(
            &project.id,
            &query.q,
            query.technology.as_deref(),
            query.provider.as_deref(),
            query.category.as_deref(),
        )
        .map_err(ApiError::internal)?;
    let total = rows.len();
    // Clamp after deletion, including deletion of the last row on a page.
    let offset = (query.offset as usize / 10 * 10).min(total.saturating_sub(1) / 10 * 10);
    Ok(Json(paged(
        rows.into_iter().skip(offset).take(10).collect(),
        total as i64,
        10,
        offset as u32,
    )))
}

pub async fn urls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let items = state
        .db
        .list_asset_urls(&project.id, 300)
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": items })))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, asset_id)): Path<(String, String)>,
) -> ApiResult {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let asset = state
        .db
        .asset_detail(&project.id, &asset_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("asset not found in this project"))?;
    Ok(Json(json!({"asset": asset})))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, asset_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::DELETE, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    match state
        .db
        .delete_inventory_asset(&project.id, &asset_id, &session.user.username)
        .map_err(ApiError::internal)?
    {
        DeleteAssetResult::Deleted => Ok(StatusCode::NO_CONTENT),
        DeleteAssetResult::NotFound => Err(ApiError::not_found("asset not found in this project")),
        DeleteAssetResult::LinkedIp => Err(ApiError::conflict(
            "ip_in_use",
            "IP address is linked to hosts; delete the host row instead",
        )),
    }
}

pub async fn export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, format)): Path<(String, String)>,
    Query(query): Query<InventoryQuery>,
) -> ApiResult<Response> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let content_type = match format.as_str() {
        "csv" => "text/csv; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => {
            return Err(ApiError::not_found(
                "unsupported asset format; use txt or csv",
            ))
        }
    };
    let project = resolve_project(&state, &id)?;
    let rows = state
        .db
        .inventory_rows_filtered(
            &project.id,
            &query.q,
            query.technology.as_deref(),
            query.provider.as_deref(),
            query.category.as_deref(),
        )
        .map_err(ApiError::internal)?;
    let count = rows.len();
    let data = if format == "csv" {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer
            .write_record(["Hosts", "IP addresses", "Last seen"])
            .map_err(ApiError::internal)?;
        for row in rows {
            // Neutralize spreadsheet formulas while preserving the raw values in TXT.
            let host = row.host.unwrap_or_default();
            let host = if host.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) {
                format!("'{host}")
            } else {
                host
            };
            writer
                .write_record([host, row.ips.join(", "), row.last_seen])
                .map_err(ApiError::internal)?;
        }
        writer.into_inner().map_err(ApiError::internal)?
    } else {
        let mut text = String::from("Hosts\tIP addresses\tLast seen\n");
        for row in rows {
            let host = row
                .host
                .unwrap_or_default()
                .replace(['\t', '\r', '\n'], " ");
            text.push_str(&format!(
                "{}\t{}\t{}\n",
                host,
                row.ips.join(", "),
                row.last_seen
            ));
        }
        text.into_bytes()
    };
    state
        .db
        .audit(
            &session.user.username,
            "asset.export",
            "project",
            Some(&project.id),
            &json!({"format": format, "query": query.q, "rows": count}),
        )
        .map_err(ApiError::internal)?;
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"assets.{format}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        data,
    )
        .into_response())
}
