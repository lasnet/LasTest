use crate::api::{authenticate, paged, require, validate_origin, ApiError, ApiResult, AppState};
use crate::domain::{Project, Role};
use crate::scope::{Scope, ScopeRule};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectBody {
    pub name: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct ScopeQuery {
    pub version: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PutScopeBody {
    pub rules: Vec<ScopeRule>,
    pub expected_version: Option<i64>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub approve: bool,
}

pub fn resolve_project(state: &AppState, key: &str) -> Result<Project, ApiError> {
    if let Some(project) = state.db.project_by_id(key).map_err(ApiError::internal)? {
        return Ok(project);
    }
    state
        .db
        .project_by_name(key)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("project not found: {key}")))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let (projects, total) = state
        .db
        .list_projects(limit, offset)
        .map_err(ApiError::internal)?;
    let mut items = Vec::new();
    for project in projects {
        let scope = state
            .db
            .current_scope(&project.id)
            .map_err(ApiError::internal)?;
        let jobs = state
            .db
            .queued_job_count(Some(&project.id))
            .map_err(ApiError::internal)?;
        items.push(json!({
            "project": project,
            "scope_version": scope.as_ref().map(|value| value.version),
            "scope_status": scope.as_ref().map(|value| value.status.as_str()),
            "active_jobs": jobs
        }));
    }
    Ok(Json(paged(items, total, limit, offset)))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateProjectBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    if state
        .db
        .project_by_name(body.name.trim())
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::conflict(
            "project_exists",
            "a project with this name already exists",
        ));
    }
    let project = state
        .db
        .create_project(
            &body.name,
            &body.client,
            &body.description,
            None,
            None,
            &session.user.username,
        )
        .map_err(|err| ApiError::bad_request("invalid_project", format!("{err:#}")))?;
    let scope = state
        .db
        .current_scope(&project.id)
        .map_err(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "project": project,
            "scope": scope.map(|value| value.to_json()),
            "next": "edit and approve scope before submitting jobs"
        })),
    ))
}

pub async fn get_one(
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
    let revisions = state
        .db
        .scope_revisions(&project.id)
        .map_err(ApiError::internal)?;
    let jobs = state
        .db
        .queued_job_count(Some(&project.id))
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "project": project,
        "scope": scope.map(|value| value.to_json()),
        "revisions": revisions.iter().map(|value| json!({
            "version": value.version,
            "status": value.status.as_str(),
            "created_at": value.created_at,
            "created_by": value.created_by,
            "approved_at": value.approved_at
        })).collect::<Vec<_>>(),
        "active_jobs": jobs
    })))
}

pub async fn get_scope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ScopeQuery>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Viewer)?;
    let project = resolve_project(&state, &id)?;
    let revision = match query.version {
        Some(version) => state
            .db
            .scope_by_version(&project.id, version)
            .map_err(ApiError::internal)?,
        None => state
            .db
            .current_scope(&project.id)
            .map_err(ApiError::internal)?,
    };
    let revision = revision.ok_or_else(|| ApiError::not_found("scope revision not found"))?;
    Ok(Json(json!({
        "project_id": project.id,
        "scope": revision.to_json(),
        "history": state.db.scope_revisions(&project.id).map_err(ApiError::internal)?
            .iter().map(|value| json!({
                "version": value.version,
                "status": value.status.as_str(),
                "created_at": value.created_at
            })).collect::<Vec<_>>()
    })))
}

pub async fn put_scope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PutScopeBody>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::PUT, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    let scope = Scope::new(body.rules)
        .map_err(|err| ApiError::bad_request("invalid_scope", err.to_string()))?;
    if body.approve && scope.rules.iter().all(|rule| rule.exclusion) {
        return Err(ApiError::bad_request(
            "invalid_scope",
            "cannot approve a scope without at least one allowed rule",
        ));
    }
    let revision = state
        .db
        .replace_scope(
            &project.id,
            body.expected_version,
            &scope,
            &body.note,
            &session.user.username,
            body.approve,
        )
        .map_err(|err| {
            let message = format!("{err:#}");
            if message.contains("version conflict") {
                ApiError::conflict("scope_version_conflict", message)
            } else {
                ApiError::bad_request("invalid_scope", message)
            }
        })?;
    Ok(Json(json!({
        "project_id": project.id,
        "scope": revision.to_json()
    })))
}

pub async fn approve_scope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Analyst)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let project = resolve_project(&state, &id)?;
    let revision = state
        .db
        .approve_scope(&project.id, version, &session.user.username)
        .map_err(|err| ApiError::bad_request("invalid_scope", format!("{err:#}")))?;
    Ok(Json(json!({
        "project_id": project.id,
        "scope": revision.to_json()
    })))
}
