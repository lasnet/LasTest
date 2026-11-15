use crate::api::{authenticate, paged, require, validate_origin, ApiError, ApiResult, AppState};
use crate::domain::Role;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    pub password: String,
    pub role: String,
    #[serde(default)]
    pub must_change_password: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserBody {
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<String>,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let (users, total) = state
        .db
        .list_users(limit, offset)
        .map_err(ApiError::internal)?;
    Ok(Json(paged(users, total, limit, offset)))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateUserBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let role = Role::parse(&body.role).map_err(|err| ApiError::bad_request("invalid_role", err))?;
    let user = state
        .auth
        .create_user(
            &session.user.username,
            &body.username,
            &body.password,
            role,
            body.must_change_password,
            None,
        )
        .map_err(|err| {
            let message = format!("{err:#}");
            if message.contains("UNIQUE") || message.contains("already exists") {
                ApiError::conflict("user_exists", "username already exists")
            } else {
                ApiError::bad_request("invalid_user", message)
            }
        })?;
    Ok((StatusCode::CREATED, Json(json!({"user": user}))))
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateUserBody>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    validate_origin(&Method::PATCH, &headers, Some(&session))?;
    let role = match body.role.as_deref() {
        Some(value) => {
            Some(Role::parse(value).map_err(|err| ApiError::bad_request("invalid_role", err))?)
        }
        None => None,
    };
    let password_hash = match body.password.as_deref() {
        Some(password) => Some(
            crate::auth::AuthService::hash_password(password)
                .map_err(|err| ApiError::bad_request("invalid_password", err.to_string()))?,
        ),
        None => None,
    };
    let must_change = body.password.as_ref().map(|_| false);
    let user = state
        .db
        .update_user(
            &id,
            role,
            body.is_active,
            password_hash.as_deref(),
            must_change,
        )
        .map_err(|err| {
            let message = format!("{err:#}");
            if message.contains("last active administrator") {
                ApiError::conflict("last_admin", message)
            } else {
                ApiError::bad_request("invalid_user", message)
            }
        })?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if body.is_active == Some(false) || body.password.is_some() {
        state
            .db
            .revoke_user_sessions(&user.id)
            .map_err(ApiError::internal)?;
    }
    state
        .db
        .audit(
            &session.user.username,
            "user.update",
            "user",
            Some(&user.id),
            &json!({
                "role": user.role.as_str(),
                "is_active": user.is_active,
                "password_changed": body.password.is_some()
            }),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"user": user})))
}

pub async fn audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let (items, total) = state
        .db
        .list_audit(limit, offset)
        .map_err(ApiError::internal)?;
    Ok(Json(paged(items, total, limit, offset)))
}
