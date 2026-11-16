//! HTTP API. Web and CLI use the same routes and authorization checks.

pub mod admin;
pub mod auth_routes;
pub mod dashboard;
pub mod jobs;
pub mod projects;
pub mod static_ui;

use crate::auth::{bearer_token, parse_cookie, require_role, AuthService, SESSION_COOKIE};
use crate::config::Config;
use crate::db::Db;
use crate::domain::{Role, User};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub auth: AuthService,
}

impl AppState {
    pub fn new(config: Config, db: Db) -> Self {
        let auth = AuthService::new(db.clone(), config.clone());
        Self {
            config: Arc::new(config),
            db,
            auth,
        }
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "authentication is required",
        )
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "internal API error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal server error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message
                }
            })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::internal(format!("{err:#}"))
    }
}

pub type ApiResult<T = Json<Value>> = std::result::Result<T, ApiError>;

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub kind: String,
    pub token: String,
}

pub fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Session, ApiError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| bearer_token(Some(value)));
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_cookie(value, SESSION_COOKIE));
    let token = bearer.or(cookie).ok_or_else(ApiError::unauthorized)?;
    let (user, kind) = state
        .auth
        .authenticate(&token)
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(Session { user, kind, token })
}

pub fn require(session: &Session, role: Role) -> Result<(), ApiError> {
    require_role(&session.user, role)
        .map_err(|_| ApiError::forbidden("forbidden", "insufficient permissions"))
}

pub fn validate_origin(
    method: &Method,
    headers: &HeaderMap,
    session: Option<&Session>,
) -> Result<(), ApiError> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let referer = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let source = origin.clone().or(referer);
    if let Some(session) = session {
        if session.kind == "web" {
            let Some(source) = source else {
                return Err(ApiError::forbidden(
                    "csrf_failed",
                    "cross-site request origin is required for cookie-authenticated changes",
                ));
            };
            check_same_origin(headers, &source)?;
        }
    } else if let Some(source) = source {
        // Login and other unauthenticated mutations accept same-origin browser
        // requests; a mismatched Origin is still rejected.
        check_same_origin(headers, &source)?;
    }
    Ok(())
}

fn check_same_origin(headers: &HeaderMap, source: &str) -> Result<(), ApiError> {
    let parsed = Url::parse(source)
        .map_err(|_| ApiError::forbidden("csrf_failed", "invalid request origin"))?;
    let source_host = parsed.host_str().unwrap_or_default();
    let source_port = parsed
        .port_or_known_default()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let host_header = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let (host_name, host_port) = split_authority(host_header);
    let expected_port = if parsed.scheme() == "https" { 443 } else { 80 };
    if source_host.eq_ignore_ascii_case(host_name)
        && (source_port == host_port || (host_port == 0 && source_port == expected_port))
    {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "csrf_failed",
            "request origin does not match the API host",
        ))
    }
}

fn split_authority(value: &str) -> (&str, u16) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            return (host, port);
        }
    }
    match value.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            (host, port.parse().unwrap_or(0))
        }
        _ => (value, 0),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health/live", get(static_ui::live))
        .route("/api/health/ready", get(static_ui::ready))
        .route(
            "/api/auth/setup",
            get(auth_routes::setup_status).post(auth_routes::setup),
        )
        .route("/api/auth/login", post(auth_routes::login))
        .route("/api/auth/logout", post(auth_routes::logout))
        .route("/api/auth/me", get(auth_routes::me))
        .route("/api/task-types", get(jobs::task_types))
        .route("/api/projects", get(projects::list).post(projects::create))
        .route("/api/projects/{id}", get(projects::get_one))
        .route(
            "/api/projects/{id}/scope",
            get(projects::get_scope).put(projects::put_scope),
        )
        .route(
            "/api/projects/{id}/scope/{version}/approve",
            post(projects::approve_scope),
        )
        .route(
            "/api/projects/{id}/jobs",
            get(jobs::list_jobs).post(jobs::submit_job),
        )
        .route("/api/jobs/{id}", get(jobs::get_job))
        .route("/api/jobs/{id}/cancel", post(jobs::cancel_job))
        .route(
            "/api/projects/{id}/chains",
            get(jobs::list_chains).post(jobs::submit_chain),
        )
        .route("/api/chains/{id}", get(jobs::get_chain))
        .route("/api/chains/{id}/cancel", post(jobs::cancel_chain))
        .route("/api/projects/{id}/dashboard", get(dashboard::dashboard))
        .route("/api/evidence/{id}", get(jobs::get_evidence))
        .route(
            "/api/projects/{id}/reports/{format}",
            get(dashboard::export_report),
        )
        .route(
            "/api/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route("/api/users/{id}", axum::routing::patch(admin::update_user))
        .route("/api/audit", get(admin::audit))
        .route("/", get(static_ui::index))
        .route("/app.js", get(static_ui::app_js))
        .route("/theme.js", get(static_ui::theme_js))
        .route("/styles.css", get(static_ui::styles))
        .route(
            "/fonts/instrument-sans.woff2",
            get(static_ui::instrument_sans),
        )
        .route("/fonts/OFL.txt", get(static_ui::font_license))
        .fallback(static_ui::index)
        .with_state(state)
}

pub fn paged<T: Serialize>(items: Vec<T>, total: i64, limit: u32, offset: u32) -> Value {
    json!({
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset
    })
}
