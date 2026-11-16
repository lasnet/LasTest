use crate::api::{authenticate, validate_origin, ApiError, ApiResult, AppState, Session};
use crate::auth::{AuthService, SESSION_COOKIE};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub client: Option<String>,
}

#[derive(Deserialize)]
pub struct SetupBody {
    pub code: String,
    pub username: String,
    pub password: String,
}

pub async fn setup_status(State(state): State<Arc<AppState>>) -> ApiResult {
    Ok(Json(json!({"required": state.db.count_users()? == 0})))
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetupBody>,
) -> ApiResult<Response> {
    validate_origin(&Method::POST, &headers, None)?;
    if state.db.count_users()? != 0 {
        return Err(ApiError::conflict(
            "setup_closed",
            "administrator setup is closed",
        ));
    }
    AuthService::validate_username(&body.username)
        .map_err(|error| ApiError::bad_request("invalid_username", error.to_string()))?;
    AuthService::validate_password(&body.password)
        .map_err(|error| ApiError::bad_request("invalid_password", error.to_string()))?;
    let user = tokio::task::spawn_blocking(move || {
        state
            .auth
            .complete_setup(&body.code, &body.username, &body.password)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?
    .ok_or_else(|| {
        ApiError::forbidden("invalid_setup_code", "the setup code is invalid or expired")
    })?;
    Ok((StatusCode::CREATED, Json(json!({"user": user}))).into_response())
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> ApiResult<Response> {
    validate_origin(&Method::POST, &headers, None)?;
    let kind = body.client.as_deref().unwrap_or("web");
    let result = state
        .auth
        .login(&body.username, &body.password, kind)
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            )
        })?;
    let mut response = Json(json!({
        "user": result.user,
        "kind": result.kind,
        "expires_at": result.expires_at,
        "token": if result.kind == "cli" { Some(result.token.clone()) } else { None },
        "message": "authenticated"
    }))
    .into_response();
    if result.kind == "web" {
        let cookie = session_cookie(&state, &result.token);
        response.headers_mut().insert(
            header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| ApiError::internal("cannot build session cookie"))?,
        );
    }
    Ok(response)
}

pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    let session = authenticate(&state, &headers)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let _ = state.auth.logout(&session.token, &session.user.username)?;
    let clear = if state.config.secure_cookies {
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
    } else {
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    };
    let mut response = Json(json!({"message": "logged out"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        clear
            .parse()
            .map_err(|_| ApiError::internal("cannot build cookie"))?,
    );
    Ok(response)
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let session: Session = authenticate(&state, &headers)?;
    Ok(Json(json!({
        "user": session.user,
        "kind": session.kind,
        "csrf": if session.kind == "web" { Some("origin-checked") } else { None }
    })))
}

pub fn session_cookie(state: &AppState, token: &str) -> String {
    let max_age = state.config.session_ttl_hours.max(1) * 3600;
    if state.config.secure_cookies {
        format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
        )
    } else {
        format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}")
    }
}
