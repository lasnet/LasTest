use crate::api::{ApiResult, AppState};
use crate::db::SCHEMA_VERSION;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

const INDEX: &str = include_str!("../../ui/index.html");
const APP_JS: &str = include_str!("../../ui/app.js");
const STYLES: &str = include_str!("../../ui/styles.css");

fn security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "same-origin".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
}

pub async fn index() -> Response {
    let mut response = Html(INDEX).into_response();
    security_headers(&mut response);
    response
}

pub async fn app_js() -> Response {
    let mut response = (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
        .into_response();
    security_headers(&mut response);
    response
}

pub async fn styles() -> Response {
    let mut response =
        ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLES).into_response();
    security_headers(&mut response);
    response
}

pub async fn live() -> Json<serde_json::Value> {
    Json(json!({"status": "live", "service": "lastest", "version": env!("CARGO_PKG_VERSION")}))
}

pub async fn ready(State(state): State<Arc<AppState>>) -> ApiResult<Response> {
    let healthy = state.db.healthy();
    let schema = state.db.schema_version().unwrap_or(-1);
    let writable = {
        let probe = state.config.data_dir.join(".readiness-probe");
        let result = std::fs::write(&probe, b"ok").and_then(|_| std::fs::remove_file(&probe));
        result.is_ok()
    };
    let nmap = crate::tasks::registry::nmap_available(&state.config);
    let worker = state
        .db
        .worker_health(state.config.worker_lease_seconds.saturating_mul(3))
        .unwrap_or_else(|_| serde_json::json!({"state": "unknown"}));
    let ready = healthy && schema == SCHEMA_VERSION && writable;
    let body = json!({
        "status": if ready { "ready" } else { "not_ready" },
        "checks": {
            "database": healthy,
            "schema_version": schema,
            "supported_schema_version": SCHEMA_VERSION,
            "data_dir_writable": writable,
            "evidence_dir": state.config.evidence_dir(),
            "nmap_adapter": if nmap { "available" } else { "unavailable" }
        },
        "worker": worker
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Ok((status, Json(body)).into_response())
}
