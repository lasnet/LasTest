use crate::api::{ApiResult, AppState};
use crate::db::SCHEMA_VERSION;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

const INDEX: &str = include_str!("../../ui/index.html");
const APP_JS: &str = include_str!("../../ui/app.js");
const THEME_JS: &str = include_str!("../../ui/theme.js");
const STYLES: &str = include_str!("../../ui/styles.css");
const INSTRUMENT_SANS: &[u8] = include_bytes!("../../ui/fonts/instrument-sans.woff2");
const FONT_LICENSE: &str = include_str!("../../ui/fonts/OFL.txt");

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

pub async fn app_js(headers: HeaderMap) -> Response {
    static ETAG: OnceLock<String> = OnceLock::new();
    static_asset(
        &headers,
        APP_JS.as_bytes(),
        "application/javascript; charset=utf-8",
        &ETAG,
    )
}

pub async fn theme_js(headers: HeaderMap) -> Response {
    static ETAG: OnceLock<String> = OnceLock::new();
    static_asset(
        &headers,
        THEME_JS.as_bytes(),
        "application/javascript; charset=utf-8",
        &ETAG,
    )
}

pub async fn styles(headers: HeaderMap) -> Response {
    static ETAG: OnceLock<String> = OnceLock::new();
    static_asset(
        &headers,
        STYLES.as_bytes(),
        "text/css; charset=utf-8",
        &ETAG,
    )
}

pub async fn instrument_sans(headers: HeaderMap) -> Response {
    static ETAG: OnceLock<String> = OnceLock::new();
    static_asset(&headers, INSTRUMENT_SANS, "font/woff2", &ETAG)
}

fn static_asset(
    request_headers: &HeaderMap,
    body: &'static [u8],
    content_type: &'static str,
    etag: &OnceLock<String>,
) -> Response {
    let etag = etag.get_or_init(|| format!("\"{:x}\"", Sha256::digest(body)));
    let matches = request_headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim))
        .any(|value| value == "*" || value.strip_prefix("W/").unwrap_or(value) == etag);
    let mut response = if matches {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        ([(header::CONTENT_TYPE, content_type)], body).into_response()
    };
    security_headers(&mut response);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, no-cache"),
    );
    response
        .headers_mut()
        .insert(header::ETAG, etag.parse().unwrap());
    response
}

pub async fn font_license() -> Response {
    let mut response = FONT_LICENSE.into_response();
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
