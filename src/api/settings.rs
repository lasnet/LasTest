use super::{authenticate, require, validate_origin, ApiError, ApiResult, AppState};
use crate::domain::Role;
use crate::provider_settings;
use crate::tasks::dnsmap;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderKeyBody {
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordlistBody {
    name: String,
    contents: String,
}

pub async fn providers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<([(header::HeaderName, &'static str); 1], Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    let providers =
        provider_settings::status(&state.db, &state.config).map_err(ApiError::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"providers": providers})),
    ))
}

pub async fn update_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ProviderKeyBody>,
) -> ApiResult<StatusCode> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    validate_origin(&Method::PUT, &headers, Some(&session))?;
    let provider =
        provider_settings::provider(&id).ok_or_else(|| ApiError::not_found("unknown provider"))?;
    let key = body.key.trim();
    if !provider_settings::valid_key(key) {
        return Err(ApiError::bad_request(
            "invalid_key",
            "Enter a single API key of 8–2048 characters",
        ));
    }
    provider_settings::save_key(
        &state.db,
        &state.config,
        &session.user.username,
        provider,
        key,
    )
    .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_wordlist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WordlistBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let session = authenticate(&state, &headers)?;
    require(&session, Role::Admin)?;
    validate_origin(&Method::POST, &headers, Some(&session))?;
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "invalid_name",
            "Enter a wordlist name of 1–80 characters",
        ));
    }
    if name.eq_ignore_ascii_case("default") {
        return Err(ApiError::conflict(
            "wordlist_exists",
            "A wordlist named default already exists",
        ));
    }
    let words = dnsmap::parse_wordlist(&body.contents)
        .map_err(|error| ApiError::bad_request("invalid_wordlist", error.to_string()))?;
    let wordlist = state
        .db
        .add_dns_wordlist(&session.user.username, name, &words)
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::conflict(
                "wordlist_exists",
                "A wordlist with this name already exists",
            )
        })?;
    Ok((StatusCode::CREATED, Json(json!({"wordlist": wordlist}))))
}
