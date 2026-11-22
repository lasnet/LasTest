//! Fixed-endpoint passive provider helpers. Operators cannot override provider
//! URLs; only deployment configuration provides them.
//!
//! The cached fetch path applies a shared SQLite rate limiter and reservation,
//! bounded retries with jitter, cancellation-aware pauses and a short negative
//! cache. The cache never stores credentials or exposes project data.

use crate::config::Config;
use crate::db::provider_cache::ReserveOutcome;
use crate::tasks::TaskContext;
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchStatus {
    Ok,
    Empty,
    AccessDenied,
    Quota,
    Unavailable,
    InvalidResponse,
    Cooldown,
}

impl FetchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Empty => "empty",
            Self::AccessDenied => "access_denied",
            Self::Quota => "quota",
            Self::Unavailable => "unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::Cooldown => "cooldown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderFetch {
    pub status: FetchStatus,
    pub http_status: Option<u16>,
    pub value: Option<Value>,
    pub cached: bool,
    pub attempts: u32,
    pub error: Option<String>,
}

impl ProviderFetch {
    fn error(status: FetchStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            http_status: None,
            value: None,
            cached: false,
            attempts: 0,
            error: Some(message.into()),
        }
    }
}

pub fn client(config: &Config) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.http_timeout())
        .connect_timeout(config.http_timeout())
        .user_agent("LasTest authorized-assessment")
        .no_proxy()
        .build()?)
}

pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (key, value) in pairs {
        if let (Ok(key), Ok(mut value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            if key == reqwest::header::AUTHORIZATION {
                value.set_sensitive(true);
            }
            map.insert(key, value);
        }
    }
    map
}

pub async fn get_text(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
    max_bytes: u64,
) -> Result<(u16, String, bool)> {
    let (status, text, truncated, _) =
        get_text_with_headers(client, url, headers, max_bytes).await?;
    Ok((status, text, truncated))
}

pub async fn get_text_with_headers(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
    max_bytes: u64,
) -> Result<(u16, String, bool, HeaderMap)> {
    let response = client.get(url).headers(headers).send().await?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let mut body = Vec::new();
    let mut truncated = false;
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        let remaining = (max_bytes as usize).saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
        if body.len() >= max_bytes as usize {
            truncated = true;
            break;
        }
    }
    Ok((
        status,
        String::from_utf8_lossy(&body).to_string(),
        truncated,
        response_headers,
    ))
}

pub async fn get_json(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
    max_bytes: u64,
) -> Result<(u16, Option<Value>, bool)> {
    let (status, text, truncated, _) =
        get_text_with_headers(client, url, headers, max_bytes).await?;
    let value = serde_json::from_str(&text).ok();
    Ok((status, value, truncated))
}

/// Namespaces are hashed so tokens never appear in cache keys, logs or files.
pub fn credential_context(provider: &str, mode: &str, secret_context: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update(b"|");
    hasher.update(mode.as_bytes());
    hasher.update(b"|");
    hasher.update(secret_context.as_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn cache_key(
    provider: &str,
    api_version: &str,
    endpoint: &str,
    credential_context: &str,
    subject: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [provider, api_version, endpoint, credential_context, subject] {
        hasher.update(part.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ensure_allowed(ctx: &TaskContext, subject: &str) -> Result<()> {
    ctx.ensure_active()?;
    ctx.authorize_ip(crate::scope::canonical_ip(subject)?)
}

async fn cancellable_sleep(ctx: &TaskContext, subject: &str, millis: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_millis(millis.max(1));
    loop {
        ensure_allowed(ctx, subject)?;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
    }
}

fn retry_after(headers: &HeaderMap) -> Option<u64> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    value.parse::<u64>().ok().or_else(|| {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .map(|time| {
                (time.with_timezone(&chrono::Utc) - chrono::Utc::now())
                    .num_seconds()
                    .max(1) as u64
            })
    })
}

pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

fn cached_fetch(entry: crate::db::provider_cache::ProviderCacheEntry) -> ProviderFetch {
    ProviderFetch {
        status: if entry.negative {
            FetchStatus::Empty
        } else {
            FetchStatus::Ok
        },
        http_status: Some(entry.http_status as u16),
        value: Some(entry.body),
        cached: true,
        attempts: 0,
        error: None,
    }
}

/// Installation-wide reservations suppress duplicate requests; every actual
/// request, including retries, passes the shared rate limit and current Scope.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_json_cached(
    ctx: &TaskContext,
    provider: &str,
    api_version: &str,
    namespace: &str,
    endpoint: &str,
    credential_context: &str,
    subject: &str,
    url: &str,
    request_headers: HeaderMap,
    max_bytes: u64,
) -> ProviderFetch {
    let key = cache_key(provider, api_version, endpoint, credential_context, subject);
    let owner = format!("{}-{}", ctx.attempt_id, crate::domain::new_id("res"));
    let attempts_limit = ctx.config.provider_max_retries.clamp(1, 5);
    // Bound both reservation lifetime and the total wait/request budget.
    let budget_seconds = ctx
        .config
        .http_timeout_seconds
        .saturating_add(30)
        .saturating_mul(attempts_limit as u64)
        .saturating_add(30)
        .min(180);
    let deadline = std::time::Instant::now() + Duration::from_secs(budget_seconds);
    let reservation_seconds = ctx
        .config
        .provider_reservation_seconds
        .max(budget_seconds as i64 + 1);
    let client = match client(&ctx.config) {
        Ok(client) => client,
        Err(_) => {
            return ProviderFetch::error(FetchStatus::Unavailable, "cannot create provider client")
        }
    };
    let mut attempts = 0;
    let mut owned = false;
    let mut result = loop {
        if ensure_allowed(ctx, subject).is_err() {
            break ProviderFetch::error(
                FetchStatus::Unavailable,
                "provider request stopped: task cancelled or IP no longer allowed",
            );
        }
        if std::time::Instant::now() >= deadline {
            break ProviderFetch::error(
                FetchStatus::Unavailable,
                "provider request exceeded its time budget",
            );
        }
        if let Ok(Some(entry)) = ctx.db.provider_cache_get(&key) {
            break cached_fetch(entry);
        }
        match ctx.db.provider_try_acquire(
            &key,
            provider,
            namespace,
            &owner,
            reservation_seconds,
            ctx.config.provider_min_interval_ms,
        ) {
            Ok(ReserveOutcome::Acquired) => owned = true,
            Ok(ReserveOutcome::Busy) | Ok(ReserveOutcome::Wait(_)) => {
                let wait = 100;
                if cancellable_sleep(ctx, subject, wait).await.is_err() {
                    break ProviderFetch::error(
                        FetchStatus::Unavailable,
                        "provider wait stopped: task cancelled or IP no longer allowed",
                    );
                }
                continue;
            }
            Ok(ReserveOutcome::Cooldown(until)) => {
                break ProviderFetch::error(
                    FetchStatus::Cooldown,
                    format!("provider cooldown until {until}"),
                );
            }
            Err(_) => {
                break ProviderFetch::error(FetchStatus::Unavailable, "provider reservation failed")
            }
        }
        // Another owner may have filled the cache just before our reservation.
        if let Ok(Some(entry)) = ctx.db.provider_cache_get(&key) {
            break cached_fetch(entry);
        }
        if ensure_allowed(ctx, subject).is_err() {
            continue;
        }
        attempts += 1;
        let request = get_text_with_headers(
            &client,
            url,
            request_headers.clone(),
            max_bytes.min(ctx.config.max_body_bytes),
        );
        tokio::pin!(request);
        let response = loop {
            tokio::select! {
                response = &mut request => break Some(response),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if ensure_allowed(ctx, subject).is_err() || std::time::Instant::now() >= deadline {
                        break None;
                    }
                }
            }
        };
        let Some(response) = response else {
            break ProviderFetch::error(
                FetchStatus::Unavailable,
                "provider request stopped: task, Scope or deadline changed",
            );
        };
        if ensure_allowed(ctx, subject).is_err() {
            break ProviderFetch::error(
                FetchStatus::Unavailable,
                "IP no longer allowed after provider request",
            );
        }
        let (status, text, truncated, headers) = match response {
            Ok(response) => response,
            Err(_) if attempts < attempts_limit => {
                if cancellable_sleep(ctx, subject, backoff_millis(attempts))
                    .await
                    .is_err()
                {
                    break ProviderFetch::error(FetchStatus::Unavailable, "provider retry stopped");
                }
                continue;
            }
            // reqwest errors can contain the full deployment URL. Do not leak
            // authentication/query data through project-visible diagnostics.
            Err(_) => {
                break ProviderFetch::error(
                    FetchStatus::Unavailable,
                    "provider connection or response failed",
                )
            }
        };
        if truncated {
            break ProviderFetch::error(
                FetchStatus::InvalidResponse,
                "provider response exceeded the configured body limit",
            );
        }
        if matches!(status, 200 | 404) {
            let value = if status == 404 {
                Some(serde_json::json!({}))
            } else {
                serde_json::from_str::<Value>(&text).ok()
            };
            let Some(value) = value else {
                break ProviderFetch::error(
                    FetchStatus::InvalidResponse,
                    "provider returned malformed JSON",
                );
            };
            // Cache only schema-valid successful responses. A partial parser
            // result is still delivered to the task, with its diagnostics.
            let parsed = crate::tasks::providers::parse(
                provider,
                &value,
                ctx.config.provider_max_candidates,
            );
            if status == 404 || !parsed.partial {
                let _ = ctx.db.provider_cache_put(
                    &key,
                    provider,
                    api_version,
                    endpoint,
                    credential_context,
                    status,
                    &value,
                    status == 404,
                    if status == 404 {
                        ctx.config.provider_negative_cache_ttl_seconds
                    } else {
                        ctx.config.provider_cache_ttl_seconds
                    },
                    ctx.config.provider_cache_max_entries,
                );
            }
            break ProviderFetch {
                status: if status == 404 {
                    FetchStatus::Empty
                } else {
                    FetchStatus::Ok
                },
                http_status: Some(status),
                value: Some(value),
                cached: false,
                attempts,
                error: None,
            };
        }
        if matches!(status, 401 | 403) {
            break ProviderFetch {
                http_status: Some(status),
                ..ProviderFetch::error(
                    FetchStatus::AccessDenied,
                    "provider rejected the installation credentials",
                )
            };
        }
        if is_retryable_status(status) && attempts < attempts_limit {
            let wait = retry_after(&headers)
                .map(|seconds| seconds.min(30) * 1000)
                .unwrap_or_else(|| backoff_millis(attempts));
            if status == 429 {
                let cooldown = retry_after(&headers)
                    .unwrap_or(ctx.config.provider_cooldown_seconds.max(1) as u64);
                let _ =
                    ctx.db
                        .provider_set_cooldown(provider, namespace, cooldown.min(3600) as i64);
                // A long Retry-After is a shared cooldown, not permission to
                // send another request early after a clamped local sleep.
                if cooldown > 30 {
                    break ProviderFetch {
                        http_status: Some(status),
                        ..ProviderFetch::error(
                            FetchStatus::Quota,
                            "provider rate limit was reached",
                        )
                    };
                }
                if cancellable_sleep(ctx, subject, cooldown * 1000 + 5)
                    .await
                    .is_err()
                {
                    break ProviderFetch::error(FetchStatus::Unavailable, "provider retry stopped");
                }
            } else if cancellable_sleep(ctx, subject, wait).await.is_err() {
                break ProviderFetch::error(FetchStatus::Unavailable, "provider retry stopped");
            }
            continue;
        }
        if status == 429 {
            let cooldown =
                retry_after(&headers).unwrap_or(ctx.config.provider_cooldown_seconds.max(1) as u64);
            let _ = ctx
                .db
                .provider_set_cooldown(provider, namespace, cooldown.min(3600) as i64);
        }
        break ProviderFetch {
            http_status: Some(status),
            ..ProviderFetch::error(
                if status == 429 {
                    FetchStatus::Quota
                } else if status >= 500 {
                    FetchStatus::Unavailable
                } else {
                    FetchStatus::InvalidResponse
                },
                format!("provider returned HTTP {status}"),
            )
        };
    };
    if owned {
        let _ = ctx.db.provider_release(&key, &owner);
    }
    result.attempts = attempts;
    result
}

fn backoff_millis(attempt: u32) -> u64 {
    use rand::Rng;
    let base = 250u64.saturating_mul(1u64 << attempt.min(4));
    (base + rand::rng().random_range(0..250)).min(5_000)
}
