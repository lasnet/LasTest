//! Fixed-endpoint passive provider helpers. Operators cannot override provider
//! URLs; only deployment configuration provides them.

use crate::config::Config;
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

pub fn client(config: &Config) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.http_timeout())
        .connect_timeout(config.http_timeout())
        .user_agent("LasTest/2.0 authorized-assessment")
        .no_proxy()
        .build()?)
}

pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (key, value) in pairs {
        if let (Ok(key), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value),
        ) {
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
    let response = client.get(url).headers(headers).send().await?;
    let status = response.status().as_u16();
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
    ))
}

pub async fn get_json(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
    max_bytes: u64,
) -> Result<(u16, Option<Value>, bool)> {
    let (status, text, truncated) = get_text(client, url, headers, max_bytes).await?;
    let value = serde_json::from_str(&text).ok();
    Ok((status, value, truncated))
}
