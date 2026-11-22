//! Optional technology evidence from the Jenkins and JQuery plugins in WhatWeb 0.6.4.
//! WhatWeb receives a local copy of an HTTP response fetched by LasTest.
use super::TaskContext;
use crate::net::http::FetchResult;
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_BYTES: u64 = 32 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Entry {
    target: String,
    http_status: u16,
    plugins: BTreeMap<String, Plugin>,
}

#[derive(Deserialize)]
struct Plugin {
    #[serde(default)]
    version: Vec<String>,
}

pub(super) async fn detect(fetch: &FetchResult, ctx: &TaskContext) -> Result<Vec<Value>> {
    let mut native = super::tech_catalog::detect(fetch);
    if let Some(path) = &ctx.config.whatweb_path {
        ctx.ensure_active()?;
        match inspect(path, fetch, ctx).await {
            Ok(technologies) => native.extend(technologies),
            Err(error) => {
                ctx.ensure_active()?;
                tracing::warn!(job_id = %ctx.job_id, %error, "WhatWeb unavailable; using built-in technology detection");
            }
        }
    }
    Ok(native)
}

async fn inspect(path: &Path, fetch: &FetchResult, ctx: &TaskContext) -> Result<Vec<Value>> {
    ensure!(
        path.is_absolute(),
        "WhatWeb requires an absolute executable path"
    );
    let Some(snapshot) = response_snapshot(fetch) else {
        return Ok(Vec::new());
    };
    let dir = tempfile::Builder::new()
        .prefix("lastest-whatweb-")
        .tempdir()?;
    let file = dir.path().join("response.http");
    tokio::fs::write(&file, snapshot).await?;
    let mut child = tokio::process::Command::new(path)
        .args([
            "--plugins=jenkins,jquery",
            "--aggression=1",
            "--follow-redirect=never",
            "--no-cookies",
            "--max-threads=1",
            "--quiet",
            "--log-json=-",
        ])
        .arg(&file)
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("could not start WhatWeb")?;
    let mut stdout = child
        .stdout
        .take()
        .context("WhatWeb stdout missing")?
        .take(MAX_OUTPUT_BYTES + 1);
    let run = async {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await?;
        ensure!(
            output.len() as u64 <= MAX_OUTPUT_BYTES,
            "WhatWeb output limit exceeded"
        );
        ensure!(
            child.wait().await?.success(),
            "WhatWeb exited unsuccessfully"
        );
        parse_output(&output, &file, fetch.status)
    };
    let run = tokio::time::timeout(TIMEOUT, run);
    tokio::pin!(run);
    loop {
        tokio::select! {
            result = &mut run => return result.context("WhatWeb timed out")?,
            _ = tokio::time::sleep(Duration::from_millis(100)) => ctx.ensure_active()?,
        }
    }
}

fn response_snapshot(fetch: &FetchResult) -> Option<String> {
    let jenkins = fetch
        .header("x-jenkins")
        .filter(|version| valid_version(version));
    let mut scripts = BTreeSet::new();
    if fetch.content_type().to_ascii_lowercase().contains("html") {
        let end = fetch
            .body
            .floor_char_boundary(MAX_BODY_BYTES.min(fetch.body.len()));
        let body = &fetch.body[..end];
        if body.to_ascii_lowercase().contains("jquery") {
            let base = url::Url::parse("https://snapshot.invalid/").expect("valid constant URL");
            let selector = scraper::Selector::parse("script[src]").expect("valid selector");
            let document = scraper::Html::parse_document(body);
            scripts.extend(
                document
                    .select(&selector)
                    .filter_map(|script| script.attr("src"))
                    .filter_map(|src| base.join(src).ok())
                    .filter(|url| matches!(url.scheme(), "http" | "https"))
                    .map(|url| url.path().to_ascii_lowercase())
                    .filter(|path| {
                        path.len() <= 512
                            && path.contains("jquery")
                            && path
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
                    })
                    .take(32),
            );
        }
    }
    if jenkins.is_none() && scripts.is_empty() {
        return None;
    }
    // WhatWeb's JQuery plugin can match filenames in prose. Rebuild script
    // references from HTML elements and omit URL hosts, queries, and cookies.
    let mut snapshot = format!("HTTP/1.1 {} Response\r\n", fetch.status);
    if let Some(version) = jenkins {
        snapshot.push_str(&format!("X-Jenkins: {version}\r\n"));
    }
    snapshot.push_str("\r\n<!doctype html>\n");
    for src in scripts {
        snapshot.push_str(&format!("<script src=\"{src}\"></script>\n"));
    }
    Some(snapshot)
}

fn valid_version(version: &str) -> bool {
    version.len() <= 40
        && version.split('.').count() >= 2
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_output(output: &[u8], file: &Path, status: u16) -> Result<Vec<Value>> {
    let [entry]: [Entry; 1] = serde_json::from_slice(output).context("invalid WhatWeb JSON")?;
    ensure!(
        Path::new(&entry.target) == file && entry.http_status == status,
        "WhatWeb returned results for a different response"
    );
    let mut technologies = Vec::new();
    for (plugin, name) in [("Jenkins", "jenkins"), ("JQuery", "jquery")] {
        if let Some(result) = entry.plugins.get(plugin) {
            for version in result
                .version
                .iter()
                .filter(|value| valid_version(value))
                .take(8)
            {
                technologies.push(json!({"name":name,"version":version,"source":"whatweb",
                    "evidence":format!("WhatWeb {plugin} plugin found a version in the HTTP response")}));
            }
        }
    }
    Ok(technologies)
}
