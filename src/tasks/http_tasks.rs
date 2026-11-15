use crate::domain::Job;
use crate::scope::{canonical_url_key, normalize_domain, parse_target_url};
use crate::tasks::{
    dedup_strings, ensure_target_limit, params_strings, parse_params, TaskContext, TaskOutcome,
};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeParams {
    #[serde(default)]
    targets: Vec<String>,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrawlParams {
    #[serde(default)]
    seeds: Vec<String>,
    max_pages: Option<usize>,
    max_depth: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathParams {
    #[serde(default)]
    base_urls: Vec<String>,
    #[serde(default)]
    words: Vec<String>,
}

const DEFAULT_PATHS: &[&str] = &[
    "admin",
    "login",
    "api",
    "health",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "backup",
    "config",
    "dashboard",
    "docs",
    "graphql",
    "metrics",
    "server-status",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "static",
    "uploads",
    "vendor",
    "old",
    "test",
    "dev",
    "debug",
];

fn scope_hosts(ctx: &TaskContext) -> Vec<String> {
    let mut out = Vec::new();
    for rule in &ctx.scope.snapshot.rules {
        if !rule.exclusion
            && matches!(
                rule.kind,
                crate::scope::RuleKind::ExactDomain | crate::scope::RuleKind::SubdomainTree
            )
            && ctx.scope.allows_host(&rule.value)
        {
            out.push(rule.value.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn chain_urls(ctx: &TaskContext) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for observation in ctx.chain_input_observations("url")? {
        out.push(observation.asset);
    }
    for observation in ctx.chain_input_observations("http")? {
        if let Some(url) = observation.data.get("url").and_then(Value::as_str) {
            out.push(url.to_string());
        }
    }
    Ok(out)
}

pub async fn run_probe(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: ProbeParams = parse_params(&job.params)?;
    let mode = params.mode.unwrap_or_else(|| "root".to_string());
    if mode != "root" && mode != "url" {
        anyhow::bail!("http.probe mode must be 'root' or 'url'");
    }
    let mut targets = if params.targets.is_empty() {
        let chained = chain_urls(ctx)?;
        if chained.is_empty() {
            scope_hosts(ctx)
        } else {
            chained
        }
    } else {
        params.targets
    };
    if mode == "root" {
        let mut roots = Vec::new();
        for target in targets {
            if target.contains("://") {
                roots.push(target);
            } else {
                let host = target.trim().trim_end_matches('.');
                roots.push(format!("https://{host}"));
                roots.push(format!("http://{host}"));
            }
        }
        targets = roots;
    }
    targets = dedup_strings(&targets);
    ensure_target_limit(targets.len(), &ctx.config)?;
    let prober = ctx.prober()?;
    let policy = ctx.config.network_policy();
    let mut outcome = TaskOutcome::new();
    outcome.target(targets.len());
    let mut hosts = Vec::new();
    for target in targets {
        ctx.ensure_active()?;
        let url = match parse_target_url(&target) {
            Ok(url) => url,
            Err(err) => {
                outcome.error(format!("{target}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        let host = url.host_str().unwrap_or_default().to_string();
        if !ctx.authorize_url_now(&url) {
            outcome.error(format!("{host} is outside the effective scope"));
            outcome.skipped();
            continue;
        }
        match prober
            .get_with_authorizer(url.as_str(), &policy, |candidate| {
                ctx.authorize_url_now(candidate)
            })
            .await
        {
            Ok(fetch) => {
                let title = extract_title(&fetch.body);
                let technologies = detect_technologies(&fetch);
                let cert = fetch
                    .tls_cert_not_after
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
                outcome.observe(
                    "http.probe",
                    "host",
                    "host",
                    &host,
                    json!({"url": fetch.final_url, "verified_ip": fetch.remote_ip.to_string()}),
                    "allowed",
                );
                outcome.observe(
                    "http.probe",
                    "http",
                    "url",
                    &fetch.final_url,
                    json!({
                        "mode": mode,
                        "requested_url": target,
                        "url": fetch.final_url,
                        "verified_ip": fetch.remote_ip.to_string(),
                        "status_code": fetch.status,
                        "title": title,
                        "server": fetch.header("server").unwrap_or(""),
                        "content_type": fetch.content_type(),
                        "technologies": technologies,
                        "tls_cert_not_after": cert,
                        "redirects": fetch.redirects,
                        "body_truncated": fetch.truncated,
                    }),
                    "allowed",
                );
                if !hosts.contains(&host) {
                    hosts.push(host.clone());
                }
                outcome.processed();
            }
            Err(err) => {
                outcome.error(format!("{target}: {err}"));
                outcome.skipped();
            }
        }
    }
    outcome.result = json!({
        "format_version": "1",
        "mode": mode,
        "probed": outcome.counters.processed,
        "hosts": hosts,
    });
    let result = outcome.result.clone();
    outcome.add_artifact("http_probe", &format!("{}-http.json", job.id), &result)?;
    Ok(outcome.finalize())
}

pub async fn run_crawl(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: CrawlParams = parse_params(&job.params)?;
    let max_pages = params
        .max_pages
        .unwrap_or(ctx.config.max_crawl_pages)
        .min(ctx.config.max_crawl_pages)
        .max(1);
    let max_depth = params
        .max_depth
        .unwrap_or(ctx.config.max_crawl_depth)
        .min(ctx.config.max_crawl_depth);
    let mut seeds = if params.seeds.is_empty() {
        let chained = chain_urls(ctx)?;
        if chained.is_empty() {
            scope_hosts(ctx)
                .into_iter()
                .flat_map(|host| [format!("https://{host}/"), format!("http://{host}/")])
                .collect()
        } else {
            chained
        }
    } else {
        params.seeds
    };
    seeds = dedup_strings(&seeds);
    ensure_target_limit(seeds.len(), &ctx.config)?;
    let prober = ctx.prober()?;
    let policy = ctx.config.network_policy();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();
    for seed in seeds {
        if let Ok(url) = parse_target_url(&seed) {
            let key = canonical_url_key(url.as_str())?;
            if seen.insert(key) {
                queue.push_back((url.to_string(), 0));
            }
        }
    }
    let mut outcome = TaskOutcome::new();
    outcome.target(queue.len());
    let mut errors_for_links = 0usize;
    while let Some((url, depth)) = queue.pop_front() {
        if outcome.counters.processed >= max_pages as u64 {
            break;
        }
        ctx.ensure_active()?;
        let parsed = match parse_target_url(&url) {
            Ok(value) => value,
            Err(err) => {
                outcome.error(format!("{url}: {err}"));
                continue;
            }
        };
        if let Some(host) = parsed.host_str() {
            if !ctx.allows_host_now(host) {
                outcome.skipped();
                continue;
            }
        }
        match prober
            .get_with_authorizer(parsed.as_str(), &policy, |candidate| {
                ctx.authorize_url_now(candidate)
            })
            .await
        {
            Ok(fetch) => {
                outcome.observe(
                    "http.crawl",
                    "http",
                    "url",
                    &fetch.final_url,
                    json!({
                        "url": fetch.final_url,
                        "depth": depth,
                        "status_code": fetch.status,
                        "title": extract_title(&fetch.body),
                        "server": fetch.header("server").unwrap_or(""),
                        "verified_ip": fetch.remote_ip.to_string(),
                    }),
                    "allowed",
                );
                outcome.processed();
                if depth < max_depth && fetch.content_type().contains("text/html") {
                    for link in extract_links(&fetch.body) {
                        let Ok(next) = parsed.join(&link) else {
                            errors_for_links += 1;
                            continue;
                        };
                        if !matches!(next.scheme(), "http" | "https") {
                            continue;
                        }
                        let key = canonical_url_key(next.as_str())?;
                        let next_host = next.host_str().unwrap_or_default().to_string();
                        if !seen.insert(key) {
                            continue;
                        }
                        let allowed = ctx.allows_host_now(&next_host);
                        outcome.observe(
                            "http.crawl",
                            "url",
                            "url",
                            next.as_str(),
                            json!({"source": "html", "from": parsed.as_str(), "depth": depth + 1}),
                            if allowed { "allowed" } else { "denied" },
                        );
                        if allowed
                            && outcome.counters.processed + (queue.len() as u64) < max_pages as u64
                        {
                            queue.push_back((next.to_string(), depth + 1));
                        }
                    }
                }
            }
            Err(err) => {
                outcome.error(format!("{url}: {err}"));
                outcome.skipped();
            }
        }
    }
    if errors_for_links > 0 {
        outcome.error(format!("{errors_for_links} malformed links were ignored"));
    }
    outcome.result = json!({
        "format_version": "1",
        "pages": outcome.counters.processed,
        "urls_seen": seen.len(),
        "max_pages": max_pages,
        "max_depth": max_depth,
    });
    let result = outcome.result.clone();
    outcome.add_artifact("crawl", &format!("{}-crawl.json", job.id), &result)?;
    Ok(outcome.finalize())
}

pub async fn run_paths(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: PathParams = parse_params(&job.params)?;
    let mut bases = if params.base_urls.is_empty() {
        let chained = chain_urls(ctx)?;
        if chained.is_empty() {
            scope_hosts(ctx)
                .into_iter()
                .map(|host| format!("https://{host}/"))
                .collect()
        } else {
            chained
        }
    } else {
        params.base_urls
    };
    bases = dedup_strings(&bases);
    let mut words: Vec<String> = if params.words.is_empty() {
        DEFAULT_PATHS
            .iter()
            .map(|value| value.to_string())
            .collect()
    } else {
        params.words
    };
    words = dedup_strings(&words);
    if words.len() > ctx.config.max_wordlist_entries {
        anyhow::bail!("path wordlist exceeds configured limit");
    }
    if bases.len() * words.len() > ctx.config.max_queue_targets {
        anyhow::bail!("path discovery request budget exceeds configured target limit");
    }
    let prober = ctx.prober()?;
    let policy = ctx.config.network_policy();
    let mut outcome = TaskOutcome::new();
    outcome.target(bases.len() * words.len());
    let mut soft404 = Vec::new();
    for base in bases {
        ctx.ensure_active()?;
        let base_url = match parse_target_url(&base) {
            Ok(url) => url,
            Err(err) => {
                outcome.error(format!("{base}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        let base_dir = format!("{}/", base_url.as_str().trim_end_matches('/'));
        let probe_path = format!(
            "__lastest_missing_{}",
            crate::domain::new_id("path").replace('_', "")
        );
        let probe_url = format!("{base_dir}{probe_path}");
        let baseline = match prober
            .get_with_authorizer(&probe_url, &policy, |candidate| {
                ctx.authorize_url_now(candidate)
            })
            .await
        {
            Ok(fetch) => Some((fetch.status, fetch.body.len())),
            Err(err) => {
                outcome.error(format!("soft-404 baseline {base_dir}: {err}"));
                None
            }
        };
        for word in &words {
            ctx.ensure_active()?;
            let candidate = format!("{base_dir}{}", word.trim_start_matches('/'));
            let url = match parse_target_url(&candidate) {
                Ok(url) => url,
                Err(_) => {
                    outcome.skipped();
                    continue;
                }
            };
            if let Some(host) = url.host_str() {
                if !ctx.allows_host_now(host) {
                    outcome.skipped();
                    continue;
                }
            }
            match prober
                .get_with_authorizer(url.as_str(), &policy, |candidate| {
                    ctx.authorize_url_now(candidate)
                })
                .await
            {
                Ok(fetch) => {
                    let soft = baseline.is_some_and(|(status, len)| {
                        status == fetch.status
                            && (len as i64 - fetch.body.len() as i64).unsigned_abs()
                                < (len.max(1) / 50 + 16) as u64
                    });
                    if soft {
                        outcome.skipped();
                        soft404.push(url.to_string());
                        continue;
                    }
                    if matches!(fetch.status, 200 | 201 | 204 | 301 | 302 | 307 | 401 | 403) {
                        outcome.observe(
                            "paths.discover",
                            "http",
                            "url",
                            &fetch.final_url,
                            json!({
                                "url": fetch.final_url,
                                "word": word,
                                "status_code": fetch.status,
                                "title": extract_title(&fetch.body),
                                "content_type": fetch.content_type(),
                                "verified_ip": fetch.remote_ip.to_string(),
                            }),
                            "allowed",
                        );
                        outcome.observe(
                            "paths.discover",
                            "url",
                            "url",
                            &fetch.final_url,
                            json!({"word": word}),
                            "allowed",
                        );
                        outcome.processed();
                    } else {
                        outcome.skipped();
                    }
                }
                Err(_) => outcome.skipped(),
            }
        }
    }
    outcome.result = json!({
        "format_version": "1",
        "checked": outcome.counters.targets,
        "found": outcome.counters.processed,
        "soft_404": soft404,
    });
    let result = outcome.result.clone();
    outcome.add_artifact("paths", &format!("{}-paths.json", job.id), &result)?;
    Ok(outcome.finalize())
}

pub fn extract_title(body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let Some(start) = lower.find("<title") else {
        return String::new();
    };
    let Some(open_end) = lower[start..].find('>').map(|idx| start + idx + 1) else {
        return String::new();
    };
    let Some(end) = lower[open_end..].find("</title>").map(|idx| open_end + idx) else {
        return String::new();
    };
    let title = body[open_end..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    title.chars().take(300).collect()
}

pub fn extract_links(body: &str) -> Vec<String> {
    let mut links = Vec::new();
    let lower = body.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(found) = lower[cursor..].find("href") {
        let index = cursor + found;
        let rest = &body[index + 4..];
        let rest_trimmed = rest.trim_start();
        let Some(rest_trimmed) = rest_trimmed.strip_prefix('=') else {
            cursor = index + 4;
            continue;
        };
        let rest_trimmed = rest_trimmed.trim_start();
        let (quote, rest_trimmed) = if let Some(value) = rest_trimmed.strip_prefix('"') {
            ('"', value)
        } else if let Some(value) = rest_trimmed.strip_prefix('\'') {
            ('\'', value)
        } else {
            cursor = index + 4;
            continue;
        };
        if let Some(end) = rest_trimmed.find(quote) {
            let value = rest_trimmed[..end].trim();
            if !value.is_empty()
                && !value.starts_with('#')
                && !value.starts_with("javascript:")
                && !value.starts_with("mailto:")
                && !value.starts_with("data:")
            {
                links.push(value.to_string());
            }
            cursor = index + 4 + (rest_trimmed[..end].len()) + 1;
        } else {
            cursor = index + 4;
        }
    }
    links
}

pub fn detect_technologies(fetch: &crate::net::http::FetchResult) -> Vec<Value> {
    let mut items = Vec::new();
    let mut push = |name: &str, version: Option<String>, source: &str| {
        items.push(json!({
            "name": name,
            "version": version,
            "source": source,
            "catalog_version": 1
        }));
    };
    if let Some(server) = fetch.header("server") {
        let lower = server.to_ascii_lowercase();
        for (name, marker) in [
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("cloudflare", "cloudflare"),
            ("microsoft-iis", "microsoft-iis"),
            ("caddy", "caddy"),
        ] {
            if lower.contains(marker) {
                let version = server
                    .split('/')
                    .nth(1)
                    .and_then(|value| value.split_whitespace().next())
                    .map(str::to_string);
                push(name, version, "header:server");
            }
        }
    }
    if let Some(powered) = fetch.header("x-powered-by") {
        push(
            powered.split('/').next().unwrap_or(powered),
            powered.split('/').nth(1).map(str::to_string),
            "header:x-powered-by",
        );
    }
    if let Some(cookie) = fetch
        .header_values("set-cookie")
        .first()
        .map(|value| value.to_ascii_lowercase())
    {
        if cookie.contains("phpsessid") {
            push("php", None, "cookie");
        }
        if cookie.contains("jsessionid") {
            push("java", None, "cookie");
        }
    }
    let body_lower = fetch.body.to_ascii_lowercase();
    if body_lower.contains("wp-content/") || body_lower.contains("wordpress") {
        push("wordpress", None, "body");
    }
    if body_lower.contains("_next/static") {
        push("next.js", None, "body");
    }
    if body_lower.contains("ng-version") {
        push("angular", None, "body");
    }
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    items.dedup_by(|a, b| a["name"] == b["name"]);
    items
}

pub fn normalize_host_target(value: &str) -> Result<String> {
    if value.contains("://") {
        let url = parse_target_url(value)?;
        Ok(url.host_str().unwrap_or_default().to_string())
    } else {
        Ok(normalize_domain(value)?)
    }
}

#[allow(dead_code)]
fn _params_marker() -> Result<Vec<String>> {
    params_strings(&json!({}), "x")
}
