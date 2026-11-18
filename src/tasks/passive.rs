use crate::domain::Job;
use crate::scope::{canonical_url_key, normalize_domain};
use crate::tasks::{dedup_strings, ensure_target_limit, provider, TaskContext, TaskOutcome};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubdomainParams {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    providers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlParams {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    sources: Vec<String>,
    limit: Option<usize>,
}

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

pub async fn run_subdomains(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: SubdomainParams = serde_json::from_value(job.params.clone())?;
    let mut domains = if params.domains.is_empty() {
        scope_hosts(ctx)
    } else {
        params.domains
    };
    domains = dedup_strings(&domains);
    if domains.is_empty() {
        anyhow::bail!("no domains supplied and scope has no allowed DNS names");
    }
    let providers = if params.providers.is_empty() {
        vec!["certspotter".to_string()]
    } else {
        params.providers
    };
    let mut outcome = TaskOutcome::new();
    outcome.target(domains.len());
    let client = provider::client(&ctx.config)?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut wildcards: HashSet<String> = HashSet::new();
    let mut source_status = Vec::new();
    for raw_domain in domains {
        ctx.ensure_active()?;
        let domain = match normalize_domain(&raw_domain) {
            Ok(value) => value,
            Err(err) => {
                outcome.error(format!("{raw_domain}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if !ctx.allows_host_now(&domain) {
            outcome.error(format!("domain {domain} is outside the effective scope"));
            outcome.skipped();
            continue;
        }
        for provider_name in &providers {
            if provider_name != "certspotter" {
                outcome.error(format!("unsupported CT provider: {provider_name}"));
                continue;
            }
            match collect_certspotter(&client, ctx, &domain).await {
                Ok(result) => {
                    for name in result.names {
                        let Ok(host) = normalize_domain(&name) else {
                            continue;
                        };
                        if name.starts_with("*.") {
                            wildcards.insert(host.clone());
                            outcome.observe(
                                "certspotter",
                                "dns_wildcard",
                                "host",
                                &host,
                                json!({"wildcard": name, "domain": domain}),
                                if ctx.scope.allows_host(&host) {
                                    "allowed"
                                } else {
                                    "denied"
                                },
                            );
                            continue;
                        }
                        if !seen.insert(host.clone()) {
                            continue;
                        }
                        let allowed = ctx.scope.allows_host(&host);
                        outcome.observe(
                            "certspotter",
                            "host",
                            "host",
                            &host,
                            json!({"domain": domain}),
                            if allowed { "allowed" } else { "denied" },
                        );
                    }
                    source_status.push(json!({
                        "provider": "certspotter",
                        "domain": domain,
                        "status": "ok",
                        "pages": result.pages,
                        "issuances": result.issuances
                    }));
                }
                Err(err) => {
                    outcome.error(format!("certspotter {domain}: {err}"));
                    source_status.push(json!({
                        "provider": "certspotter",
                        "domain": domain,
                        "status": "error",
                        "reason": err.to_string()
                    }));
                }
            }
        }
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
        "subdomains": seen.iter().cloned().collect::<Vec<_>>(),
        "wildcards": wildcards.iter().cloned().collect::<Vec<_>>(),
        "sources": source_status,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "subdomains",
        &format!("{}-subdomains.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}

struct CtResult {
    names: Vec<String>,
    pages: u32,
    issuances: u64,
}

async fn collect_certspotter(
    client: &reqwest::Client,
    ctx: &TaskContext,
    domain: &str,
) -> Result<CtResult> {
    let mut next = {
        let mut url = Url::parse(&ctx.config.certspotter_url)?;
        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("include_subdomains", "true")
            .append_pair("expand", "dns_names");
        url
    };
    let base_origin = Url::parse(&ctx.config.certspotter_url)?
        .origin()
        .ascii_serialization();
    let mut names = Vec::new();
    let mut pages = 0u32;
    let mut issuances = 0u64;
    while pages < 10 {
        ctx.ensure_active()?;
        pages += 1;
        let mut request = client.get(next.clone());
        if let Some(token) = &ctx.config.certspotter_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .timeout(ctx.config.http_timeout())
            .send()
            .await
            .context("certspotter request failed")?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("Cert Spotter quota exceeded (HTTP 429)");
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            anyhow::bail!("Cert Spotter rejected the configured credentials");
        }
        if !status.is_success() {
            anyhow::bail!("Cert Spotter returned HTTP {status}");
        }
        let link = response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            let remaining = (ctx.config.max_body_bytes as usize).saturating_sub(body.len());
            if chunk.len() > remaining {
                anyhow::bail!("Cert Spotter response exceeded configured body limit");
            }
            body.extend_from_slice(&chunk);
            if body.len() >= ctx.config.max_body_bytes as usize {
                anyhow::bail!("Cert Spotter response exceeded configured body limit");
            }
        }
        let value: Value = serde_json::from_slice(&body).context("invalid Cert Spotter JSON")?;
        let Some(items) = value.as_array() else {
            anyhow::bail!("unexpected Cert Spotter payload");
        };
        for item in items {
            issuances += 1;
            if let Some(list) = item.get("dns_names").and_then(Value::as_array) {
                for name in list {
                    if let Some(name) = name.as_str() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        let Some(link) = link else {
            break;
        };
        let Some(next_url) = parse_link_next(&link) else {
            break;
        };
        if next_url.origin().ascii_serialization() != base_origin {
            anyhow::bail!("Cert Spotter pagination link points to an unexpected origin");
        }
        next = next_url;
    }
    Ok(CtResult {
        names,
        pages,
        issuances,
    })
}

fn parse_link_next(link: &str) -> Option<Url> {
    for part in link.split(',') {
        let mut pieces = part.split(';');
        let url_part = pieces.next()?.trim().trim_matches(['<', '>']);
        let rel = pieces.any(|piece| {
            let piece = piece.trim();
            piece == "rel=\"next\"" || piece == "rel=next"
        });
        if rel {
            return Url::parse(url_part).ok();
        }
    }
    None
}

pub async fn run_urls_passive(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: UrlParams = serde_json::from_value(job.params.clone())?;
    let mut domains = if params.domains.is_empty() {
        scope_hosts(ctx)
    } else {
        params.domains
    };
    domains = dedup_strings(&domains);
    if domains.is_empty() {
        anyhow::bail!("no domains supplied and scope has no allowed DNS names");
    }
    let sources = if params.sources.is_empty() {
        vec!["wayback".to_string(), "commoncrawl".to_string()]
    } else {
        params.sources
    };
    let limit = params
        .limit
        .unwrap_or(1000)
        .min(ctx.config.max_queue_targets)
        .max(1);
    ensure_target_limit(limit, &ctx.config)?;
    let client = provider::client(&ctx.config)?;
    let mut outcome = TaskOutcome::new();
    outcome.target(domains.len());
    let mut seen: HashSet<String> = HashSet::new();
    let mut source_status = Vec::new();
    for raw_domain in domains {
        ctx.ensure_active()?;
        let domain = normalize_domain(&raw_domain)?;
        if !ctx.allows_host_now(&domain) {
            outcome.error(format!("domain {domain} is outside the effective scope"));
            outcome.skipped();
            continue;
        }
        for source in &sources {
            ctx.ensure_active()?;
            let result = match source.as_str() {
                "wayback" => collect_wayback(&client, ctx, &domain, limit).await,
                "commoncrawl" => collect_commoncrawl(&client, ctx, &domain, limit).await,
                other => Err(anyhow::anyhow!("unsupported URL source: {other}")),
            };
            match result {
                Ok(urls) => {
                    let mut added = 0usize;
                    for url in urls {
                        let canonical = canonical_url_key(&url).unwrap_or_else(|_| url.to_string());
                        if !seen.insert(canonical) {
                            continue;
                        }
                        let allowed = Url::parse(&url)
                            .ok()
                            .and_then(|parsed| parsed.host_str().map(str::to_string))
                            .is_some_and(|host| ctx.scope.allows_host(&host));
                        outcome.observe(
                            source,
                            "url",
                            "url",
                            &url,
                            json!({"source": source, "domain": domain}),
                            if allowed { "allowed" } else { "denied" },
                        );
                        added += 1;
                    }
                    source_status.push(json!({
                        "source": source, "domain": domain, "status": "ok", "urls": added
                    }));
                }
                Err(err) => {
                    outcome.error(format!("{source} {domain}: {err}"));
                    source_status.push(json!({
                        "source": source, "domain": domain, "status": "error",
                        "reason": err.to_string()
                    }));
                }
            }
        }
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
        "urls": seen.len(),
        "sources": source_status,
    });
    let result = outcome.result.clone();
    outcome.add_artifact("urls", &format!("{}-urls.json", job.id), &result)?;
    Ok(outcome.finalize())
}

async fn collect_wayback(
    client: &reqwest::Client,
    ctx: &TaskContext,
    domain: &str,
    limit: usize,
) -> Result<Vec<String>> {
    let mut url = Url::parse(&ctx.config.wayback_url)?;
    url.query_pairs_mut()
        .append_pair("url", &format!("{domain}/*"))
        .append_pair("output", "json")
        .append_pair("fl", "original,timestamp,statuscode")
        .append_pair("filter", "statuscode:200")
        .append_pair("collapse", "urlkey")
        .append_pair("limit", &limit.to_string());
    let (status, text, truncated) = provider::get_text(
        client,
        url.as_str(),
        provider::headers(&[]),
        ctx.config.max_body_bytes,
    )
    .await?;
    if truncated {
        anyhow::bail!("Wayback response exceeded configured body limit");
    }
    if status != 200 {
        anyhow::bail!("Wayback returned HTTP {status}");
    }
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(&text).context("invalid Wayback JSON")?;
    let Some(rows) = value.as_array() else {
        return Ok(Vec::new());
    };
    let mut urls = Vec::new();
    for row in rows.iter().skip(1) {
        if let Some(cells) = row.as_array() {
            if let Some(original) = cells.first().and_then(Value::as_str) {
                urls.push(original.to_string());
            }
        }
    }
    Ok(urls)
}

async fn collect_commoncrawl(
    client: &reqwest::Client,
    ctx: &TaskContext,
    domain: &str,
    limit: usize,
) -> Result<Vec<String>> {
    let (status, value, _) = provider::get_json(
        client,
        &ctx.config.commoncrawl_url,
        provider::headers(&[]),
        2 * 1024 * 1024,
    )
    .await?;
    if status != 200 {
        anyhow::bail!("Common Crawl index list returned HTTP {status}");
    }
    let index = value
        .as_ref()
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find_map(|item| item.get("cdx-api").and_then(Value::as_str))
        })
        .context("Common Crawl index list has no cdx-api entry")?
        .to_string();
    let mut url = Url::parse(&index)?;
    let configured_origin = Url::parse(&ctx.config.commoncrawl_url)?
        .origin()
        .ascii_serialization();
    if url.origin().ascii_serialization() != configured_origin {
        anyhow::bail!("Common Crawl index URL points to an unexpected origin");
    }
    url.query_pairs_mut()
        .append_pair("url", &format!("{domain}/*"))
        .append_pair("output", "json")
        .append_pair("fl", "url")
        .append_pair("limit", &limit.to_string());
    let (status, text, truncated) = provider::get_text(
        client,
        url.as_str(),
        provider::headers(&[]),
        ctx.config.max_body_bytes,
    )
    .await?;
    if truncated {
        anyhow::bail!("Common Crawl response exceeded configured body limit");
    }
    if status != 200 {
        anyhow::bail!("Common Crawl returned HTTP {status}");
    }
    let mut urls = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            if let Some(url) = value.get("url").and_then(Value::as_str) {
                urls.push(url.to_string());
            }
        }
        if urls.len() >= limit {
            break;
        }
    }
    Ok(urls)
}
