use crate::domain::Job;
use crate::scope::{canonical_url_key, normalize_domain};
use crate::tasks::{
    dedup_strings, discovery, ensure_target_limit, provider, TaskContext, TaskOutcome,
};
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
    let saved_token = crate::provider_settings::read_key(&ctx.db, &ctx.config, "certspotter")?;
    let token = saved_token
        .as_deref()
        .or(ctx.config.certspotter_token.as_deref());
    let mut seen: HashSet<String> = HashSet::new();
    let mut wildcards: HashSet<String> = HashSet::new();
    let mut source_status = Vec::new();
    let mut checked = HashSet::new();
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    let dns = ctx.dns()?;
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
            match collect_certspotter(&client, ctx, &domain, token).await {
                Ok(result) => {
                    for name in result.names {
                        let Ok(host) = normalize_domain(&name) else {
                            continue;
                        };
                        // Certificate wildcards are diagnostics, not concrete hosts.
                        if name.starts_with("*.") {
                            wildcards.insert(host);
                            continue;
                        }
                        if seen.contains(&host) || !checked.insert((domain.clone(), host.clone())) {
                            continue;
                        }
                        if !discovery::allows_dns(ctx, &domain, &host)? {
                            outcome.skipped();
                            rejected.push(json!({"host":host,"domain":domain,"reason":"scope"}));
                            continue;
                        }
                        let ips = match discovery::resolve_ips(&dns, ctx, &domain, &host).await {
                            Ok(ips) => ips,
                            Err(error) => {
                                ctx.ensure_active()?;
                                outcome.skipped();
                                if !discovery::allows_dns(ctx, &domain, &host)? {
                                    rejected.push(
                                        json!({"host":host,"domain":domain,"reason":"scope"}),
                                    );
                                } else if crate::net::dns::is_no_records(&error) {
                                    rejected.push(json!({"host":host,"domain":domain,"reason":"no_addresses"}));
                                } else {
                                    let message = crate::net::dns::error_message(&error);
                                    outcome.error(format!("DNS {host}: {message}"));
                                    rejected.push(json!({"host":host,"domain":domain,"reason":"dns_error","error":message}));
                                }
                                continue;
                            }
                        };
                        discovery::observe_host(
                            &mut outcome,
                            ctx,
                            "certspotter",
                            &domain,
                            &host,
                            &ips,
                        )?;
                        seen.insert(host.clone());
                        hosts.push(json!({"host":host,"ips":ips,"dns_verified":true}));
                    }
                    let mut source = json!({
                        "provider": "certspotter", "domain": domain,
                        "status": if result.error.is_some() { "partial" } else { "ok" },
                        "pages": result.pages, "issuances": result.issuances,
                    });
                    if let Some(error) = result.error {
                        outcome.error(format!("certspotter {domain}: {error}"));
                        source["reason"] = json!(error);
                    }
                    source_status.push(source);
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
    let mut subdomains: Vec<_> = seen.into_iter().collect();
    subdomains.sort();
    let mut wildcards: Vec<_> = wildcards.into_iter().collect();
    wildcards.sort();
    hosts.sort_by(|a, b| a["host"].as_str().cmp(&b["host"].as_str()));
    outcome.result = json!({
        "format_version": "1",
        "subdomains": subdomains,
        "hosts": hosts,
        "rejected": rejected,
        "dns_verified": true,
        "wildcards": wildcards,
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
    error: Option<String>,
}

async fn collect_certspotter(
    client: &reqwest::Client,
    ctx: &TaskContext,
    domain: &str,
    token: Option<&str>,
) -> Result<CtResult> {
    // Build every page from the configured v1 endpoint. The provider's Link
    // header can omit /v1; the documented cursor is the last issuance's id.
    let mut endpoint = Url::parse(&ctx.config.certspotter_url)?;
    let retained: Vec<(String, String)> = endpoint
        .query_pairs()
        .filter(|(key, _)| {
            !matches!(
                key.as_ref(),
                "domain" | "include_subdomains" | "expand" | "after"
            )
        })
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    endpoint.set_query(None);
    endpoint
        .query_pairs_mut()
        .extend_pairs(retained)
        .append_pair("domain", domain)
        .append_pair("include_subdomains", "true")
        .append_pair("expand", "dns_names");
    let mut next = endpoint.clone();
    let mut names = Vec::new();
    let mut pages = 0u32;
    let mut issuances = 0u64;
    let mut cursors = HashSet::new();
    let result = async {
        loop {
            ctx.ensure_active()?;
            pages += 1;
            let mut request = client.get(next.clone());
            if let Some(token) = token {
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
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                anyhow::bail!("Cert Spotter rejected the configured credentials");
            }
            if !status.is_success() {
                anyhow::bail!("Cert Spotter returned HTTP {status}");
            }
            let mut body = Vec::new();
            let mut response = response;
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() as u64 > ctx.config.max_body_bytes.saturating_sub(body.len() as u64)
                {
                    anyhow::bail!("Cert Spotter response exceeded configured body limit");
                }
                body.extend_from_slice(&chunk);
            }
            let value: Value =
                serde_json::from_slice(&body).context("invalid Cert Spotter JSON")?;
            let items = value
                .as_array()
                .context("unexpected Cert Spotter payload")?;
            if items.is_empty() {
                break;
            }
            for item in items {
                issuances += 1;
                if let Some(list) = item.get("dns_names").and_then(Value::as_array) {
                    names.extend(list.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
            let cursor = items
                .last()
                .and_then(|item| item.get("id"))
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .context("Cert Spotter response is missing its pagination id")?;
            if !cursors.insert(cursor.to_owned()) {
                anyhow::bail!("Cert Spotter repeated its pagination id; results are incomplete");
            }
            if pages >= 10 {
                anyhow::bail!("Cert Spotter reached the 10-page limit; results are incomplete");
            }
            next = endpoint.clone();
            next.query_pairs_mut().append_pair("after", cursor);
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let error = match result {
        Ok(()) => None,
        Err(error) if error.is::<crate::tasks::TaskCancelled>() || issuances == 0 => {
            return Err(error)
        }
        Err(error) => Some(error.to_string()),
    };
    Ok(CtResult {
        names,
        pages,
        issuances,
        error,
    })
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
