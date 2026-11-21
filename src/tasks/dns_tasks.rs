use crate::domain::Job;
use crate::scope::{canonical_ip, normalize_domain};
use crate::tasks::{
    dedup_strings, discovery, ensure_target_limit, parse_params, provider, providers, TaskContext,
    TaskOutcome,
};
use anyhow::Result;
use hickory_resolver::proto::rr::RecordType;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordsParams {
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    record_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseParams {
    ips: Vec<String>,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    sources: Option<Vec<String>>,
}

fn push_url_segment(base: &str, segment: &str) -> String {
    match url::Url::parse(base) {
        Ok(mut url) => {
            url.path_segments_mut()
                .map(|mut segments| {
                    segments.push(segment);
                })
                .ok();
            url.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), segment),
    }
}

#[derive(Default)]
struct CandidateAggregate {
    sources: std::collections::BTreeSet<String>,
    source_ips: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct IpSummary {
    sources: Vec<String>,
    candidates: usize,
    status: String,
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

fn chain_hosts(ctx: &TaskContext) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for observation in ctx.chain_input_observations("host")? {
        out.push(observation.asset);
    }
    for observation in ctx.chain_input_observations("url")? {
        if let Ok(url) = crate::scope::parse_target_url(&observation.asset) {
            if let Some(host) = url.host_str() {
                out.push(host.to_string());
            }
        }
    }
    Ok(out)
}

pub async fn run_records(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: RecordsParams = parse_params(&job.params)?;
    let mut targets = if params.targets.is_empty() {
        chain_hosts(ctx)?
    } else {
        params.targets
    };
    if targets.is_empty() {
        targets = scope_hosts(ctx);
    }
    targets = dedup_strings(&targets);
    ensure_target_limit(targets.len(), &ctx.config)?;
    let record_types: Vec<String> = if params.record_types.is_empty() {
        ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
            .iter()
            .map(|value| value.to_string())
            .collect()
    } else {
        params.record_types
    };
    let mut types = Vec::new();
    for value in record_types {
        types.push(crate::net::dns::record_type(&value)?);
    }
    let dns = ctx.dns()?;
    let mut outcome = TaskOutcome::new();
    outcome.target(targets.len());
    let mut records = Vec::new();
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    for raw_target in targets {
        ctx.ensure_active()?;
        let target = raw_target.trim().trim_end_matches('.');
        if target.is_empty() {
            outcome.skipped();
            continue;
        }
        if let Ok(ip) = canonical_ip(target) {
            if !ctx.allows_ip_now(ip) {
                outcome.error(format!("IP target {ip} is not explicitly allowed by scope"));
                outcome.skipped();
                continue;
            }
            if types.contains(&RecordType::PTR) || types.is_empty() {
                match dns.reverse(ip).await {
                    Ok(names) => {
                        for name in names {
                            let in_scope = ctx.scope.allows_host(&name);
                            outcome.observe(
                                "dns",
                                "ptr",
                                "ip",
                                &ip.to_string(),
                                json!({"name": name, "target": target}),
                                if in_scope { "allowed" } else { "denied" },
                            );
                            records.push(json!({"target": target, "type": "PTR", "value": name}));
                        }
                        outcome.processed();
                    }
                    Err(err) => {
                        outcome.error(format!("PTR {ip}: {err}"));
                        outcome.skipped();
                    }
                }
            } else {
                outcome.skipped();
            }
            continue;
        }
        let host = match normalize_domain(target) {
            Ok(host) => host,
            Err(err) => {
                outcome.error(format!("{target}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if !ctx.allows_host_now(&host) {
            outcome.error(format!("host {host} is outside the effective scope"));
            outcome.skipped();
            continue;
        }
        let errors_before = outcome.counters.errors;
        let mut selected = Vec::new();
        for record_type in &types {
            if *record_type == RecordType::PTR {
                continue;
            }
            ctx.ensure_active()?;
            if !ctx.allows_host_now(&host) {
                break;
            }
            match dns.lookup(&host, *record_type).await {
                Ok(answers) => {
                    for answer in answers {
                        selected.push(answer.clone());
                        records.push(json!({
                            "target": target,
                            "type": answer.record_type,
                            "value": answer.value
                        }));
                    }
                }
                Err(err) => {
                    if !crate::net::dns::is_no_records(&err) {
                        let message = crate::net::dns::error_message(&err);
                        outcome.error(format!("{host} {record_type}: {message}"));
                    }
                }
            }
        }
        let ips = match discovery::resolve_ips(&dns, ctx, &host, &host).await {
            Ok(ips) => ips,
            Err(error) => {
                ctx.ensure_active()?;
                outcome.skipped();
                if !ctx.allows_host_now(&host) {
                    rejected.push(json!({"host":host,"reason":"scope"}));
                } else if crate::net::dns::is_no_records(&error) {
                    rejected.push(json!({"host":host,"reason":"no_addresses"}));
                } else {
                    let message = crate::net::dns::error_message(&error);
                    if outcome.counters.errors == errors_before {
                        outcome.error(format!("DNS {host}: {message}"));
                    }
                    rejected.push(json!({"host":host,"reason":"dns_error","error":message}));
                }
                continue;
            }
        };
        discovery::observe_host(&mut outcome, ctx, "dns", &host, &host, &ips)?;
        for answer in selected {
            // The common publisher already records verified A/AAAA answers.
            if answer.record_type == "A" || answer.record_type == "AAAA" {
                continue;
            }
            outcome.observe("dns", "dns", "host", &host,
                json!({"record_type":answer.record_type,"value":answer.value,"target":target,"addresses":ips,"dns_verified":true}),
                "observed");
        }
        hosts.push(json!({"host":host,"ips":ips,"dns_verified":true}));
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
        "targets": outcome.counters.targets,
        "records": records,
        "hosts": hosts,
        "rejected": rejected,
        "dns_verified": true,
        "record_types": types.iter().map(ToString::to_string).collect::<Vec<_>>(),
    });
    let result = outcome.result.clone();
    outcome.add_artifact("dns_records", &format!("{}-dns.json", job.id), &result)?;
    Ok(outcome.finalize())
}

pub async fn run_wordlist(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    crate::tasks::dnsmap::validate(&job.params, &ctx.config)?;
    let params: crate::tasks::dnsmap::WordlistParams = parse_params(&job.params)?;
    let domain = normalize_domain(&params.domain)?;
    ctx.authorize_host(&domain)?;
    let words = crate::tasks::dnsmap::words(&params);
    let dns = ctx.dns()?;
    let mut outcome = TaskOutcome::new();
    outcome.target(words.len());
    // Probe twice to collect wildcard addresses from both address families.
    let mut wildcard: HashSet<IpAddr> = HashSet::new();
    let mut wildcard_ips: Vec<String> = Vec::new();
    for _ in 0..2 {
        ctx.ensure_active()?;
        let label: String = (0..12)
            .map(|_| {
                let idx = rand::rng().random_range(0..36);
                char::from_digit(idx, 36).unwrap_or('x')
            })
            .collect();
        let probe = format!("{label}.{domain}");
        if !discovery::allows_dns(ctx, &domain, &probe)? {
            continue;
        }
        if let Ok(ips) = discovery::resolve_ips(&dns, ctx, &domain, &probe).await {
            for ip in &ips {
                wildcard.insert(*ip);
                wildcard_ips.push(ip.to_string());
            }
        }
    }
    wildcard_ips.sort();
    wildcard_ips.dedup();
    let mut found = Vec::new();
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    let candidates = crate::tasks::dnsmap::discover(&params, &words, ctx).await?;
    let mut lookups = tokio::task::JoinSet::new();
    let mut candidates = candidates.into_iter();
    loop {
        while lookups.len() < params.concurrency {
            let Some(candidate) = candidates.next() else {
                break;
            };
            ctx.ensure_active()?;
            if !discovery::allows_dns(ctx, &domain, &candidate)? {
                continue;
            }
            let dns = dns.clone();
            let ctx = ctx.clone();
            let domain = domain.clone();
            lookups.spawn(async move {
                let result = discovery::resolve_ips(&dns, &ctx, &domain, &candidate).await;
                (candidate, result)
            });
        }
        let next = tokio::select! {
            next = lookups.join_next() => next,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                ctx.ensure_active()?;
                ctx.authorize_host(&domain)?;
                continue;
            }
        };
        let Some(next) = next else {
            break;
        };
        let (candidate, result) = next?;
        ctx.ensure_active()?;
        if !discovery::allows_dns(ctx, &domain, &candidate)? {
            continue;
        }
        match result {
            Ok(ips) => {
                if !wildcard.is_empty() && ips.iter().all(|ip| wildcard.contains(ip)) {
                    outcome.skipped();
                    rejected.push(json!({"host":candidate,"reason":"wildcard","addresses":ips}));
                    continue;
                }
                found.push(candidate.clone());
                discovery::observe_host(
                    &mut outcome,
                    ctx,
                    "dns.wordlist",
                    &domain,
                    &candidate,
                    &ips,
                )?;
                hosts.push(json!({"host":candidate,"ips":ips,"dns_verified":true}));
                outcome.processed();
            }
            Err(error) => {
                outcome.skipped();
                if crate::net::dns::is_no_records(&error) {
                    rejected.push(json!({"host":candidate,"reason":"no_addresses"}));
                } else {
                    let message = crate::net::dns::error_message(&error);
                    outcome.error(format!("DNS {candidate}: {message}"));
                    rejected.push(json!({"host":candidate,"reason":"dns_error","error":message}));
                }
            }
        }
    }
    found.sort();
    outcome.counters.skipped = outcome
        .counters
        .targets
        .saturating_sub(outcome.counters.processed);
    outcome.result = json!({
        "format_version": "1",
        "domain": domain,
        "engine": "dnsmap",
        "wordlist": if params.words.is_empty() { params.wordlist.as_str() } else { "custom" },
        "concurrency": params.concurrency,
        "found": found,
        "hosts": hosts,
        "rejected": rejected,
        "dns_verified": true,
        "wildcard_addresses": wildcard_ips,
        "searched": outcome.counters.targets,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "dns_wordlist",
        &format!("{}-dns-wordlist.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}

pub async fn run_reverse_ip(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: ReverseParams = parse_params(&job.params)?;
    let ips = dedup_strings(&params.ips);
    if ips.is_empty() || ips.len() > 128 {
        anyhow::bail!("reverse.ip accepts 1-128 explicit addresses");
    }
    let selected_sources: Vec<String> = match &params.sources {
        Some(sources) => {
            if sources.is_empty() {
                anyhow::bail!("reverse.ip sources must not be empty");
            }
            dedup_strings(sources)
        }
        None => {
            // Legacy `providers` semantics keep PTR and default to Shodan when
            // the provider list is empty.
            let mut selected = vec!["ptr".to_string()];
            let providers = if params.providers.is_empty() {
                vec!["shodan_internetdb".to_string()]
            } else {
                dedup_strings(&params.providers)
            };
            for provider in providers {
                if !selected.contains(&provider) {
                    selected.push(provider);
                }
            }
            selected
        }
    };
    let use_ptr = selected_sources.iter().any(|source| source == "ptr");
    let selected_providers: Vec<String> = selected_sources
        .iter()
        .filter(|source| source.as_str() != "ptr")
        .cloned()
        .collect();
    let dns = ctx.dns()?;
    let mut outcome = TaskOutcome::new();
    outcome.target(ips.len());
    let mut candidate_map: std::collections::BTreeMap<String, CandidateAggregate> =
        std::collections::BTreeMap::new();
    let mut provider_status = Vec::new();
    let mut ip_summaries = Vec::new();
    for raw in &ips {
        ctx.ensure_active()?;
        let ip = match canonical_ip(raw) {
            Ok(ip) => ip,
            Err(err) => {
                outcome.error(format!("{raw}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if let Err(err) = ctx.authorize_ip(ip) {
            provider_status.push(json!({
                "ip": ip.to_string(), "status": "skipped", "reason": err.to_string()
            }));
            outcome.skipped();
            continue;
        }
        let mut summary = IpSummary {
            sources: Vec::new(),
            candidates: 0,
            status: "ok".to_string(),
        };
        if use_ptr {
            summary.sources.push("ptr".to_string());
            match dns.reverse(ip).await {
                Ok(names) => {
                    let mut found = 0usize;
                    for name in names {
                        let in_scope = ctx.scope.allows_host(&name);
                        outcome.observe(
                            "dns",
                            "ptr",
                            "ip",
                            &ip.to_string(),
                            json!({"name": name}),
                            if in_scope { "allowed" } else { "denied" },
                        );
                        if let Some(normalized) = providers::normalize_candidate(&name) {
                            if candidate_map.len() >= ctx.config.max_discovery_candidates
                                && !candidate_map.contains_key(&normalized)
                            {
                                outcome.error(
                                    "discovery candidate limit reached; results are incomplete",
                                );
                                break;
                            }
                            candidate_map
                                .entry(normalized.clone())
                                .or_default()
                                .sources
                                .insert("ptr".to_string());
                            candidate_map
                                .get_mut(&normalized)
                                .expect("candidate entry")
                                .source_ips
                                .insert(ip.to_string());
                            outcome.candidate(
                                crate::domain::NewCandidate::new(&normalized, "ptr", "ptr")
                                    .with_ip(Some(ip.to_string()))
                                    .with_details(json!({"raw_name": name})),
                            );
                            found += 1;
                        } else {
                            provider_status.push(json!({
                                "provider": "ptr", "ip": ip.to_string(),
                                "status": "diagnostic",
                                "reason": "non-name PTR value was not published as a candidate",
                                "value": name
                            }));
                        }
                    }
                    summary.candidates += found;
                }
                Err(err) => {
                    summary.status = "unavailable".to_string();
                    provider_status.push(json!({
                        "provider": "ptr", "ip": ip.to_string(), "status": "unavailable",
                        "reason": format!("{err}")
                    }));
                    outcome.error(format!("PTR {ip}: {err}"));
                }
            }
        }
        for provider_name in &selected_providers {
            ctx.ensure_active()?;
            if provider_name == "censys" {
                let integration = ctx.config.censys_integration();
                if !integration.configured {
                    summary.sources.push("censys".to_string());
                    provider_status.push(json!({
                        "provider": "censys", "ip": ip.to_string(),
                        "status": "skipped", "mode": integration.mode.as_str(),
                        "reason": integration.reason
                    }));
                    if integration.mode == crate::config::CensysMode::Incomplete {
                        outcome.error("Censys configuration is incomplete");
                    }
                    continue;
                }
                let (url, request_headers, credential_context, api_version, namespace) =
                    match integration.mode {
                        crate::config::CensysMode::Platform => {
                            let url = push_url_segment(&integration.endpoint, &ip.to_string());
                            let pat = ctx.config.censys_pat.clone().unwrap_or_default();
                            let mut pairs = vec![
                                ("Authorization".to_string(), format!("Bearer {pat}")),
                                (
                                    "Accept".to_string(),
                                    "application/vnd.censys.api.v3.host.v1+json".to_string(),
                                ),
                            ];
                            if let Some(org) = &ctx.config.censys_organization_id {
                                pairs.push(("X-Organization-ID".to_string(), org.clone()));
                            }
                            let header_pairs: Vec<(&str, &str)> = pairs
                                .iter()
                                .map(|(key, value)| (key.as_str(), value.as_str()))
                                .collect();
                            let context = provider::credential_context(
                                "censys",
                                "platform_v3",
                                &format!(
                                    "{}|{}|{}",
                                    pat,
                                    ctx.config
                                        .censys_organization_id
                                        .clone()
                                        .unwrap_or_default(),
                                    integration.endpoint
                                ),
                            );
                            (
                                url,
                                provider::headers(&header_pairs),
                                context,
                                "v3",
                                integration.endpoint.clone(),
                            )
                        }
                        _ => {
                            let auth = format!(
                                "{}:{}",
                                ctx.config.censys_api_id.clone().unwrap_or_default(),
                                ctx.config.censys_api_secret.clone().unwrap_or_default()
                            );
                            use base64::Engine;
                            let encoded = base64::engine::general_purpose::STANDARD.encode(&auth);
                            let url = push_url_segment(&integration.endpoint, &ip.to_string());
                            let context = provider::credential_context(
                                "censys",
                                "legacy_v2",
                                &format!("{}|{}", auth, integration.endpoint),
                            );
                            (
                                url,
                                provider::headers(&[(
                                    "Authorization",
                                    &format!("Basic {encoded}"),
                                )]),
                                context,
                                "v2",
                                integration.endpoint.clone(),
                            )
                        }
                    };
                let fetch = provider::fetch_json_cached(
                    ctx,
                    "censys",
                    api_version,
                    &namespace,
                    &namespace,
                    &credential_context,
                    &ip.to_string(),
                    &url,
                    request_headers,
                    2 * 1024 * 1024,
                )
                .await;
                summary.sources.push("censys".to_string());
                handle_provider_fetch(
                    &mut outcome,
                    &mut provider_status,
                    &mut summary,
                    &mut candidate_map,
                    "censys",
                    ip,
                    integration.mode.as_str(),
                    fetch,
                    ctx.config.provider_max_candidates,
                    ctx.config.max_discovery_candidates,
                );
                continue;
            }
            if provider_name == "shodan_internetdb" {
                let base = ctx.config.shodan_internetdb_url.clone();
                let url = push_url_segment(&base, &ip.to_string());
                let context =
                    provider::credential_context("shodan_internetdb", "internetdb", "public");
                let fetch = provider::fetch_json_cached(
                    ctx,
                    "shodan_internetdb",
                    "internetdb",
                    &base,
                    &base,
                    &context,
                    &ip.to_string(),
                    &url,
                    provider::headers(&[]),
                    1024 * 1024,
                )
                .await;
                summary.sources.push("shodan_internetdb".to_string());
                handle_provider_fetch(
                    &mut outcome,
                    &mut provider_status,
                    &mut summary,
                    &mut candidate_map,
                    "shodan_internetdb",
                    ip,
                    "internetdb",
                    fetch,
                    ctx.config.provider_max_candidates,
                    ctx.config.max_discovery_candidates,
                );
                continue;
            }
            outcome.error(format!("unsupported reverse IP source: {provider_name}"));
        }
        ip_summaries.push(json!({
            "ip": ip.to_string(),
            "sources": summary.sources,
            "candidates": summary.candidates,
            "status": summary.status,
        }));
        outcome.processed();
    }

    // Verify each distinct candidate once against the current DNS scope.
    let mut checks = Vec::new();
    let mut published = 0usize;
    let mut not_permitted = 0usize;
    let mut no_addresses = 0usize;
    let mut dns_errors = 0usize;
    for (hostname, aggregate) in &candidate_map {
        ctx.ensure_active()?;
        let permission_domain = discovery::candidate_dns_domain(ctx, hostname)?;
        let source_ips: Vec<String> = aggregate.source_ips.iter().cloned().collect();
        let mut candidate = crate::domain::NewCandidate::new(hostname, "reverse.ip", "dns_check")
            .with_details(json!({"sources": aggregate.sources, "source_ips": source_ips}));
        let (status, addresses, ip_match, scope_status, reason) = if permission_domain.is_none() {
            not_permitted += 1;
            (
                "not_permitted".to_string(),
                Vec::new(),
                "unknown".to_string(),
                "denied".to_string(),
                Some("candidate is outside the current DNS scope".to_string()),
            )
        } else {
            let domain = permission_domain.as_deref().expect("permitted domain");
            match discovery::resolve_ips(&dns, ctx, domain, hostname).await {
                Ok(ips) => {
                    let addresses: Vec<String> = ips.iter().map(ToString::to_string).collect();
                    let matched = addresses.iter().any(|ip| aggregate.source_ips.contains(ip));
                    discovery::observe_host(
                        &mut outcome,
                        ctx,
                        "reverse.ip",
                        domain,
                        hostname,
                        &ips,
                    )?;
                    published += 1;
                    (
                        "verified".to_string(),
                        addresses,
                        if matched { "matched" } else { "not_matched" }.to_string(),
                        if ctx.allows_host_now(hostname) {
                            "allowed"
                        } else {
                            "denied"
                        }
                        .to_string(),
                        None,
                    )
                }
                Err(error) => {
                    ctx.ensure_active()?;
                    if crate::net::dns::is_no_records(&error) {
                        no_addresses += 1;
                        (
                            "no_addresses".to_string(),
                            Vec::new(),
                            "unknown".to_string(),
                            if ctx.allows_host_now(hostname) {
                                "allowed".to_string()
                            } else {
                                "denied".to_string()
                            },
                            Some("DNS returned no addresses".to_string()),
                        )
                    } else {
                        dns_errors += 1;
                        let message = crate::net::dns::error_message(&error);
                        outcome.error(format!("DNS {hostname}: {message}"));
                        (
                            "dns_error".to_string(),
                            Vec::new(),
                            "unknown".to_string(),
                            "denied".to_string(),
                            Some(message),
                        )
                    }
                }
            }
        };
        candidate = candidate.with_dns(&status, addresses.clone(), &ip_match, &scope_status);
        candidate.details["source_ip_matches"] = json!(source_ips.iter().map(|ip| json!({
            "ip": ip,
            "match": if status != "verified" { "unknown" } else if addresses.contains(ip) { "matched" } else { "not_matched" }
        })).collect::<Vec<_>>());
        if let Some(reason) = &reason {
            candidate = candidate.with_reason(reason.clone());
        }
        outcome.candidate(candidate);
        checks.push(json!({
            "hostname": hostname,
            "sources": aggregate.sources,
            "source_ips": source_ips,
            "dns_status": status,
            "addresses": addresses,
            "ip_match": ip_match,
            "scope_status": scope_status,
            "reason": reason,
        }));
    }
    let has_errors = outcome.counters.errors > 0 || !outcome.errors.is_empty();
    outcome.result = json!({
        "format_version": "2",
        "sources": selected_sources,
        "ips": ip_summaries,
        "counts": {
            "candidates": candidate_map.len(),
            "verified": checks.iter().filter(|check| check["dns_status"] == "verified").count(),
            "published": published,
            "not_permitted": not_permitted,
            "no_addresses": no_addresses,
            "dns_errors": dns_errors,
        },
        "checks": checks,
        "partial": has_errors,
        "providers": provider_status,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "reverse_ip",
        &format!("{}-reverse-ip.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}

#[allow(clippy::too_many_arguments)]
fn handle_provider_fetch(
    outcome: &mut TaskOutcome,
    provider_status: &mut Vec<Value>,
    summary: &mut IpSummary,
    candidate_map: &mut std::collections::BTreeMap<String, CandidateAggregate>,
    provider: &str,
    ip: std::net::IpAddr,
    api_version: &str,
    fetch: provider::ProviderFetch,
    max_candidates: usize,
    candidate_limit: usize,
) {
    let status_value = fetch.status.as_str();
    if fetch.status == provider::FetchStatus::Ok {
        if let Some(value) = fetch.value.as_ref() {
            let parsed = providers::parse(provider, value, max_candidates);
            for name in &parsed.names {
                if candidate_map.len() >= candidate_limit && !candidate_map.contains_key(name) {
                    outcome.error("discovery candidate limit reached; results are incomplete");
                    summary.status = "partial".into();
                    break;
                }
                let aggregate = candidate_map.entry(name.clone()).or_default();
                aggregate.sources.insert(provider.to_string());
                aggregate.source_ips.insert(ip.to_string());
                outcome.candidate(
                    crate::domain::NewCandidate::new(name, provider, "provider_name")
                        .with_ip(Some(ip.to_string()))
                        .with_details(json!({
                            "api_version": api_version,
                            "provider_ip": ip.to_string(),
                            "partial": parsed.partial,
                        })),
                );
            }
            summary.candidates += parsed.names.len();
            outcome.observe(
                provider,
                "provider",
                "ip",
                &ip.to_string(),
                json!({
                    "api_version": api_version,
                    "cached": fetch.cached,
                    "candidate_count": parsed.names.len(),
                    "passive": parsed.passive,
                    "partial": parsed.partial,
                }),
                "allowed",
            );
            if parsed.partial {
                summary.status = "partial".to_string();
                outcome.error(format!(
                    "{provider} {ip}: provider response was incomplete or invalid"
                ));
            }
            if !parsed.notes.is_empty() {
                provider_status.push(json!({
                    "provider": provider, "ip": ip.to_string(), "status": "partial",
                    "reason": parsed.notes.join("; "), "cached": fetch.cached
                }));
            }
        }
    }
    match fetch.status {
        provider::FetchStatus::Ok => provider_status.push(json!({
            "provider": provider, "ip": ip.to_string(), "status": "ok",
            "http_status": fetch.http_status, "cached": fetch.cached,
            "attempts": fetch.attempts
        })),
        provider::FetchStatus::Empty => provider_status.push(json!({
            "provider": provider, "ip": ip.to_string(), "status": "empty",
            "http_status": fetch.http_status, "cached": fetch.cached
        })),
        other => {
            if summary.status == "ok" {
                summary.status = other.as_str().to_string();
            }
            provider_status.push(json!({
                "provider": provider, "ip": ip.to_string(), "status": status_value,
                "http_status": fetch.http_status, "cached": fetch.cached,
                "attempts": fetch.attempts,
                "reason": fetch.error
            }));
            outcome.error(format!(
                "{provider} {ip}: {}",
                fetch.error.unwrap_or_else(|| status_value.to_string())
            ));
        }
    }
}
