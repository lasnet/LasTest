use crate::domain::Job;
use crate::scope::{canonical_ip, normalize_domain};
use crate::tasks::{
    dedup_strings, ensure_target_limit, parse_params, provider, TaskContext, TaskOutcome,
};
use anyhow::Result;
use hickory_resolver::proto::rr::RecordType;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
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
        let mut found = 0usize;
        for record_type in &types {
            if *record_type == RecordType::PTR {
                continue;
            }
            ctx.ensure_active()?;
            match dns.lookup(&host, *record_type).await {
                Ok(answers) => {
                    for answer in answers {
                        found += 1;
                        let scope_status = if let Ok(ip) = canonical_ip(&answer.value) {
                            if ctx.scope.allows_ip(ip) {
                                "allowed"
                            } else {
                                "observed"
                            }
                        } else {
                            "observed"
                        };
                        outcome.observe(
                            "dns",
                            "dns",
                            "host",
                            &host,
                            json!({
                                "record_type": answer.record_type,
                                "value": answer.value,
                                "target": target
                            }),
                            scope_status,
                        );
                        if let Ok(ip) = canonical_ip(&answer.value) {
                            outcome.observe(
                                "dns",
                                "ip",
                                "ip",
                                &ip.to_string(),
                                json!({"host": host, "record_type": answer.record_type}),
                                scope_status,
                            );
                        }
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
        if found == 0 {
            outcome.observe(
                "dns",
                "dns_empty",
                "host",
                &host,
                json!({"target": target}),
                "allowed",
            );
        }
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
        "targets": outcome.counters.targets,
        "records": records,
        "record_types": types.iter().map(ToString::to_string).collect::<Vec<_>>(),
    });
    let result = outcome.result.clone();
    outcome.add_artifact("dns_records", &format!("{}-dns.json", job.id), &result)?;
    Ok(outcome.finalize())
}

async fn resolve_discovery_ips(
    dns: &crate::net::DnsClient,
    ctx: &TaskContext,
    domain: &str,
    host: &str,
) -> Result<Vec<IpAddr>> {
    ctx.ensure_active()?;
    if !crate::tasks::subfinder::allows_discovery_dns(ctx, domain, host)? {
        anyhow::bail!("DNS discovery host is excluded by scope");
    }
    let lookup = dns.resolve_ips(host);
    tokio::pin!(lookup);
    loop {
        tokio::select! {
            result = &mut lookup => return result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                ctx.ensure_active()?;
                if !crate::tasks::subfinder::allows_discovery_dns(ctx, domain, host)? {
                    anyhow::bail!("DNS discovery scope changed");
                }
            }
        }
    }
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
        if !crate::tasks::subfinder::allows_discovery_dns(ctx, &domain, &probe)? {
            continue;
        }
        if let Ok(ips) = resolve_discovery_ips(&dns, ctx, &domain, &probe).await {
            for ip in &ips {
                wildcard.insert(*ip);
                wildcard_ips.push(ip.to_string());
            }
        }
    }
    wildcard_ips.sort();
    wildcard_ips.dedup();
    let mut found = Vec::new();
    let candidates = crate::tasks::dnsmap::discover(&params, &words, ctx).await?;
    let mut lookups = tokio::task::JoinSet::new();
    let mut candidates = candidates.into_iter();
    loop {
        while lookups.len() < params.concurrency {
            let Some(candidate) = candidates.next() else {
                break;
            };
            ctx.ensure_active()?;
            if !crate::tasks::subfinder::allows_discovery_dns(ctx, &domain, &candidate)? {
                continue;
            }
            let dns = dns.clone();
            let ctx = ctx.clone();
            let domain = domain.clone();
            lookups.spawn(async move {
                let result = resolve_discovery_ips(&dns, &ctx, &domain, &candidate).await;
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
        if !crate::tasks::subfinder::allows_discovery_dns(ctx, &domain, &candidate)? {
            continue;
        }
        match result {
            Ok(ips) => {
                if !wildcard.is_empty() && ips.iter().all(|ip| wildcard.contains(ip)) {
                    outcome.skipped();
                    continue;
                }
                found.push(candidate.clone());
                outcome.observe(
                    "dns.wordlist",
                    "host",
                    "host",
                    &candidate,
                    json!({"addresses": ips.iter().map(ToString::to_string).collect::<Vec<_>>()}),
                    "allowed",
                );
                for ip in ips {
                    outcome.observe(
                        "dns.wordlist",
                        "ip",
                        "ip",
                        &ip.to_string(),
                        json!({"host": candidate}),
                        if ctx.scope.allows_ip(ip) {
                            "allowed"
                        } else {
                            "observed"
                        },
                    );
                }
                outcome.processed();
            }
            Err(_) => {
                outcome.skipped();
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
    if ips.len() > 128 {
        anyhow::bail!("reverse.ip accepts at most 128 explicit addresses");
    }
    let providers: Vec<String> = if params.providers.is_empty() {
        vec!["shodan_internetdb".to_string()]
    } else {
        params.providers
    };
    let dns = ctx.dns()?;
    let client = provider::client(&ctx.config)?;
    let mut outcome = TaskOutcome::new();
    outcome.target(ips.len());
    let mut provider_status = Vec::new();
    for raw in ips {
        ctx.ensure_active()?;
        let ip = match canonical_ip(&raw) {
            Ok(ip) => ip,
            Err(err) => {
                outcome.error(format!("{raw}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if let Err(err) = ctx.authorize_ip(ip) {
            outcome.error(err.to_string());
            outcome.skipped();
            continue;
        }
        match dns.reverse(ip).await {
            Ok(names) => {
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
                }
            }
            Err(err) => outcome.error(format!("PTR {ip}: {err}")),
        }
        for provider_name in &providers {
            ctx.ensure_active()?;
            if provider_name == "censys"
                && (ctx.config.censys_api_id.is_none() || ctx.config.censys_api_secret.is_none())
            {
                provider_status.push(json!({
                    "provider": "censys",
                    "ip": ip.to_string(),
                    "status": "skipped",
                    "reason": "provider is not configured"
                }));
                continue;
            }
            if provider_name == "shodan_internetdb" {
                let url = format!(
                    "{}/{}",
                    ctx.config.shodan_internetdb_url.trim_end_matches('/'),
                    ip
                );
                match provider::get_json(&client, &url, provider::headers(&[]), 1024 * 1024).await {
                    Ok((200, Some(value), _)) => {
                        provider_status.push(json!({
                            "provider": "shodan_internetdb", "ip": ip.to_string(), "status": "ok"
                        }));
                        outcome.observe(
                            "shodan_internetdb",
                            "provider",
                            "ip",
                            &ip.to_string(),
                            value,
                            "allowed",
                        );
                    }
                    Ok((404, _, _)) => provider_status.push(json!({
                        "provider": "shodan_internetdb", "ip": ip.to_string(), "status": "empty"
                    })),
                    Ok((status, _, _)) => {
                        provider_status.push(json!({
                            "provider": "shodan_internetdb", "ip": ip.to_string(),
                            "status": "error", "http_status": status
                        }));
                        outcome.error(format!("Shodan InternetDB returned HTTP {status} for {ip}"));
                    }
                    Err(err) => {
                        provider_status.push(json!({
                            "provider": "shodan_internetdb", "ip": ip.to_string(),
                            "status": "unavailable"
                        }));
                        outcome.error(format!("Shodan InternetDB {ip}: {err}"));
                    }
                }
            } else if provider_name == "censys" {
                let auth = format!(
                    "{}:{}",
                    ctx.config.censys_api_id.clone().unwrap_or_default(),
                    ctx.config.censys_api_secret.clone().unwrap_or_default()
                );
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(auth);
                let url = format!("{}/{}", ctx.config.censys_url.trim_end_matches('/'), ip);
                match provider::get_json(
                    &client,
                    &url,
                    provider::headers(&[("Authorization", &format!("Basic {encoded}"))]),
                    2 * 1024 * 1024,
                )
                .await
                {
                    Ok((200, Some(value), _)) => {
                        provider_status.push(json!({
                            "provider": "censys", "ip": ip.to_string(), "status": "ok"
                        }));
                        outcome.observe(
                            "censys",
                            "provider",
                            "ip",
                            &ip.to_string(),
                            value,
                            "allowed",
                        );
                    }
                    Ok((404, _, _)) => provider_status.push(json!({
                        "provider": "censys", "ip": ip.to_string(), "status": "empty"
                    })),
                    Ok((status, _, _)) => {
                        provider_status.push(json!({
                            "provider": "censys", "ip": ip.to_string(),
                            "status": "error", "http_status": status
                        }));
                        outcome.error(format!("Censys returned HTTP {status} for {ip}"));
                    }
                    Err(err) => {
                        provider_status.push(json!({
                            "provider": "censys", "ip": ip.to_string(), "status": "unavailable"
                        }));
                        outcome.error(format!("Censys {ip}: {err}"));
                    }
                }
            } else {
                outcome.error(format!("unsupported reverse IP provider: {provider_name}"));
            }
        }
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
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
