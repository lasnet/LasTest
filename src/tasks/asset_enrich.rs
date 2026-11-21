//! `assets.enrich`: combine stored DNS/HTTP/port/provider data, re-check
//! permitted candidates against the current Scope and optionally perform
//! explicitly enabled HTTP requests through the existing prober.
use crate::domain::{Job, NewCandidate, NewEnrichment};
use crate::scope::normalize_domain;
use crate::tasks::discovery;
use crate::tasks::http_tasks::{cookie_names, detect_technologies, extract_title};
use crate::tasks::{parse_params, TaskContext, TaskOutcome};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrichParams {
    #[serde(default)]
    candidate_ids: Vec<String>,
    #[serde(default)]
    asset_ids: Vec<String>,
    #[serde(default)]
    http_enrichment: bool,
    #[serde(default)]
    limit: Option<usize>,
}

fn candidate_host(candidate: &Value) -> Option<String> {
    candidate
        .get("hostname")
        .and_then(Value::as_str)
        .and_then(|host| normalize_domain(host).ok())
}

fn candidate_id(candidate: &Value) -> Option<String> {
    candidate
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn needs_check(candidate: &Value, refresh_seconds: i64) -> bool {
    let status = candidate
        .get("dns_status")
        .and_then(Value::as_str)
        .unwrap_or("not_checked");
    if matches!(status, "not_checked" | "not_permitted" | "dns_error") {
        return true;
    }
    let Some(checked) = candidate.get("last_checked_at").and_then(Value::as_str) else {
        return true;
    };
    match chrono::DateTime::parse_from_rfc3339(checked) {
        Ok(checked) => {
            let age = chrono::Utc::now().signed_duration_since(checked.with_timezone(&chrono::Utc));
            age.num_seconds() >= refresh_seconds
        }
        Err(_) => true,
    }
}

pub(crate) fn provider_passive(observations: &[Value]) -> Value {
    let mut out = json!({"ports": [], "cpes": [], "vulns": [], "services": [], "certificates": [], "reports": []});
    for observation in observations {
        if observation["kind"] != "provider" {
            continue;
        }
        let Some(passive) = observation.pointer("/data/passive") else {
            continue;
        };
        for key in ["asn", "organization", "country"] {
            if out[key].is_null() && !passive[key].is_null() {
                out[key] = passive[key].clone();
            }
        }
        for key in ["ports", "cpes", "vulns", "services", "certificates"] {
            for value in passive[key].as_array().into_iter().flatten() {
                let values = out[key].as_array_mut().expect("passive list");
                if !values.contains(value) {
                    values.push(value.clone());
                }
            }
        }
        out["reports"].as_array_mut().expect("reports").push(json!({
            "source": observation["source"], "ip": observation["asset"],
            "observed_at": observation["observed_at"], "data": passive,
        }));
    }
    out
}

fn confirmed_ports(observations: &[Value]) -> Vec<Value> {
    observations
        .iter()
        .filter(|observation| {
            matches!(observation["kind"].as_str(), Some("port" | "service"))
                && observation["data"]["state"] == "open"
        })
        .map(|observation| {
            json!({
                "ip": observation.get("asset"),
                "source": observation.get("source"),
                "observed_at": observation.get("observed_at"),
                "data": observation.get("data"),
            })
        })
        .collect()
}

fn saved_http(observations: &[Value]) -> Vec<Value> {
    observations
        .iter()
        .filter(|observation| observation.get("kind").and_then(Value::as_str) == Some("http"))
        .map(|observation| observation.get("data").cloned().unwrap_or(Value::Null))
        .collect()
}

fn address_matches(addresses: &[String], source_ips: &[String]) -> bool {
    addresses.iter().any(|address| source_ips.contains(address))
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: EnrichParams = parse_params(&job.params)?;
    let limit = params
        .limit
        .unwrap_or(200)
        .min(ctx.config.max_discovery_candidates)
        .max(1);
    let chain_mode = !ctx.input_jobs.is_empty();
    let explicit = !params.candidate_ids.is_empty() || !params.asset_ids.is_empty();
    let mut ip_assets = Vec::new();
    let mut candidates = ctx
        .db
        .candidates_by_ids(&ctx.project_id, &params.candidate_ids)?;
    anyhow::ensure!(
        candidates.len() == params.candidate_ids.iter().collect::<BTreeSet<_>>().len(),
        "candidate not found in this project"
    );
    for id in &params.asset_ids {
        let asset = ctx
            .db
            .asset_detail(&ctx.project_id, id)?
            .ok_or_else(|| anyhow::anyhow!("asset not found in this project"))?;
        if let Some(candidate) = ctx.db.candidate_for_asset(&ctx.project_id, id)? {
            candidates.push(candidate);
        } else if asset["kind"] == "host" {
            candidates.push(json!({"hostname": asset["canonical_value"], "asset_id": id,
                "dns_status": "not_checked", "addresses": [], "ip_match": "unknown"}));
        } else if asset["kind"] == "ip" {
            ip_assets.push(asset);
        }
    }
    if explicit && chain_mode {
        candidates.extend(ctx.chain_input_candidates()?);
    }
    if !explicit {
        if chain_mode {
            candidates = ctx.chain_input_candidates()?;
        } else {
            candidates = ctx.db.recent_candidates(&ctx.project_id, limit as u32)?;
            for asset in ctx.db.list_assets(&ctx.project_id, limit as u32)? {
                if asset["kind"] == "host" {
                    candidates.push(
                        json!({"hostname": asset["canonical_value"], "asset_id": asset["id"],
                        "dns_status": "not_checked", "addresses": [], "ip_match": "unknown"}),
                    );
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    candidates.retain(|candidate| candidate_host(candidate).is_some_and(|host| seen.insert(host)));
    let omitted = candidates
        .len()
        .saturating_sub(limit.saturating_sub(ip_assets.len()));
    candidates.truncate(limit.saturating_sub(ip_assets.len()));
    if candidates.is_empty() && ip_assets.is_empty() {
        let reason = if chain_mode {
            "no committed candidate input from earlier stages"
        } else {
            "no candidates are available in this project"
        };
        let mut outcome = TaskOutcome::new();
        outcome.target(0);
        outcome.result = json!({
            "format_version": "1",
            "empty": true,
            "reason": reason,
            "http_enrichment": params.http_enrichment,
            "processed": 0,
        });
        let result = outcome.result.clone();
        outcome.add_artifact(
            "asset_enrichment",
            &format!("{}-enrich.json", job.id),
            &result,
        )?;
        return Ok(outcome.finalize());
    }

    let dns = ctx.dns()?;
    let prober = if params.http_enrichment {
        Some(ctx.prober()?)
    } else {
        None
    };
    let policy = ctx.config.network_policy();
    let mut outcome = TaskOutcome::new();
    outcome.target(candidates.len() + ip_assets.len());
    if omitted > 0 {
        outcome.counters.skipped += omitted as u64;
        outcome.error(format!("{omitted} additional candidates exceed the enrichment limit; original selected Assets take priority"));
    }
    let mut summaries = Vec::new();
    let mut http_count = 0usize;
    let mut not_permitted = 0usize;
    let mut verified_count = 0usize;
    for candidate in &candidates {
        ctx.ensure_active()?;
        let Some(host) = candidate_host(candidate) else {
            outcome.skipped();
            continue;
        };
        let candidate_id = candidate_id(candidate);
        let asset_id = candidate
            .get("asset_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let existing_status = candidate
            .get("dns_status")
            .and_then(Value::as_str)
            .unwrap_or("not_checked");
        let mut dns_status = existing_status.to_string();
        let mut addresses: Vec<String> = candidate
            .get("addresses")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let source_ips: Vec<String> = if chain_mode {
            candidate["source_ips"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        } else {
            match &candidate_id {
                Some(id) => ctx.db.candidate_source_ips(&ctx.project_id, id)?,
                None => Vec::new(),
            }
        };
        let mut ip_match = candidate
            .get("ip_match")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let mut dns_records = json!({});
        for observation in ctx.observations_for_host(&host)? {
            if observation["kind"] == "dns" {
                if let (Some(kind), Some(value)) = (
                    observation["data"]["record_type"].as_str(),
                    observation["data"]["value"].as_str(),
                ) {
                    dns_records
                        .as_object_mut()
                        .expect("records")
                        .entry(kind.to_ascii_lowercase())
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("record list")
                        .push(json!(value));
                }
            }
        }
        let mut http_services = saved_http(&ctx.observations_for_host(&host)?);
        let mut checked_now = false;
        let refresh = ctx.config.discovery_refresh_seconds;
        if needs_check(candidate, refresh) {
            match discovery::candidate_dns_domain(ctx, &host)? {
                None => {
                    dns_status = "not_permitted".to_string();
                    addresses.clear();
                    ip_match = "unknown".to_string();
                    not_permitted += 1;
                    outcome.candidate(
                        NewCandidate::new(&host, "assets.enrich", "enrich_dns")
                            .with_dns("not_permitted", Vec::new(), "unknown", "denied")
                            .with_reason("DNS verification is outside the current Scope"),
                    );
                }
                Some(domain) => {
                    checked_now = true;
                    match discovery::resolve_ips(&dns, ctx, &domain, &host).await {
                        Ok(ips) => {
                            ctx.ensure_active()?;
                            addresses = ips.iter().map(ToString::to_string).collect();
                            let matched = address_matches(&addresses, &source_ips);
                            ip_match = if source_ips.is_empty() {
                                "unknown".to_string()
                            } else if matched {
                                "matched".to_string()
                            } else {
                                "not_matched".to_string()
                            };
                            dns_status = "verified".to_string();
                            verified_count += 1;
                            discovery::observe_host(
                                &mut outcome,
                                ctx,
                                "assets.enrich",
                                &domain,
                                &host,
                                &ips,
                            )?;
                            let scope_status = if ctx.allows_host_now(&host) {
                                "allowed"
                            } else {
                                "denied"
                            };
                            outcome.candidate(
                                NewCandidate::new(&host, "assets.enrich", "enrich_dns")
                                    .with_dns(
                                        "verified",
                                        addresses.clone(),
                                        &ip_match,
                                        scope_status,
                                    )
                                    .with_details(json!({"dns": dns_records})),
                            );
                        }
                        Err(error) => {
                            ctx.ensure_active()?;
                            if crate::net::dns::is_no_records(&error) {
                                dns_status = "no_addresses".to_string();
                                addresses.clear();
                                ip_match = "unknown".to_string();
                                outcome.candidate(
                                    NewCandidate::new(&host, "assets.enrich", "enrich_dns")
                                        .with_dns("no_addresses", Vec::new(), "unknown", "allowed")
                                        .with_reason("DNS returned no addresses"),
                                );
                            } else {
                                dns_status = "dns_error".to_string();
                                addresses.clear();
                                ip_match = "unknown".to_string();
                                let message = crate::net::dns::error_message(&error);
                                outcome.error(format!("DNS {host}: {message}"));
                                outcome.candidate(
                                    NewCandidate::new(&host, "assets.enrich", "enrich_dns")
                                        .with_dns("dns_error", Vec::new(), "unknown", "denied")
                                        .with_error(message),
                                );
                            }
                        }
                    }
                }
            }
        }
        // Supplement missing record types even when reverse.ip just verified
        // A/AAAA. Every lookup rechecks exclusions and is cancellation-aware.
        if let Some(domain) = discovery::candidate_dns_domain(ctx, &host)? {
            for (key, kind) in [
                ("cname", hickory_resolver::proto::rr::RecordType::CNAME),
                ("mx", hickory_resolver::proto::rr::RecordType::MX),
                ("ns", hickory_resolver::proto::rr::RecordType::NS),
                ("txt", hickory_resolver::proto::rr::RecordType::TXT),
            ] {
                if dns_records.get(key).is_some() {
                    continue;
                }
                match discovery::lookup_records(&dns, ctx, &domain, &host, kind).await {
                    Ok(records) => {
                        dns_records[key] =
                            json!(records.into_iter().map(|r| r.value).collect::<Vec<_>>());
                    }
                    Err(error) => {
                        ctx.ensure_active()?;
                        if !discovery::allows_dns(ctx, &domain, &host)? {
                            break;
                        }
                        if crate::net::dns::is_no_records(&error) {
                            dns_records[key] = json!([]);
                        } else {
                            outcome.error(format!(
                                "DNS {kind} {host}: {}",
                                crate::net::dns::error_message(&error)
                            ));
                        }
                    }
                }
            }
        }
        let mut http_errors = Vec::new();
        let mut http_attempted = false;
        let before_http = http_count;
        // Enabled active HTTP enrichment uses the existing prober, which checks
        // every redirect and enforces scope and metadata exclusions.
        if let Some(prober) = &prober {
            let permission_domain = discovery::candidate_dns_domain(ctx, &host)?;
            if permission_domain.is_none() {
                // DNS-only permission does not authorize HTTP.
            } else {
                let mut urls: Vec<String> = http_services
                    .iter()
                    .filter_map(|service| service["url"].as_str().map(str::to_string))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .take(16)
                    .collect();
                if urls.is_empty() {
                    urls = vec![format!("https://{host}/"), format!("http://{host}/")];
                }
                for url in urls {
                    ctx.ensure_active()?;
                    let Ok(parsed) = crate::scope::parse_target_url(&url) else {
                        continue;
                    };
                    if !ctx.authorize_url_now(&parsed) {
                        continue;
                    }
                    http_attempted = true;
                    match prober
                        .get_with_authorizer(parsed.as_str(), &policy, |candidate| {
                            ctx.authorize_url_now(candidate)
                        })
                        .await
                    {
                        Ok(fetch) => {
                            let technologies = detect_technologies(&fetch);
                            let final_host = crate::scope::parse_target_url(&fetch.final_url)
                                .ok()
                                .and_then(|url| url.host_str().map(str::to_string))
                                .unwrap_or_else(|| host.clone());
                            // Never attribute the final service IP to the
                            // original host after a cross-host redirect.
                            if final_host == host {
                                outcome.observe(
                                    "assets.enrich",
                                    "host",
                                    "host",
                                    &host,
                                    json!({"url": fetch.final_url, "verified_ip": fetch.remote_ip.to_string()}),
                                    "allowed",
                                );
                            }
                            outcome.observe(
                                "assets.enrich",
                                "http",
                                "url",
                                &fetch.final_url,
                                json!({
                                    "requested_url": url,
                                    "url": fetch.final_url,
                                    "verified_ip": fetch.remote_ip.to_string(),
                                    "status_code": fetch.status,
                                    "title": extract_title(&fetch.body),
                                    "server": fetch.header("server").unwrap_or(""),
                                    "content_type": fetch.content_type(),
                                    "technologies": technologies,
                                    "cookie_names": cookie_names(&fetch),
                                    "redirects": fetch.redirects,
                                    "body_truncated": fetch.truncated,
                                }),
                                "allowed",
                            );
                            if final_host == host {
                                http_services.push(json!({
                                    "url": fetch.final_url,
                                    "requested_url": url,
                                    "verified_ip": fetch.remote_ip.to_string(),
                                    "status_code": fetch.status,
                                    "title": extract_title(&fetch.body),
                                    "server": fetch.header("server").unwrap_or(""),
                                    "content_type": fetch.content_type(),
                                    "technologies": technologies,
                                    "redirects": fetch.redirects,
                                }));
                            }
                            http_count += 1;
                            break;
                        }
                        Err(error) => {
                            ctx.ensure_active()?;
                            http_errors.push(json!({"url": url, "reason": error.to_string()}));
                        }
                    }
                }
            }
        }
        if http_attempted && before_http == http_count {
            outcome.error(format!("HTTP enrichment failed for {host}"));
        }
        let mut observations = ctx.observations_for_host(&host)?;
        // Only current DNS addresses may contribute current port/provider
        // information; original discovery IPs remain provenance, not links.
        for ip in &addresses {
            observations.extend(ctx.observations_for_host(ip)?);
        }
        let passive = provider_passive(&observations);
        let mut technology_input = observations.clone();
        technology_input.extend(http_services.iter().cloned());
        let technologies = crate::tasks::tech_catalog::from_stored(&technology_input);
        let data = json!({
            "format_version": "1",
            "host": host,
            "candidate_id": candidate_id.clone(),
            "checked_at": crate::domain::now_rfc3339(),
            "checked_now": checked_now,
            "dns": {
                "status": dns_status,
                "addresses": addresses,
                "ip_match": ip_match,
                "records": dns_records,
                "scope_status": if ctx.allows_host_now(&host) { "allowed" } else { "denied" },
            },
            "http": http_services,
            "http_errors": http_errors,
            "technologies": technologies,
            "ports": {
                "confirmed": confirmed_ports(&observations),
                "passive_reported": passive.get("ports").cloned().unwrap_or_else(|| json!([])),
            },
            "network": {
                "asn": passive.get("asn").cloned().unwrap_or(Value::Null),
                "organization": passive.get("organization").cloned().unwrap_or(Value::Null),
                "country": passive.get("country").cloned().unwrap_or(Value::Null),
            },
            "sources": observations
                .iter()
                .filter_map(|observation| observation.get("source").and_then(Value::as_str))
                .collect::<BTreeSet<_>>(),
            "observation_ids": observations
                .iter()
                .filter_map(|observation| observation.get("id").and_then(Value::as_str))
                .collect::<BTreeSet<_>>(),
        });
        outcome.enrichment(NewEnrichment {
            host: host.clone(),
            candidate_id,
            asset_id,
            data: data.clone(),
        });
        summaries.push(json!({
            "host": host,
            "dns_status": dns_status,
            "ip_match": ip_match,
            "http_enriched": before_http < http_count,
        }));
        outcome.processed();
    }
    for asset in ip_assets {
        ctx.ensure_active()?;
        let ip = asset["canonical_value"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid IP Asset"))?;
        ctx.authorize_ip(crate::scope::canonical_ip(ip)?)?;
        let observations = ctx.observations_for_host(ip)?;
        let passive = provider_passive(&observations);
        let mut http = saved_http(&observations);
        let mut errors = Vec::new();
        if let Some(prober) = &prober {
            let authority = if ip.contains(':') {
                format!("[{ip}]")
            } else {
                ip.to_string()
            };
            for scheme in ["https", "http"] {
                let url = format!("{scheme}://{authority}/");
                ctx.ensure_active()?;
                match prober
                    .get_with_authorizer(&url, &policy, |url| ctx.authorize_url_now(url))
                    .await
                {
                    Ok(fetch) => {
                        let data = json!({"url":fetch.final_url,"status_code":fetch.status,"title":extract_title(&fetch.body),"server":fetch.header("server").unwrap_or(""),"verified_ip":fetch.remote_ip.to_string(),"technologies":detect_technologies(&fetch)});
                        outcome.observe(
                            "assets.enrich",
                            "http",
                            "url",
                            &fetch.final_url,
                            data.clone(),
                            "allowed",
                        );
                        http.push(data);
                        http_count += 1;
                        break;
                    }
                    Err(error) => errors.push(json!({"url":url,"reason":error.to_string()})),
                }
            }
            if http.is_empty() {
                outcome.error(format!("HTTP enrichment failed for {ip}"));
            }
        }
        let mut tech_input = observations.clone();
        tech_input.extend(http.iter().cloned());
        let data = json!({"format_version":"1","host":ip,"checked_at":crate::domain::now_rfc3339(),
            "dns":{"status":"not_applicable","addresses":[ip],"records":{},"scope_status":"allowed"},
            "http":http,"http_errors":errors,"technologies":crate::tasks::tech_catalog::from_stored(&tech_input),
            "ports":{"confirmed":confirmed_ports(&observations),"passive_reported":passive.get("ports").cloned().unwrap_or_else(||json!([]))},
            "network":{"asn":passive.get("asn"),"organization":passive.get("organization"),"country":passive.get("country")}});
        outcome.enrichment(NewEnrichment {
            host: ip.to_string(),
            candidate_id: None,
            asset_id: asset["id"].as_str().map(str::to_string),
            data,
        });
        summaries.push(json!({"host":ip,"dns_status":"not_applicable"}));
        outcome.processed();
    }
    let has_errors = outcome.counters.errors > 0 || !outcome.errors.is_empty();
    outcome.result = json!({
        "format_version": "1",
        "http_enrichment": params.http_enrichment,
        "counters": {
            "candidates": candidates.len(),
            "verified": verified_count,
            "not_permitted": not_permitted,
            "http_responses": http_count,
        },
        "candidates": summaries,
        "partial": has_errors,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "asset_enrichment",
        &format!("{}-enrich.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}
