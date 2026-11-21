//! Materialize server-owned Asset selections; never trust client supplied grants.
use super::{discovery, TaskContext};
use crate::db::asset_input::AssetInput;
use crate::scope::{canonical_ip, RuleKind, Scope};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const INPUT_KEY: &str = "_asset_input";

pub fn allows_selected_host(scope: &Scope, host: &str) -> bool {
    !scope.exclusion_matches_host(host)
        && scope.rules.iter().any(|rule| {
            !rule.exclusion
                && matches!(rule.kind, RuleKind::ExactDomain | RuleKind::SubdomainTree)
                && scope.allows_host(&rule.value)
                && (host == rule.value || host.ends_with(&format!(".{}", rule.value)))
        })
}

pub fn selection_scope(scope: &Scope, inputs: &[AssetInput]) -> Result<Scope> {
    let mut expanded = scope.clone();
    for input in inputs {
        if let Some(host) = &input.host {
            anyhow::ensure!(
                allows_selected_host(scope, host),
                "Asset {host} is outside Scope"
            );
            expanded.rules.push(crate::scope::ScopeRule::new(
                RuleKind::ExactDomain,
                host,
                false,
            )?);
        }
        for value in &input.ips {
            let ip = canonical_ip(value)?;
            anyhow::ensure!(
                !scope.exclusion_matches_ip(ip),
                "Asset IP {ip} is excluded by Scope"
            );
            anyhow::ensure!(
                scope.allows_ip(ip) || input.host.is_some(),
                "Asset IP {ip} is outside Scope"
            );
            expanded
                .rules
                .push(crate::scope::ScopeRule::new(RuleKind::Ip, value, false)?);
        }
    }
    Ok(expanded)
}

fn roots(input: &AssetInput) -> Vec<String> {
    let hosts = input
        .host
        .clone()
        .map(|host| vec![host])
        .unwrap_or_else(|| input.ips.clone());
    hosts
        .iter()
        .flat_map(|host| {
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.clone()
            };
            [format!("https://{host}/"), format!("http://{host}/")]
        })
        .collect()
}

pub fn materialize(task: &str, params: &Value, inputs: &[AssetInput]) -> Result<Value> {
    let mut params = params.clone();
    let object = params
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("params must be an object"))?;
    anyhow::ensure!(
        !object.contains_key(INPUT_KEY),
        "Asset input metadata is server-owned"
    );
    anyhow::ensure!(
        inputs
            .iter()
            .all(|input| input.host.is_some() || !input.ips.is_empty()),
        "Asset has no host or address"
    );
    for key in [
        "targets",
        "domains",
        "domain",
        "ips",
        "seeds",
        "base_urls",
        "asset_ids",
        "candidate_ids",
    ] {
        anyhow::ensure!(
            !object.contains_key(key),
            "with asset_ids, {key} is derived from Assets and must not be supplied in params"
        );
    }
    let values = |items: Vec<String>| json!(items.into_iter().collect::<BTreeSet<_>>());
    match task {
        "reverse.ip" | "tcp.connect" | "nmap.profile" => {
            object.insert(
                "ips".into(),
                values(inputs.iter().flat_map(|input| input.ips.clone()).collect()),
            );
        }
        "urls.passive" => {
            let domains: Vec<_> = inputs
                .iter()
                .filter_map(|input| input.host.clone())
                .collect();
            anyhow::ensure!(
                domains.len() == inputs.len(),
                "URL archive collection needs DNS Assets; select HTTP crawling for IP-only Assets"
            );
            object.insert("domains".into(), values(domains));
        }
        "http.crawl" | "paths.discover" | "web.checks" => {
            let key = match task {
                "http.crawl" => "seeds",
                "paths.discover" => "base_urls",
                _ => "targets",
            };
            object.insert(key.into(), values(inputs.iter().flat_map(roots).collect()));
        }
        "http.probe" => {
            anyhow::ensure!(
                inputs.iter().all(|input| !input.urls.is_empty()),
                "selected Assets have no URLs; run Web Crawling first"
            );
            object.insert(
                "targets".into(),
                values(inputs.iter().flat_map(|input| input.urls.clone()).collect()),
            );
            object.insert("mode".into(), json!("url"));
        }
        "assets.enrich" | "assets.classify" => {
            object.insert(
                "asset_ids".into(),
                json!(inputs.iter().map(|input| &input.id).collect::<Vec<_>>()),
            );
        }
        _ => anyhow::bail!("this task does not accept Asset selections"),
    }
    Ok(params)
}

pub async fn prepare(
    job: &crate::domain::Job,
    ctx: &TaskContext,
    metadata: &Value,
) -> Result<TaskContext> {
    let mut inputs: Vec<AssetInput> = serde_json::from_value(metadata.clone())?;
    anyhow::ensure!(!inputs.is_empty(), "Asset selection is empty");
    let current = ctx.current_scope()?;
    selection_scope(&ctx.scope.snapshot, &inputs)?;
    selection_scope(&current, &inputs)?;
    for input in &mut inputs {
        ctx.ensure_active()?;
        let asset = ctx
            .db
            .asset_detail(&ctx.project_id, &input.id)?
            .ok_or_else(|| anyhow::anyhow!("selected Asset was deleted"))?;
        anyhow::ensure!(
            asset["canonical_value"].as_str()
                == input
                    .host
                    .as_deref()
                    .or_else(|| input.ips.first().map(String::as_str)),
            "selected Asset changed"
        );
        if job.task_type != "assets.classify" {
            if let Some(host) = &input.host {
                let domain = discovery::candidate_dns_domain(ctx, host)?
                    .ok_or_else(|| anyhow::anyhow!("selected DNS Asset is no longer allowed"))?;
                let fresh = discovery::resolve_ips(&ctx.dns()?, ctx, &domain, host).await?;
                input
                    .ips
                    .retain(|value| canonical_ip(value).is_ok_and(|ip| fresh.contains(&ip)));
                if matches!(
                    job.task_type.as_str(),
                    "reverse.ip" | "tcp.connect" | "nmap.profile"
                ) {
                    anyhow::ensure!(!input.ips.is_empty(), "DNS addresses changed for {host}; run Subdomain Enumeration again before scanning IPs");
                }
            }
            for value in &input.ips {
                ctx.config.network_policy().permits(canonical_ip(value)?)?;
            }
        }
    }
    let mut ctx = ctx.clone();
    ctx.asset_inputs = Some(inputs);
    Ok(ctx)
}
