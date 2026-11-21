//! `assets.classify`: local, versioned classification and technology routing
//! over already stored data. No DNS, HTTP or provider requests are performed.
use crate::domain::{Job, NewClassification};
use crate::tasks::tech_catalog;
use crate::tasks::{parse_params, TaskContext, TaskOutcome};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifyParams {
    #[serde(default)]
    candidate_ids: Vec<String>,
    #[serde(default)]
    asset_ids: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn candidate_host(candidate: &Value) -> Option<String> {
    candidate
        .get("hostname")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn mx_values(enrichment: Option<&Value>) -> Vec<String> {
    enrichment
        .and_then(|value| value.pointer("/data/dns/records/mx"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn ns_values(enrichment: Option<&Value>) -> Vec<String> {
    enrichment
        .and_then(|value| value.pointer("/data/dns/records/ns"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn surface_hints(
    host: &str,
    technologies: &[Value],
    mx: &[String],
    ns: &[String],
    asn_organization: Option<&str>,
) -> Vec<Value> {
    let mut hints = Vec::new();
    let tech_names: BTreeSet<String> = technologies
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if tech_names.contains("tilda") {
        hints.push(json!({
            "name": "tilda",
            "kind": "website-builder",
            "basis": "http technology signature"
        }));
    }
    if tech_names.contains("cloudflare") {
        hints.push(json!({
            "name": "cloudflare-cdn",
            "kind": "cdn",
            "basis": "HTTP Server/CF headers; this does not prove the whole domain uses Cloudflare"
        }));
    }
    if ns
        .iter()
        .any(|value| tech_catalog::host_matches_suffix(value, "ns.cloudflare.com"))
    {
        hints.push(json!({
            "name": "cloudflare-dns",
            "kind": "dns",
            "basis": "NS record; DNS delegation does not prove HTTP is served by Cloudflare"
        }));
    }
    let mail_hosts: Vec<_> = mx
        .iter()
        .filter_map(|value| value.split_whitespace().last())
        .collect();
    for (suffixes, name, basis) in [
        (
            &["google.com", "googlemail.com"][..],
            "google-workspace",
            "MX points at Google mail infrastructure",
        ),
        (
            &["mail.protection.outlook.com"][..],
            "microsoft-365",
            "MX points at Microsoft 365 mail infrastructure",
        ),
        (
            &["mx.yandex.net", "mx.yandex.ru"][..],
            "yandex-360",
            "MX points at Yandex mail infrastructure",
        ),
    ] {
        if mail_hosts.iter().any(|host| {
            suffixes
                .iter()
                .any(|suffix| tech_catalog::host_matches_suffix(host, suffix))
        }) {
            hints.push(json!({"name": name, "kind": "mail", "basis": basis}));
        }
    }
    if let Some(organization) = asn_organization {
        let lower = organization.to_ascii_lowercase();
        for marker in [
            "hosting",
            "cloud",
            "digitalocean",
            "ovh",
            "hetzner",
            "amazon",
            "aws",
            "azure",
            "google",
        ] {
            if lower.contains(marker) {
                hints.push(json!({
                    "name": "shared-hosting",
                    "kind": "hosting",
                    "basis": format!("network organization contains {marker}; an ASN is not proof of company ownership"),
                }));
                break;
            }
        }
    }
    if hints.is_empty() {
        hints.push(json!({
            "name": "unknown",
            "kind": "unknown",
            "basis": "no surface-provider signal in stored data"
        }));
    }
    let _ = host;
    hints
}

fn categories_for(
    host: &str,
    technologies: &[Value],
    http: &[Value],
    candidate: Option<&Value>,
    surface_hints: &[Value],
    mx: &[String],
) -> Vec<String> {
    let mut categories = BTreeSet::new();
    let tech_names: BTreeSet<String> = technologies
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if !http.is_empty()
        || tech_names.iter().any(|name| {
            matches!(
                name.as_str(),
                "nginx" | "apache" | "wordpress" | "jira" | "grafana" | "spring" | "php"
            )
        })
    {
        categories.insert("web".to_string());
    }
    if !mx.is_empty()
        || tech_catalog::has_token(host, "mail")
        || tech_catalog::has_token(host, "smtp")
        || tech_catalog::has_token(host, "webmail")
    {
        categories.insert("mail".to_string());
    }
    for token in ["vpn", "openvpn", "wireguard"] {
        if tech_catalog::has_token(host, token) {
            categories.insert("vpn".to_string());
        }
    }
    for token in ["api", "graphql", "rest"] {
        if tech_catalog::has_token(host, token) {
            categories.insert("api".to_string());
        }
    }
    for token in ["admin", "portal", "manage", "dashboard"] {
        if tech_catalog::has_token(host, token) {
            categories.insert("admin".to_string());
        }
    }
    for token in ["dev", "staging", "stage", "test", "qa", "uat", "beta"] {
        if tech_catalog::has_token(host, token) {
            categories.insert("dev".to_string());
        }
    }
    for token in [
        "auth", "sso", "login", "signin", "idp", "oauth", "adfs", "okta",
    ] {
        if tech_catalog::has_token(host, token) {
            categories.insert("auth".to_string());
        }
    }
    for token in ["storage", "files", "cdn", "static", "assets", "s3", "blob"] {
        if tech_catalog::has_token(host, token) {
            categories.insert("storage".to_string());
        }
    }
    let http_login = http.iter().any(|service| {
        matches!(
            service.get("status_code").and_then(Value::as_u64),
            Some(401 | 403)
        )
    });
    if http_login || categories.contains("auth") {
        categories.insert("login".to_string());
    }
    if surface_hints.iter().any(|hint| {
        !matches!(
            hint.get("name").and_then(Value::as_str),
            Some("unknown") | None
        )
    }) {
        categories.insert("provider-like".to_string());
    }
    if let Some(candidate) = candidate {
        let sources = candidate
            .get("sources")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if sources.len() >= 2 {
            categories.insert("multi-source".to_string());
        }
        if candidate.get("ip_match").and_then(Value::as_str) == Some("matched") {
            categories.insert("scope-ip-match".to_string());
        }
    }
    categories.into_iter().collect()
}

fn confidence_and_interest(
    candidate: Option<&Value>,
    technologies: &[Value],
    http: &[Value],
    categories: &[String],
    enrichment: Option<&Value>,
) -> (String, String, Vec<Value>) {
    let dns_status = candidate
        .and_then(|value| value.get("dns_status"))
        .and_then(Value::as_str)
        .or_else(|| {
            enrichment
                .and_then(|value| value.pointer("/data/dns/status"))
                .and_then(Value::as_str)
        });
    let ip_match = candidate
        .and_then(|value| value.get("ip_match"))
        .and_then(Value::as_str)
        .or_else(|| {
            enrichment
                .and_then(|value| value.pointer("/data/dns/ip_match"))
                .and_then(Value::as_str)
        });
    let source_count = candidate
        .and_then(|value| value.get("sources"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let mut reasons = Vec::new();
    let confidence = if dns_status == Some("verified")
        && ip_match == Some("matched")
        && source_count >= 2
    {
        reasons.push(json!({
            "claim": "high-confidence connection",
            "basis": "verified A/AAAA answer matches one source IP and at least two independent source labels are present"
        }));
        "high"
    } else if dns_status == Some("verified") {
        reasons.push(json!({
            "claim": "verified DNS connection",
            "basis": "the name currently resolves, but the address match or independent provenance is incomplete"
        }));
        "medium"
    } else if !technologies.is_empty() || !http.is_empty() || source_count >= 2 {
        reasons.push(json!({
            "claim": "observed but not DNS-verified",
            "basis": "provider or stored service evidence exists without a current verified relation"
        }));
        "low"
    } else {
        reasons.push(json!({
            "claim": "unknown evidence quality",
            "basis": "no DNS verification and no service evidence is stored"
        }));
        "unknown"
    };
    let interest = if dns_status == Some("verified")
        && categories
            .iter()
            .any(|category| matches!(category.as_str(), "admin" | "auth" | "login" | "dev"))
    {
        reasons.push(json!({
            "claim": "high operator interest",
            "basis": "a verified host exposes administrative, authentication or development naming"
        }));
        "high"
    } else if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "web" | "mail" | "vpn" | "api" | "storage"
        )
    }) {
        reasons.push(json!({
            "claim": "medium operator interest",
            "basis": "the stored signal indicates a common service surface"
        }));
        "medium"
    } else if dns_status.is_some() {
        reasons.push(json!({
            "claim": "low operator interest",
            "basis": "no administrative, authentication or common service category was derived"
        }));
        "low"
    } else {
        reasons.push(json!({
            "claim": "unknown operator interest",
            "basis": "insufficient stored data to prioritize this subject"
        }));
        "unknown"
    };
    (confidence.to_string(), interest.to_string(), reasons)
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: ClassifyParams = parse_params(&job.params)?;
    let limit = params
        .limit
        .unwrap_or(500)
        .min(ctx.config.max_discovery_candidates)
        .max(1);
    let chain_mode = !ctx.input_jobs.is_empty();
    let mut candidates = if !params.candidate_ids.is_empty() {
        ctx.db
            .candidates_by_ids(&ctx.project_id, &params.candidate_ids)?
    } else if chain_mode {
        ctx.chain_input_candidates()?
    } else if params.asset_ids.is_empty() {
        ctx.db.recent_candidates(&ctx.project_id, limit as u32)?
    } else {
        Vec::new()
    };
    anyhow::ensure!(
        params.candidate_ids.is_empty()
            || candidates.len() == params.candidate_ids.iter().collect::<BTreeSet<_>>().len(),
        "candidate not found in this project"
    );
    let mut assets = Vec::new();
    if !params.asset_ids.is_empty() {
        for id in &params.asset_ids {
            if let Some(candidate) = ctx.db.candidate_for_asset(&ctx.project_id, id)? {
                candidates.push(candidate);
            }
            let asset = ctx
                .db
                .asset_detail(&ctx.project_id, id)?
                .ok_or_else(|| anyhow::anyhow!("asset not found in this project"))?;
            if asset["kind"] == "host" {
                assets.push(json!({
                    "id": asset["id"],
                    "kind": asset["kind"],
                    "canonical_value": asset["canonical_value"],
                }));
            }
        }
    } else if chain_mode || !params.candidate_ids.is_empty() {
        // Only hosts derived from the selected candidate input, never the
        // whole project history.
        for candidate in &candidates {
            if let Some(host) = candidate_host(candidate) {
                if let Some(asset) = ctx.db.host_asset_by_canonical(&ctx.project_id, &host)? {
                    assets.push(asset);
                }
            }
        }
    } else {
        // A bounded standalone sample of the current project data.
        let all = ctx.db.list_assets(&ctx.project_id, limit as u32)?;
        assets.extend(
            all.into_iter()
                .filter(|asset| asset.get("kind").and_then(Value::as_str) == Some("host")),
        );
    }
    let mut seen_assets = BTreeSet::new();
    assets.retain(|asset| {
        asset
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| seen_assets.insert(id.to_string()))
    });
    let mut enrichment_by_host: BTreeMap<String, Value> = BTreeMap::new();
    if chain_mode {
        for input in &ctx.input_jobs {
            for enrichment in ctx.db.enrichments_for_job(&input.id, limit as u32)? {
                if let Some(host) = enrichment.get("host").and_then(Value::as_str) {
                    enrichment_by_host.insert(host.to_string(), enrichment);
                }
            }
        }
    } else {
        for candidate in &candidates {
            if let Some(host) = candidate_host(candidate) {
                if let Some(enrichment) = ctx.db.latest_enrichment(&ctx.project_id, &host)? {
                    enrichment_by_host.insert(host, enrichment);
                }
            }
        }
    }
    // Include enrichment for standalone existing Assets too.
    if !chain_mode {
        for asset in &assets {
            if let Some(host) = asset["canonical_value"].as_str() {
                if let Some(enrichment) = ctx.db.latest_enrichment(&ctx.project_id, host)? {
                    enrichment_by_host.insert(host.to_string(), enrichment);
                }
            }
        }
    }
    if candidates.is_empty() && assets.is_empty() {
        let reason = if chain_mode {
            "no committed candidate or enrichment input from earlier stages"
        } else {
            "no candidates or host assets are available in this project"
        };
        let mut outcome = TaskOutcome::new();
        outcome.target(0);
        outcome.result = json!({
            "format_version": "1",
            "catalog_version": tech_catalog::CATALOG_VERSION,
            "empty": true,
            "reason": reason,
            "classified": 0,
        });
        let result = outcome.result.clone();
        outcome.add_artifact(
            "asset_classification",
            &format!("{}-classify.json", job.id),
            &result,
        )?;
        return Ok(outcome.finalize());
    }

    let candidate_by_host: BTreeMap<String, Value> = candidates
        .iter()
        .filter_map(|candidate| candidate_host(candidate).map(|host| (host, candidate.clone())))
        .collect();
    let asset_by_host: BTreeMap<String, Value> = assets
        .iter()
        .filter_map(|asset| {
            asset
                .get("canonical_value")
                .and_then(Value::as_str)
                .map(|host| (host.to_string(), asset.clone()))
        })
        .collect();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    hosts.extend(candidate_by_host.keys().cloned());
    hosts.extend(asset_by_host.keys().cloned());
    let mut outcome = TaskOutcome::new();
    outcome.target(hosts.len());
    let mut summaries = Vec::new();
    for host in hosts.into_iter().take(limit) {
        ctx.ensure_active()?;
        let candidate = candidate_by_host.get(&host);
        let asset = asset_by_host.get(&host);
        let enrichment = enrichment_by_host.get(&host);
        let observations = ctx.observations_for_host(&host)?;
        let mut technology_input = observations.clone();
        if let Some(enrichment) = enrichment {
            if let Some(data) = enrichment.get("data") {
                technology_input.push(data.clone());
            }
            if let Some(http) = enrichment.pointer("/data/http").and_then(Value::as_array) {
                technology_input.extend(http.iter().cloned());
            }
        }
        let technologies = tech_catalog::from_stored(&technology_input);
        let http = enrichment
            .and_then(|value| value.pointer("/data/http"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| {
                observations
                    .iter()
                    .filter(|observation| {
                        observation.get("kind").and_then(Value::as_str) == Some("http")
                    })
                    .filter_map(|observation| observation.get("data").cloned())
                    .collect()
            });
        let mx = mx_values(enrichment);
        let ns = ns_values(enrichment);
        let asn_organization = enrichment
            .and_then(|value| value.pointer("/data/network/organization"))
            .and_then(Value::as_str);
        let hints = surface_hints(&host, &technologies, &mx, &ns, asn_organization);
        let categories = categories_for(&host, &technologies, &http, candidate, &hints, &mx);
        let groups = tech_catalog::groups_for(&technologies);
        let (confidence, interest, mut reasons) =
            confidence_and_interest(candidate, &technologies, &http, &categories, enrichment);
        reasons.push(json!({
            "claim": "technology routing",
            "basis": format!("groups: {}", groups.join(", "))
        }));
        let data = json!({
            "catalog_version": tech_catalog::CATALOG_VERSION,
            "host": host,
            "groups": groups,
            "categories": categories,
            "technologies": technologies,
            "surface_hints": hints,
            "confidence": confidence,
            "interest": interest,
            "reasons": reasons,
            "evidence": {
                "http_services": http.len(),
                "mx_records": mx,
                "ns_records": ns,
                "observation_ids": observations
                    .iter()
                    .filter_map(|observation| observation.get("id").and_then(Value::as_str))
                    .collect::<BTreeSet<_>>(),
            },
            "classified_at": crate::domain::now_rfc3339(),
        });
        if let Some(candidate) = candidate {
            if let Some(id) = candidate.get("id").and_then(Value::as_str) {
                outcome.classification(NewClassification {
                    subject_type: "candidate".to_string(),
                    subject_id: id.to_string(),
                    host: Some(host.clone()),
                    data: data.clone(),
                });
            }
        }
        if let Some(asset) = asset {
            if let Some(id) = asset.get("id").and_then(Value::as_str) {
                outcome.classification(NewClassification {
                    subject_type: "asset".to_string(),
                    subject_id: id.to_string(),
                    host: Some(host.clone()),
                    data: data.clone(),
                });
            }
        }
        for service in &http {
            let Some(url) = service["url"].as_str() else {
                continue;
            };
            if url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .as_deref()
                != Some(host.as_str())
            {
                continue;
            }
            let service_tech = tech_catalog::from_stored(std::slice::from_ref(service));
            outcome.classification(NewClassification {
                subject_type: "service".to_string(),
                subject_id: crate::scope::canonical_url_key(url)?,
                host: Some(host.clone()),
                data: json!({"catalog_version": tech_catalog::CATALOG_VERSION,
                    "groups": tech_catalog::groups_for(&service_tech), "technologies": service_tech,
                    "confidence": confidence, "interest": interest,
                    "evidence": {"url": url, "observed_at": service["observed_at"]}}),
            });
        }
        summaries.push(json!({
            "host": host,
            "groups": data["groups"],
            "categories": data["categories"],
            "confidence": data["confidence"],
            "interest": data["interest"],
            "surface_hints": data["surface_hints"],
        }));
        outcome.processed();
    }
    let mut group_counts = BTreeMap::new();
    for summary in &summaries {
        for group in summary["groups"].as_array().into_iter().flatten() {
            if let Some(group) = group.as_str() {
                *group_counts.entry(group.to_string()).or_insert(0u64) += 1;
            }
        }
    }
    outcome.result = json!({
        "format_version": "1",
        "catalog_version": tech_catalog::CATALOG_VERSION,
        "classified": summaries.len(),
        "group_counts": group_counts,
        "subjects": summaries,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "asset_classification",
        &format!("{}-classify.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}
