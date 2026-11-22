//! Typed task registry and bounded task implementations.

pub mod asset_classify;
pub mod asset_enrich;
pub mod asset_input;
pub(crate) mod discovery;
pub mod dns_tasks;
pub mod dnsmap;
pub mod http_tasks;
pub mod network;
pub mod nmap;
pub mod passive;
pub mod provider;
pub mod providers;
pub mod registry;
pub mod subfinder;
pub mod tech_catalog;
pub mod web_checks;

use crate::config::Config;
use crate::db::jobs::{NewFinding, NewObservation};
use crate::db::Db;
use crate::domain::{new_id, Job, JobCounters, JobStatus};
use crate::scope::{canonical_ip, canonical_url_key, normalize_domain, EffectiveScope};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
#[error("task cancelled")]
pub struct TaskCancelled;

#[derive(Debug, Clone)]
pub struct TaskArtifact {
    pub kind: String,
    pub filename: String,
    pub content: Vec<u8>,
}

#[derive(Debug)]
pub struct TaskOutcome {
    pub status: JobStatus,
    pub result: Value,
    pub counters: JobCounters,
    pub error: Option<String>,
    pub observations: Vec<NewObservation>,
    pub findings: Vec<NewFinding>,
    pub artifacts: Vec<TaskArtifact>,
    pub errors: Vec<String>,
    pub candidates: Vec<crate::domain::NewCandidate>,
    pub enrichments: Vec<crate::domain::NewEnrichment>,
    pub classifications: Vec<crate::domain::NewClassification>,
}

impl TaskOutcome {
    pub fn new() -> Self {
        Self {
            status: JobStatus::Succeeded,
            result: json!({}),
            counters: JobCounters::default(),
            error: None,
            observations: Vec::new(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            errors: Vec::new(),
            candidates: Vec::new(),
            enrichments: Vec::new(),
            classifications: Vec::new(),
        }
    }

    pub fn target(&mut self, count: usize) {
        self.counters.targets = count as u64;
    }

    pub fn processed(&mut self) {
        self.counters.processed += 1;
    }

    pub fn skipped(&mut self) {
        self.counters.skipped += 1;
    }

    pub fn error(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.counters.errors += 1;
        self.errors.push(message);
    }

    pub fn observe(
        &mut self,
        source: &str,
        kind: &str,
        asset_kind: &str,
        asset: &str,
        data: Value,
        scope_status: &str,
    ) {
        let canonical = match asset_kind {
            "host" => normalize_domain(asset).unwrap_or_else(|_| asset.to_string()),
            "ip" => canonical_ip(asset)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| asset.to_string()),
            "url" => canonical_url_key(asset).unwrap_or_else(|_| asset.to_string()),
            _ => asset.to_string(),
        };
        self.observations.push(NewObservation {
            source: source.to_string(),
            kind: kind.to_string(),
            asset_kind: asset_kind.to_string(),
            asset: asset.to_string(),
            canonical_asset: canonical,
            data,
            scope_status: scope_status.to_string(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finding(
        &mut self,
        rule_id: &str,
        rule_version: u32,
        severity: &str,
        title: &str,
        asset: &str,
        evidence: Value,
        source: &str,
    ) {
        self.findings.push(NewFinding {
            rule_id: rule_id.to_string(),
            rule_version,
            severity: severity.to_string(),
            title: title.to_string(),
            asset: asset.to_string(),
            evidence,
            source: source.to_string(),
        });
    }

    pub fn add_raw_artifact(&mut self, kind: &str, filename: &str, content: Vec<u8>) {
        self.artifacts.push(TaskArtifact {
            kind: kind.to_string(),
            filename: filename.to_string(),
            content,
        });
    }

    pub fn candidate(&mut self, candidate: crate::domain::NewCandidate) {
        self.candidates.push(candidate);
    }

    pub fn enrichment(&mut self, enrichment: crate::domain::NewEnrichment) {
        self.enrichments.push(enrichment);
    }

    pub fn classification(&mut self, classification: crate::domain::NewClassification) {
        self.classifications.push(classification);
    }

    pub fn add_artifact<T: Serialize>(
        &mut self,
        kind: &str,
        filename: &str,
        value: &T,
    ) -> Result<()> {
        let mut content = serde_json::to_vec_pretty(value)?;
        content.push(b'\n');
        self.artifacts.push(TaskArtifact {
            kind: kind.to_string(),
            filename: filename.to_string(),
            content,
        });
        Ok(())
    }

    pub fn finalize(mut self) -> Self {
        if self.status == JobStatus::Succeeded
            && (!self.errors.is_empty() || self.counters.errors > 0)
        {
            self.status = JobStatus::Partial;
        }
        self.result["errors"] = json!(self.errors);
        if !self.errors.is_empty() && self.error.is_none() {
            self.error = Some(self.errors.join("; "));
        }
        self
    }

    pub fn fail(mut self, message: impl Into<String>) -> Self {
        self.status = JobStatus::Failed;
        self.error = Some(message.into());
        self.result["errors"] = json!(self.errors);
        self
    }

    pub fn partial(mut self, message: impl Into<String>) -> Self {
        self.status = JobStatus::Partial;
        self.error = Some(message.into());
        self.result["errors"] = json!(self.errors);
        self
    }
}

impl Default for TaskOutcome {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct TaskContext {
    pub db: Db,
    pub config: Config,
    pub project_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub scope: EffectiveScope,
    pub cancel: Arc<AtomicBool>,
    pub previous_job: Option<Job>,
    /// Committed input jobs for this stage. For legacy chains this is the
    /// immediate predecessor; explicit `input_refs` select several stages of
    /// the same run.
    pub input_jobs: Vec<Job>,
    /// Only server-owned, project-local selections, freshly verified by execute.
    pub asset_inputs: Option<Vec<crate::db::asset_input::AssetInput>>,
}

impl TaskContext {
    pub fn ensure_active(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(anyhow::Error::new(TaskCancelled));
        }
        Ok(())
    }

    pub fn current_scope(&self) -> Result<crate::scope::Scope> {
        Ok(self
            .db
            .current_scope(&self.project_id)?
            .context("project scope is missing")?
            .scope)
    }

    pub fn allows_host_now(&self, host: &str) -> bool {
        if let Some(inputs) = &self.asset_inputs {
            return inputs
                .iter()
                .any(|input| input.host.as_deref() == Some(host))
                && asset_input::allows_selected_host(&self.scope.snapshot, host)
                && self
                    .current_scope()
                    .is_ok_and(|scope| asset_input::allows_selected_host(&scope, host));
        }
        self.current_scope()
            .map(|current| self.scope.snapshot.allows_host(host) && current.allows_host(host))
            .unwrap_or(false)
    }

    pub fn allows_ip_now(&self, ip: std::net::IpAddr) -> bool {
        if let Some(inputs) = &self.asset_inputs {
            let Ok(current) = self.current_scope() else {
                return false;
            };
            if self.scope.snapshot.exclusion_matches_ip(ip) || current.exclusion_matches_ip(ip) {
                return false;
            }
            return inputs.iter().any(|input| {
                input
                    .ips
                    .iter()
                    .any(|value| canonical_ip(value).ok() == Some(ip))
                    && match &input.host {
                        Some(host) => {
                            asset_input::allows_selected_host(&self.scope.snapshot, host)
                                && asset_input::allows_selected_host(&current, host)
                        }
                        None => self.scope.snapshot.allows_ip(ip) && current.allows_ip(ip),
                    }
            });
        }
        self.current_scope()
            .map(|current| self.scope.snapshot.allows_ip(ip) && current.allows_ip(ip))
            .unwrap_or(false)
    }

    pub fn authorize_url_now(&self, url: &url::Url) -> bool {
        if self.ensure_active().is_err() {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        if let Ok(ip) = canonical_ip(host) {
            self.allows_ip_now(ip)
        } else {
            self.allows_host_now(host)
        }
    }

    pub fn combined_scope_now(&self) -> Result<crate::scope::Scope> {
        let current = self.current_scope()?;
        Ok(
            crate::scope::EffectiveScope::new(self.scope.snapshot.clone(), current)
                .combined_scope(),
        )
    }

    pub fn authorize_host(&self, host: &str) -> Result<()> {
        self.ensure_active()?;
        if self.allows_host_now(host) {
            Ok(())
        } else {
            anyhow::bail!("host {host} is outside the effective scope")
        }
    }

    pub fn authorize_ip(&self, ip: std::net::IpAddr) -> Result<()> {
        self.ensure_active()?;
        if !self.allows_ip_now(ip) {
            anyhow::bail!("IP {ip} is not explicitly allowed by the effective IP/CIDR scope");
        }
        self.config.network_policy().permits(ip)?;
        Ok(())
    }

    pub fn prober(&self) -> Result<crate::net::HttpProber> {
        crate::net::HttpProber::new(&self.config)
    }

    pub fn dns(&self) -> Result<crate::net::DnsClient> {
        crate::net::DnsClient::new(&self.config)
    }

    pub fn chain_input_observations(&self, kind: &str) -> Result<Vec<crate::domain::Observation>> {
        let mut items = Vec::new();
        for job in &self.input_jobs {
            let observations = self.db.observations_for_job(&job.id)?;
            items.extend(observations.into_iter().filter(|item| item.kind == kind));
        }
        Ok(items)
    }

    /// Candidates published by committed input stages of this chain run.
    pub fn chain_input_candidates(&self) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for job in self.input_jobs.iter().rev() {
            for candidate in self.db.candidates_for_job(&job.id)? {
                let host = candidate
                    .get("hostname")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if !host.is_empty() && seen.insert(host) {
                    out.push(candidate);
                }
            }
        }
        Ok(out)
    }

    /// Explicit chain inputs are immutable published snapshots, not a read of
    /// whichever neighbouring run most recently updated the project.
    pub fn observations_for_host(&self, host: &str) -> Result<Vec<Value>> {
        let mut rows = self.db.observations_for_host(&self.project_id, host)?;
        if !self.input_jobs.is_empty() {
            let selected = self.asset_inputs.as_ref().is_some_and(|inputs| {
                inputs.iter().any(|input| {
                    input.host.as_deref() == Some(host) || input.ips.iter().any(|ip| ip == host)
                })
            });
            rows.retain(|row| {
                selected
                    || row["job_id"]
                        .as_str()
                        .is_some_and(|id| self.input_jobs.iter().any(|job| job.id == id))
            });
        }
        Ok(rows)
    }
}

pub async fn execute(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    ctx.ensure_active()?;
    let mut job = job.clone();
    let prepared;
    let ctx = if let Some(metadata) = job
        .params
        .as_object_mut()
        .and_then(|params| params.remove(asset_input::INPUT_KEY))
    {
        prepared = asset_input::prepare(&job, ctx, &metadata).await?;
        if matches!(
            job.task_type.as_str(),
            "reverse.ip" | "tcp.connect" | "nmap.profile"
        ) {
            job.params["ips"] = serde_json::json!(prepared
                .asset_inputs
                .as_ref()
                .into_iter()
                .flatten()
                .flat_map(|input| input.ips.clone())
                .collect::<std::collections::BTreeSet<_>>());
        }
        &prepared
    } else {
        ctx
    };
    let job = &job;
    match job.task_type.as_str() {
        "dns.records" => dns_tasks::run_records(job, ctx).await,
        "dns.wordlist" => dns_tasks::run_wordlist(job, ctx).await,
        "reverse.ip" => dns_tasks::run_reverse_ip(job, ctx).await,
        "subdomains.discover" => passive::run_subdomains(job, ctx).await,
        "subdomains.subfinder" => subfinder::run(job, ctx).await,
        "urls.passive" => passive::run_urls_passive(job, ctx).await,
        "http.crawl" => http_tasks::run_crawl(job, ctx).await,
        "paths.discover" => http_tasks::run_paths(job, ctx).await,
        "http.probe" => http_tasks::run_probe(job, ctx).await,
        "web.checks" => web_checks::run(job, ctx).await,
        "tcp.connect" => network::run_tcp(job, ctx).await,
        "nmap.profile" => nmap::run(job, ctx).await,
        "assets.enrich" => asset_enrich::run(job, ctx).await,
        "assets.classify" => asset_classify::run(job, ctx).await,
        other => Err(anyhow::anyhow!("unsupported task type: {other}")).context("task registry"),
    }
}

pub fn parse_params<T: serde::de::DeserializeOwned>(params: &Value) -> Result<T> {
    serde_json::from_value(params.clone())
        .with_context(|| format!("invalid task parameters: {params}"))
}

pub fn params_strings(params: &Value, key: &str) -> Result<Vec<String>> {
    let Some(value) = params.get(key) else {
        return Ok(Vec::new());
    };
    let items: Vec<String> = serde_json::from_value(value.clone())
        .with_context(|| format!("parameter '{key}' must be an array of strings"))?;
    Ok(items)
}

pub fn dedup_strings(items: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        let value = item.trim();
        if !value.is_empty() && !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
    out
}

pub fn ensure_target_limit(count: usize, config: &Config) -> Result<()> {
    if count > config.max_queue_targets {
        anyhow::bail!(
            "target count {count} exceeds configured limit {}",
            config.max_queue_targets
        );
    }
    Ok(())
}

pub fn new_evidence_path(prefix: &str) -> String {
    format!("{prefix}-{}.json", new_id("art"))
}

fn ensure_keys(params: &Value, allowed: &[&str]) -> Result<()> {
    let object = params
        .as_object()
        .context("task parameters must be a JSON object")?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            anyhow::bail!("unknown task parameter: {key}");
        }
    }
    Ok(())
}

pub(crate) fn string_list(params: &Value, key: &str) -> Result<Vec<String>> {
    params_strings(params, key)
}

/// Validation performed at submission time, before a job enters the queue.
pub fn validate_submission(
    task_type: &str,
    params: &Value,
    config: &Config,
    db: &Db,
) -> Result<()> {
    match task_type {
        "subdomains.subfinder" => subfinder::validate(params, config)?,
        "subdomains.discover" => {
            ensure_keys(params, &["domains", "providers"])?;
            for provider in string_list(params, "providers")? {
                if provider != "certspotter" {
                    anyhow::bail!("unsupported CT provider: {provider}");
                }
            }
        }
        "dns.records" => {
            ensure_keys(params, &["targets", "record_types"])?;
            for record_type in string_list(params, "record_types")? {
                crate::net::dns::record_type(&record_type)?;
            }
        }
        "dns.wordlist" => {
            dnsmap::prepare(params, config, db)?;
        }
        "reverse.ip" => {
            ensure_keys(
                params,
                &["ips", "providers", "sources", "use_configured_censys"],
            )?;
            if let Some(preference) = params.get("use_configured_censys") {
                anyhow::ensure!(
                    preference.is_boolean(),
                    "use_configured_censys must be a boolean"
                );
            }
            let ips = string_list(params, "ips")?;
            if ips.is_empty() || ips.len() > 128 {
                anyhow::bail!("reverse.ip requires 1-128 explicit IP addresses");
            }
            for ip in ips {
                canonical_ip(&ip)?;
            }
            let has_providers = params.get("providers").is_some();
            let has_sources = params.get("sources").is_some();
            if has_providers && has_sources {
                anyhow::bail!("reverse.ip accepts either sources or legacy providers, not both");
            }
            if let Some(value) = params.get("sources") {
                let sources: Vec<String> = serde_json::from_value(value.clone())
                    .context("sources must be an array of strings")?;
                if dedup_strings(&sources).is_empty() {
                    anyhow::bail!("reverse.ip sources must not be empty");
                }
                for source in dedup_strings(&sources) {
                    if !matches!(source.as_str(), "ptr" | "shodan_internetdb" | "censys") {
                        anyhow::bail!("unsupported reverse IP source: {source}");
                    }
                }
            }
            for provider in string_list(params, "providers")? {
                if !matches!(provider.as_str(), "shodan_internetdb" | "censys") {
                    anyhow::bail!("unsupported reverse IP provider: {provider}");
                }
            }
        }
        "assets.enrich" => {
            ensure_keys(
                params,
                &["candidate_ids", "asset_ids", "http_enrichment", "limit"],
            )?;
            let count = string_list(params, "candidate_ids")?.len()
                + string_list(params, "asset_ids")?.len();
            if count
                > config
                    .max_discovery_candidates
                    .min(config.max_queue_targets)
            {
                anyhow::bail!("too many selected discovery targets");
            }
            if let Some(limit) = params.get("limit") {
                let limit = limit.as_u64().context("limit must be a positive integer")?;
                if limit == 0 || limit > config.max_queue_targets as u64 {
                    anyhow::bail!("limit exceeds the configured target limit");
                }
            }
            if let Some(value) = params.get("http_enrichment") {
                if value.as_bool().is_none() {
                    anyhow::bail!("http_enrichment must be a boolean");
                }
            }
        }
        "assets.classify" => {
            ensure_keys(params, &["candidate_ids", "asset_ids", "limit"])?;
            let count = string_list(params, "candidate_ids")?.len()
                + string_list(params, "asset_ids")?.len();
            if count
                > config
                    .max_discovery_candidates
                    .min(config.max_queue_targets)
            {
                anyhow::bail!("too many selected discovery targets");
            }
            if let Some(limit) = params.get("limit") {
                let limit = limit.as_u64().context("limit must be a positive integer")?;
                if limit == 0 || limit > config.max_queue_targets as u64 {
                    anyhow::bail!("limit exceeds the configured target limit");
                }
            }
        }
        "http.probe" => {
            ensure_keys(params, &["targets", "mode"])?;
            if let Some(mode) = params.get("mode").and_then(Value::as_str) {
                if !matches!(mode, "root" | "url") {
                    anyhow::bail!("http.probe mode must be root or url");
                }
            }
        }
        "urls.passive" => {
            ensure_keys(params, &["domains", "sources", "limit"])?;
            for source in string_list(params, "sources")? {
                if !matches!(source.as_str(), "wayback" | "commoncrawl") {
                    anyhow::bail!("unsupported URL source: {source}");
                }
            }
            if let Some(limit) = params.get("limit") {
                let limit = limit.as_u64().context("limit must be a positive integer")?;
                if limit == 0 || limit > config.max_queue_targets as u64 {
                    anyhow::bail!("limit exceeds the configured target limit");
                }
            }
        }
        "http.crawl" => {
            ensure_keys(params, &["seeds", "max_pages", "max_depth"])?;
            for key in ["max_pages", "max_depth"] {
                if let Some(value) = params.get(key) {
                    if value.as_u64().is_none() {
                        anyhow::bail!("{key} must be a non-negative integer");
                    }
                }
            }
        }
        "paths.discover" => {
            ensure_keys(params, &["base_urls", "words"])?;
            let words = string_list(params, "words")?;
            if words.len() > config.max_wordlist_entries {
                anyhow::bail!("path wordlist exceeds configured limit");
            }
        }
        "tcp.connect" => {
            ensure_keys(params, &["ips", "ports", "proxy_profile"])?;
            let ips = string_list(params, "ips")?;
            if ips.is_empty() || ips.len() > 256 {
                anyhow::bail!("tcp.connect requires 1-256 explicit IP addresses");
            }
            for ip in ips {
                let ip = canonical_ip(&ip)?;
                config.network_policy().permits(ip)?;
            }
            validate_ports(params)?;
            if let Some(profile) = params.get("proxy_profile").and_then(Value::as_str) {
                if !config
                    .socks5_profiles
                    .iter()
                    .any(|item| item.name == profile)
                {
                    anyhow::bail!("unknown SOCKS5 proxy profile: {profile}");
                }
            }
        }
        "nmap.profile" => {
            ensure_keys(params, &["ips", "ports"])?;
            if !registry::nmap_available(config) {
                anyhow::bail!(
                    "nmap.profile is unavailable: Nmap is not installed or not configured"
                );
            }
            let ips = string_list(params, "ips")?;
            if ips.is_empty() || ips.len() > 128 {
                anyhow::bail!("nmap.profile requires 1-128 explicit IP addresses");
            }
            for ip in ips {
                canonical_ip(&ip)?;
            }
            validate_ports(params)?;
        }
        "web.checks" => {
            ensure_keys(params, &["targets", "cookie_names"])?;
        }
        other => anyhow::bail!("unsupported task type: {other}"),
    }
    Ok(())
}

fn validate_ports(params: &Value) -> Result<()> {
    let Some(ports) = params.get("ports") else {
        return Ok(());
    };
    let ports: Vec<u16> = serde_json::from_value(ports.clone())
        .context("ports must be an array of integers between 1 and 65535")?;
    if ports.len() > 1024 || ports.contains(&0) {
        anyhow::bail!("ports must contain at most 1024 non-zero values");
    }
    Ok(())
}

/// Explicit targets must already be inside the approved scope. Empty target
/// arrays derive their work from the scope snapshot inside the task.
pub fn validate_scope_targets(
    task_type: &str,
    params: &Value,
    scope: &crate::scope::Scope,
    config: &Config,
) -> Result<()> {
    let ip_tasks = matches!(task_type, "tcp.connect" | "nmap.profile" | "reverse.ip");
    if ip_tasks {
        for raw in string_list(params, "ips")? {
            let ip = canonical_ip(&raw)?;
            if !scope.allows_ip(ip) {
                anyhow::bail!("IP {ip} is not explicitly allowed by the approved scope");
            }
            config.network_policy().permits(ip)?;
        }
        return Ok(());
    }
    if task_type == "dns.wordlist" {
        if let Some(domain) = params.get("domain").and_then(Value::as_str) {
            let domain = normalize_domain(domain)?;
            if !scope.allows_host(&domain) {
                anyhow::bail!("domain {domain} is outside the approved scope");
            }
        }
        return Ok(());
    }
    for key in ["targets", "domains", "seeds", "base_urls"] {
        for raw in string_list(params, key)? {
            if raw.contains("://") {
                let url = crate::scope::parse_target_url(&raw)?;
                let host = url.host_str().unwrap_or_default();
                if let Ok(ip) = canonical_ip(host) {
                    if !scope.allows_ip(ip) {
                        anyhow::bail!("IP {ip} is not explicitly allowed by the approved scope");
                    }
                } else if !scope.allows_host(host) {
                    anyhow::bail!("host {host} is outside the approved scope");
                }
            } else if let Ok(ip) = canonical_ip(&raw) {
                if !scope.allows_ip(ip) {
                    anyhow::bail!("IP {ip} is not explicitly allowed by the approved scope");
                }
            } else {
                let host = normalize_domain(&raw)?;
                if !scope.allows_host(&host) {
                    anyhow::bail!("host {host} is outside the approved scope");
                }
            }
        }
    }
    Ok(())
}
