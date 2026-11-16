//! Idempotent import of LasTest 1.x project artifacts and archive history.
//!
//! The importer reads a consistent copy of the legacy data. It never writes to
//! the source directory and never activates imported scope or archived jobs.

use crate::config::Config;
use crate::db::import::{ImportedFinding, ImportedJob, ImportedObservation};
use crate::db::projects::ScopeRevision;
use crate::db::Db;
use crate::domain::{new_id, now_rfc3339, Project, ScopeStatus};
use crate::scope::{canonical_ip, canonical_url_key, normalize_domain, RuleKind, Scope, ScopeRule};
use anyhow::{Context, Result};
use base64::Engine;
use rusqlite::OpenFlags;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    pub projects_dir: PathBuf,
    pub database: Option<PathBuf>,
    pub logs_root: Option<PathBuf>,
    pub apply: bool,
    pub mappings: HashMap<String, String>,
    pub import_users: bool,
    pub actor: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportCounts {
    pub scope_rules: u64,
    pub subdomains: u64,
    pub dns_records: u64,
    pub http_hosts: u64,
    pub urls: u64,
    pub ports: u64,
    pub findings: u64,
    pub jobs: u64,
    pub audit: u64,
    pub artifacts: u64,
    pub logs: u64,
    pub users: u64,
}

impl ImportCounts {
    fn add(&mut self, other: &ImportCounts) {
        self.scope_rules += other.scope_rules;
        self.subdomains += other.subdomains;
        self.dns_records += other.dns_records;
        self.http_hosts += other.http_hosts;
        self.urls += other.urls;
        self.ports += other.ports;
        self.findings += other.findings;
        self.jobs += other.jobs;
        self.audit += other.audit;
        self.artifacts += other.artifacts;
        self.logs += other.logs;
        self.users += other.users;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectImportReport {
    pub source_name: String,
    pub target_name: String,
    pub status: String,
    pub planned: ImportCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<ImportCounts>,
    pub warnings: Vec<String>,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub mode: String,
    pub source_root: String,
    pub projects: Vec<ProjectImportReport>,
    pub totals: ImportCounts,
    pub warnings: Vec<String>,
    pub conflicts: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct DnsEntry {
    host: String,
    record_type: String,
    value: String,
    source: String,
}

#[derive(Debug, Clone)]
struct HttpEntry {
    url: String,
    host: String,
    status_code: Option<u64>,
    title: String,
    server: String,
    tech: Vec<String>,
    source: String,
}

#[derive(Debug, Clone)]
struct UrlEntry {
    url: String,
    source: String,
}

#[derive(Debug, Clone)]
struct PortEntry {
    ip: String,
    port: u16,
    state: String,
    service: String,
    product: String,
    version: String,
    source: String,
}

#[derive(Debug, Clone)]
struct DomainIpEntry {
    domain: String,
    ip: String,
}

#[derive(Debug, Clone)]
struct FindingEntry {
    rule_id: String,
    severity: String,
    title: String,
    asset: String,
    evidence: Value,
    source: String,
    observed_at: String,
}

#[derive(Debug, Clone)]
struct JobEntry {
    source_id: String,
    task_type: String,
    status: String,
    params: Value,
    result: Value,
    error: Option<String>,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
}

#[derive(Debug, Clone)]
struct AuditEntry {
    source_id: String,
    actor: String,
    action: String,
    entity_type: String,
    entity_id: Option<String>,
    details: Value,
    created_at: String,
}

#[derive(Debug, Clone)]
struct LegacyProject {
    source_name: String,
    path: PathBuf,
    client: String,
    description: String,
    created_at: String,
    scope: Scope,
    subdomains: Vec<(String, String)>,
    dns: Vec<DnsEntry>,
    http: Vec<HttpEntry>,
    urls: Vec<UrlEntry>,
    domain_ip: Vec<DomainIpEntry>,
    ports: Vec<PortEntry>,
    findings: Vec<FindingEntry>,
    jobs: Vec<JobEntry>,
    artifacts: Vec<PathBuf>,
    warnings: Vec<String>,
}

pub async fn run_import(config: &Config, options: &ImportOptions) -> Result<ImportReport> {
    let projects_dir = &options.projects_dir;
    if !projects_dir.is_dir() {
        anyhow::bail!(
            "legacy projects directory does not exist: {}",
            projects_dir.display()
        );
    }
    let mut report = ImportReport {
        mode: if options.apply { "apply" } else { "dry-run" }.to_string(),
        source_root: projects_dir.display().to_string(),
        projects: Vec::new(),
        totals: ImportCounts::default(),
        warnings: Vec::new(),
        conflicts: Vec::new(),
        errors: Vec::new(),
    };
    let legacy_projects = load_projects(projects_dir, &mut report.warnings)?;
    let legacy_jobs = if let Some(database) = &options.database {
        jobs_by_project(database).unwrap_or_default()
    } else {
        HashMap::new()
    };
    let legacy_logs = match (&options.database, &options.logs_root) {
        (Some(database), Some(logs_root)) => {
            logs_by_project(database, logs_root).unwrap_or_default()
        }
        _ => HashMap::new(),
    };
    if legacy_projects.is_empty() {
        report
            .warnings
            .push("no legacy projects with config.yaml were found".to_string());
    }
    let existing = if options.apply {
        None
    } else {
        Some(read_existing_target(&config.database_path())?)
    };
    let db = if options.apply {
        Some(Db::new(config.database_path())?)
    } else {
        None
    };
    let mut first_project_id: Option<String> = None;
    for legacy in legacy_projects {
        let target_name = options
            .mappings
            .get(&legacy.source_name)
            .cloned()
            .unwrap_or_else(|| legacy.source_name.clone());
        let mut planned = planned_counts(&legacy);
        planned.jobs = legacy_jobs.get(&legacy.source_name).copied().unwrap_or(0);
        planned.logs = legacy_logs.get(&legacy.source_name).copied().unwrap_or(0);
        let mut project_report = ProjectImportReport {
            source_name: legacy.source_name.clone(),
            target_name: target_name.clone(),
            status: "new".to_string(),
            planned,
            imported: None,
            warnings: legacy.warnings.clone(),
            conflicts: Vec::new(),
        };
        report.totals.add(&project_report.planned);
        if let Some(existing) = &existing {
            if existing.projects.contains(&target_name) {
                project_report.status = "conflict".to_string();
                let message = format!(
                    "target project '{}' already exists; pass --map {}={} to import explicitly",
                    target_name, legacy.source_name, target_name
                );
                project_report.conflicts.push(message.clone());
                report.conflicts.push(message);
            }
        }
        if options.apply {
            let db = db.as_ref().expect("database is initialized for apply");
            if db
                .project_by_source_id(&legacy.source_name)
                .map_err(anyhow::Error::msg)?
                .is_none()
                && db
                    .project_by_name(&target_name)
                    .map_err(anyhow::Error::msg)?
                    .is_some()
                && !options.mappings.contains_key(&legacy.source_name)
            {
                project_report.status = "conflict".to_string();
                let message = format!(
                    "target project '{}' already exists; pass --map {}={} to import explicitly",
                    target_name, legacy.source_name, target_name
                );
                project_report.conflicts.push(message.clone());
                report.conflicts.push(message);
            }
        }
        if options.apply && project_report.status != "conflict" {
            let db = db.as_ref().expect("database is initialized for apply");
            match apply_project(
                db,
                config,
                &legacy,
                &target_name,
                options,
                &mut project_report,
            )
            .await
            {
                Ok(project_id) => {
                    if first_project_id.is_none() {
                        first_project_id = Some(project_id);
                    }
                }
                Err(err) => {
                    let message = format!("{}: {err:#}", legacy.source_name);
                    project_report.status = "error".to_string();
                    project_report.conflicts.push(message.clone());
                    report.errors.push(message);
                }
            }
        }
        report.projects.push(project_report);
    }
    if options.apply {
        let db = db.as_ref().expect("database is initialized for apply");
        if let Some(project_id) = &first_project_id {
            import_history(db, config, options, project_id, &mut report)?;
        } else if options.import_users {
            let users = import_users(db, options)?;
            report.totals.users += users;
            for project in &mut report.projects {
                project
                    .imported
                    .get_or_insert_with(ImportCounts::default)
                    .users = users;
            }
        }
        db.create_import_run(
            &report.source_root,
            "apply",
            &serde_json::to_value(&report.totals)?,
            &serde_json::to_value(&report)?,
        )?;
        db.audit(
            &options.actor,
            "import.legacy",
            "import",
            None,
            &json!({"projects": report.projects.len(), "totals": report.totals}),
        )?;
    } else {
        // Dry run statistics remain exactly the planned source counts.
        report.totals.audit = audit_count(options).unwrap_or(0);
        report.totals.jobs = legacy_job_count(options).unwrap_or(0);
    }
    Ok(report)
}

fn planned_counts(legacy: &LegacyProject) -> ImportCounts {
    ImportCounts {
        scope_rules: legacy.scope.rules.len() as u64,
        subdomains: legacy.subdomains.len() as u64,
        dns_records: legacy.dns.len() as u64,
        http_hosts: legacy.http.len() as u64,
        urls: legacy.urls.len() as u64,
        ports: legacy.ports.len() as u64,
        findings: legacy.findings.len() as u64,
        jobs: legacy.jobs.len() as u64,
        audit: 0,
        artifacts: legacy.artifacts.len() as u64,
        logs: 0,
        users: 0,
    }
}

fn load_projects(root: &Path, warnings: &mut Vec<String>) -> Result<Vec<LegacyProject>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_symlink() || !path.is_dir() {
            continue;
        }
        if path.join("config.yaml").is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.len() > 500 {
        anyhow::bail!("legacy source contains more than 500 projects");
    }
    let mut projects = Vec::new();
    for path in paths {
        match load_project(&path, warnings) {
            Ok(project) => projects.push(project),
            Err(err) => warnings.push(format!("{}: {err:#}", path.display())),
        }
    }
    Ok(projects)
}

fn load_project(path: &Path, _warnings: &mut Vec<String>) -> Result<LegacyProject> {
    let mut local_warnings = Vec::new();
    let config_path = path.join("config.yaml");
    let config_text = safe_read_to_string(&config_path, path, 4 * 1024 * 1024)?;
    let config: serde_yaml::Value = serde_yaml::from_str(&config_text)
        .with_context(|| format!("invalid legacy config {}", config_path.display()))?;
    let project_section = yaml_section(&config, "project");
    let scope_section = yaml_section(&config, "scope");
    let source_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("legacy project directory has no name")?
        .to_string();
    let client = yaml_string(project_section, "client");
    let description = yaml_string(project_section, "description");
    let created_at = yaml_string(project_section, "created_at");
    let mut rules = Vec::new();
    for (key, exclusion) in [("domains", false), ("ips", false), ("exclusions", true)] {
        let Some(values) = yaml_list(scope_section, key) else {
            continue;
        };
        for value in values {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let rule = if let Ok(ip) = canonical_ip(value) {
                ScopeRule::new(RuleKind::Ip, &ip.to_string(), exclusion)
            } else if value.contains('/') && value.parse::<ipnet::IpNet>().is_ok() {
                ScopeRule::new(RuleKind::Cidr, value, exclusion)
            } else if let Some(base) = value.strip_prefix("*.") {
                ScopeRule::new(RuleKind::SubdomainTree, base, exclusion)
            } else {
                ScopeRule::new(RuleKind::ExactDomain, value, exclusion)
            };
            match rule {
                Ok(mut rule) => {
                    rule.verified = false;
                    rules.push(rule);
                }
                Err(err) => local_warnings.push(format!("scope rule '{value}' was skipped: {err}")),
            }
        }
    }
    let scope = Scope::new(rules)?;

    let mut subdomains = Vec::new();
    let mut seen_subdomains = HashSet::new();
    let sub_path = path
        .join("recon")
        .join("subdomains")
        .join("subdomains.json");
    if let Some(value) = read_json_optional(&sub_path, path, 8 * 1024 * 1024, &mut local_warnings) {
        let sources = value.get("sources").and_then(Value::as_object);
        let mut source_for_name: HashMap<String, String> = HashMap::new();
        if let Some(sources) = sources {
            for (source, names) in sources {
                if let Some(names) = names.as_array() {
                    for name in names {
                        if let Some(name) = name.as_str() {
                            source_for_name
                                .entry(name.trim().to_ascii_lowercase())
                                .or_insert_with(|| source.clone());
                        }
                    }
                }
            }
        }
        if let Some(names) = value.get("all").and_then(Value::as_array) {
            for name in names {
                if let Some(name) = name.as_str() {
                    let Ok(name) = normalize_domain(name) else {
                        continue;
                    };
                    if seen_subdomains.insert(name.clone()) {
                        let source = source_for_name
                            .get(&name)
                            .cloned()
                            .unwrap_or_else(|| "legacy.subfinder".to_string());
                        subdomains.push((name, source));
                    }
                }
            }
        } else {
            local_warnings.push("subdomains.json has no 'all' list".to_string());
        }
    }

    let mut dns = Vec::new();
    let dns_path = path
        .join("recon")
        .join("dns_records")
        .join("dns_records.json");
    if let Some(value) = read_json_optional(&dns_path, path, 16 * 1024 * 1024, &mut local_warnings)
    {
        if let Some(hosts) = value.get("hosts").and_then(Value::as_array) {
            for host in hosts {
                let Some(name) = host.get("host").and_then(Value::as_str) else {
                    continue;
                };
                let Some(records) = host.get("records").and_then(Value::as_object) else {
                    continue;
                };
                for (record_type, values) in records {
                    if let Some(values) = values.as_array() {
                        for record in values {
                            if let Some(record) = record.as_str() {
                                dns.push(DnsEntry {
                                    host: name.to_string(),
                                    record_type: record_type.to_string(),
                                    value: record.to_string(),
                                    source: "legacy.dns-records".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let mut http = Vec::new();
    let http_path = path.join("recon").join("httpx").join("alive_hosts.json");
    if let Some(value) = read_json_optional(&http_path, path, 16 * 1024 * 1024, &mut local_warnings)
    {
        if let Some(hosts) = value.get("hosts").and_then(Value::as_array) {
            for host in hosts {
                let url = host
                    .get("url")
                    .or_else(|| host.get("input"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if url.is_empty() {
                    continue;
                }
                http.push(HttpEntry {
                    host: host
                        .get("host")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    url,
                    status_code: host
                        .get("status_code")
                        .or_else(|| host.get("status-code"))
                        .and_then(Value::as_u64),
                    title: host
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    server: host
                        .get("webserver")
                        .or_else(|| host.get("server"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    tech: host
                        .get("tech")
                        .or_else(|| host.get("technologies"))
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default(),
                    source: "legacy.httpx".to_string(),
                });
            }
        }
    }
    if http.is_empty() {
        for key in ["root_alive_hosts", "alive_hosts"] {
            let path_keys: &[&str] = if key == "root_alive_hosts" {
                &["recon", "httpx", "root_alive_hosts"]
            } else {
                &["recon", "alive_hosts"]
            };
            if let Some(values) = yaml_nested_list(&config, path_keys) {
                for url in values {
                    if url.starts_with("http://") || url.starts_with("https://") {
                        http.push(HttpEntry {
                            url,
                            host: String::new(),
                            status_code: None,
                            title: String::new(),
                            server: String::new(),
                            tech: Vec::new(),
                            source: "legacy.config-httpx".to_string(),
                        });
                    }
                }
            }
        }
        for relative in [
            Path::new("recon/httpx/alive_hosts.txt"),
            Path::new("recon/httpx/urls/alive_urls.txt"),
            Path::new("recon/httpx/root/alive_hosts.txt"),
        ] {
            if let Ok(text) = safe_read_to_string(&path.join(relative), path, 8 * 1024 * 1024) {
                for line in text.lines() {
                    let line = line.trim();
                    if line.starts_with("http://") || line.starts_with("https://") {
                        http.push(HttpEntry {
                            url: line.to_string(),
                            host: String::new(),
                            status_code: None,
                            title: String::new(),
                            server: String::new(),
                            tech: Vec::new(),
                            source: "legacy.httpx-url-mode".to_string(),
                        });
                    }
                }
            }
        }
    }

    let mut urls = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut add_url = |url: &str, source: &str| {
        let url = url.trim();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return;
        }
        let key = canonical_url_key(url).unwrap_or_else(|_| url.to_string());
        if seen_urls.insert(key) {
            urls.push(UrlEntry {
                url: url.to_string(),
                source: source.to_string(),
            });
        }
    };
    let passive_path = path.join("recon").join("urls").join("passive_urls.json");
    if let Some(value) =
        read_json_optional(&passive_path, path, 32 * 1024 * 1024, &mut local_warnings)
    {
        if let Some(items) = value.get("urls").and_then(Value::as_array) {
            for item in items {
                let source = item
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("legacy.url-discovery");
                if let Some(url) = item.get("url").and_then(Value::as_str) {
                    add_url(url, &format!("legacy.{source}"));
                }
            }
        }
    }
    let all_urls = path.join("recon").join("urls").join("all_urls.txt");
    if let Ok(text) = safe_read_to_string(&all_urls, path, 32 * 1024 * 1024) {
        for line in text.lines() {
            add_url(line, "legacy.urls");
        }
    }
    let sources_dir = path.join("recon").join("urls").join("sources");
    if sources_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&sources_dir) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry
                    .file_type()
                    .map(|kind| kind.is_symlink())
                    .unwrap_or(true)
                {
                    continue;
                }
                if entry_path.extension().and_then(|value| value.to_str()) != Some("txt") {
                    continue;
                }
                let source = entry_path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("urls");
                if let Ok(text) = safe_read_to_string(&entry_path, path, 16 * 1024 * 1024) {
                    for line in text.lines() {
                        add_url(line, &format!("legacy.{source}"));
                    }
                }
            }
        }
    }

    let mut domain_ip = Vec::new();
    let mut ports = Vec::new();
    let nmap_dir = path.join("recon").join("nmap");
    let mut artifact_paths = vec![config_path.clone()];
    for candidate in [
        sub_path,
        dns_path,
        http_path,
        passive_path,
        all_urls,
        path.join("web").join("nuclei").join("findings.json"),
    ] {
        if candidate.is_file() {
            artifact_paths.push(candidate);
        }
    }
    if nmap_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&nmap_dir) {
            let mut nmap_files: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension().and_then(|value| value.to_str()) == Some("json")
                        || path.extension().and_then(|value| value.to_str()) == Some("txt")
                })
                .collect();
            nmap_files.sort();
            nmap_files.truncate(80);
            for nmap_path in nmap_files {
                if nmap_path.extension().and_then(|value| value.to_str()) == Some("txt") {
                    artifact_paths.push(nmap_path);
                    continue;
                }
                if let Some(value) =
                    read_json_optional(&nmap_path, path, 32 * 1024 * 1024, &mut local_warnings)
                {
                    extract_domain_ip(&value, &mut domain_ip);
                    extract_ports(&value, &mut ports, "ip");
                    artifact_paths.push(nmap_path);
                }
            }
        }
    }
    let domain_map_path = nmap_dir.join("domain_ip_map.json");
    if let Some(value) = read_json_optional(
        &domain_map_path,
        path,
        16 * 1024 * 1024,
        &mut local_warnings,
    ) {
        extract_domain_ip(&value, &mut domain_ip);
        if !artifact_paths.iter().any(|path| path == &domain_map_path) {
            artifact_paths.push(domain_map_path);
        }
    }
    dedup_domain_ip(&mut domain_ip);
    dedup_ports(&mut ports);

    let mut seen_http = HashSet::new();
    http.retain(|entry| {
        let key = canonical_url_key(&entry.url).unwrap_or_else(|_| entry.url.clone());
        seen_http.insert(key)
    });

    let mut findings = Vec::new();
    let findings_path = path.join("web").join("nuclei").join("findings.json");
    if let Some(value) =
        read_json_optional(&findings_path, path, 32 * 1024 * 1024, &mut local_warnings)
    {
        let generated = value
            .get("generated_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let generated = if generated.is_empty() {
            now_rfc3339()
        } else {
            generated
        };
        if let Some(items) = value.get("findings").and_then(Value::as_array) {
            for item in items {
                let template = item
                    .get("template_id")
                    .and_then(Value::as_str)
                    .unwrap_or("legacy.nuclei");
                let severity = item
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_ascii_lowercase();
                let severity =
                    if ["critical", "high", "medium", "low", "info"].contains(&severity.as_str()) {
                        severity
                    } else {
                        "unknown".to_string()
                    };
                let asset = item
                    .get("matched_at")
                    .or_else(|| item.get("host"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if asset.is_empty() {
                    local_warnings.push("a Nuclei finding without host was skipped".to_string());
                    continue;
                }
                findings.push(FindingEntry {
                    rule_id: format!("nuclei.legacy.{template}"),
                    severity,
                    title: item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(template)
                        .to_string(),
                    asset,
                    evidence: item.clone(),
                    source: "nuclei.legacy".to_string(),
                    observed_at: generated.clone(),
                });
            }
        }
    }

    let jobs = Vec::new();
    let mut seen_artifacts = HashSet::new();
    artifact_paths.retain(|path| seen_artifacts.insert(path.clone()));
    Ok(LegacyProject {
        source_name,
        path: path.to_path_buf(),
        client,
        description,
        created_at,
        scope,
        subdomains,
        dns,
        http,
        urls,
        domain_ip,
        ports,
        findings,
        jobs,
        artifacts: artifact_paths,
        warnings: local_warnings,
    })
}

fn extract_domain_ip(value: &Value, out: &mut Vec<DomainIpEntry>) {
    if let Some(map) = value.get("domains").and_then(Value::as_object) {
        for (domain, ips) in map {
            if let Some(ips) = ips.as_array() {
                for ip in ips {
                    if let Some(ip) = ip.as_str() {
                        if canonical_ip(ip).is_ok() {
                            out.push(DomainIpEntry {
                                domain: domain.clone(),
                                ip: ip.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn extract_ports(value: &Value, out: &mut Vec<PortEntry>, current_ip: &str) {
    match value {
        Value::Object(map) => {
            let mut ip = current_ip.to_string();
            for key in ["ip", "address", "addr"] {
                if let Some(value) = map.get(key).and_then(Value::as_str) {
                    if canonical_ip(value).is_ok() {
                        ip = value.to_string();
                    }
                }
            }
            let port = map
                .get("port")
                .and_then(Value::as_u64)
                .or_else(|| {
                    map.get("portid")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse().ok())
                })
                .filter(|port| *port > 0 && *port <= 65535);
            if let Some(port) = port {
                if canonical_ip(&ip).is_ok() {
                    out.push(PortEntry {
                        ip: ip.clone(),
                        port: port as u16,
                        state: map
                            .get("state")
                            .and_then(|value| {
                                value.as_str().map(str::to_string).or_else(|| {
                                    value
                                        .get("state")
                                        .and_then(Value::as_str)
                                        .map(str::to_string)
                                })
                            })
                            .unwrap_or_else(|| "open".to_string()),
                        service: map
                            .get("service")
                            .and_then(|value| value.get("name").and_then(Value::as_str))
                            .unwrap_or("")
                            .to_string(),
                        product: map
                            .get("service")
                            .and_then(|value| value.get("product").and_then(Value::as_str))
                            .unwrap_or("")
                            .to_string(),
                        version: map
                            .get("service")
                            .and_then(|value| value.get("version").and_then(Value::as_str))
                            .unwrap_or("")
                            .to_string(),
                        source: "nmap.legacy".to_string(),
                    });
                }
            }
            for child in map.values() {
                extract_ports(child, out, &ip);
            }
        }
        Value::Array(items) => {
            for item in items {
                extract_ports(item, out, current_ip);
            }
        }
        _ => {}
    }
}

fn dedup_domain_ip(items: &mut Vec<DomainIpEntry>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert((item.domain.clone(), item.ip.clone())));
}

fn dedup_ports(items: &mut Vec<PortEntry>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert((item.ip.clone(), item.port, item.state.clone())));
}

fn load_audit(database: &Path) -> Result<Vec<AuditEntry>> {
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare(
        "SELECT id, COALESCE(actor_username, ''), action, resource_type,
                resource_id, details_json, created_at FROM audit_events ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AuditEntry {
            source_id: row.get::<_, i64>(0)?.to_string(),
            actor: row.get(1)?,
            action: row.get(2)?,
            entity_type: row.get(3)?,
            entity_id: row.get(4)?,
            details: sanitize_import_details(&crate::db::json_or_empty(
                row.get::<_, Option<String>>(5)?.unwrap_or_default(),
            )),
            created_at: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn audit_count(options: &ImportOptions) -> Result<u64> {
    let Some(database) = &options.database else {
        return Ok(0);
    };
    if !database.is_file() {
        return Ok(0);
    }
    Ok(load_audit(database)?.len() as u64)
}

fn logs_by_project(database: &Path, logs_root: &Path) -> Result<HashMap<String, u64>> {
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut job_project = HashMap::new();
    let mut stmt = conn.prepare("SELECT id, project_name FROM jobs")?;
    for row in stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (id, project) = row?;
        job_project.insert(id, project);
    }
    let jobs_dir = logs_root.join("jobs");
    if !jobs_dir.is_dir() {
        return Ok(HashMap::new());
    }
    let mut counts = HashMap::new();
    for (index, entry) in std::fs::read_dir(&jobs_dir)?.flatten().enumerate() {
        if index >= 500 {
            break;
        }
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("log") {
            continue;
        }
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let Some(job_id) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if let Some(project) = job_project.get(job_id) {
            *counts.entry(project.clone()).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

fn jobs_by_project(database: &Path) -> Result<HashMap<String, u64>> {
    if !database.is_file() {
        return Ok(HashMap::new());
    }
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut map = HashMap::new();
    let mut stmt =
        match conn.prepare("SELECT project_name, COUNT(*) FROM jobs GROUP BY project_name") {
            Ok(stmt) => stmt,
            Err(_) => return Ok(map),
        };
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;
    for row in rows {
        let (name, count) = row?;
        map.insert(name, count);
    }
    Ok(map)
}

fn legacy_job_count(options: &ImportOptions) -> Result<u64> {
    let Some(database) = &options.database else {
        return Ok(0);
    };
    if !database.is_file() {
        return Ok(0);
    }
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count = conn
        .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0);
    Ok(count as u64)
}

async fn apply_project(
    db: &Db,
    config: &Config,
    legacy: &LegacyProject,
    target_name: &str,
    options: &ImportOptions,
    report: &mut ProjectImportReport,
) -> Result<String> {
    let existing_by_source = db.project_by_source_id(&legacy.source_name)?;
    let project_id;
    let scope_revision: ScopeRevision;
    if let Some(project) = existing_by_source {
        project_id = project.id.clone();
        report.status = "resumed".to_string();
        scope_revision = db
            .current_scope(&project_id)?
            .context("target project has no scope revision")?;
    } else if let Some(project) = db.project_by_name(target_name)? {
        if !options.mappings.contains_key(&legacy.source_name) {
            report.status = "conflict".to_string();
            anyhow::bail!("target project '{target_name}' already exists; use --map");
        }
        project_id = project.id.clone();
        report.status = "mapped".to_string();
        scope_revision = db
            .current_scope(&project_id)?
            .context("target project has no scope revision")?;
    } else {
        let project = create_imported_project(db, legacy, target_name, &options.actor)?;
        project_id = project.id;
        scope_revision = db
            .current_scope(&project_id)?
            .context("imported project has no scope revision")?;
        if !legacy.scope.rules.is_empty() {
            let revision = db.create_scope_revision(
                &project_id,
                scope_revision.version + 1,
                &legacy.scope,
                ScopeStatus::PendingReview,
                "imported from LasTest 1.x; review before running scans",
                &options.actor,
            )?;
            db.audit(
                &options.actor,
                "scope.import",
                "project",
                Some(&project_id),
                &json!({"version": revision.version, "status": "pending_review", "rules": legacy.scope.rules.len()}),
            )?;
            // Use the newly created pending revision for job/observation context.
            return import_project_data(
                db,
                config,
                legacy,
                &project_id,
                &revision,
                options,
                report,
                target_name,
            )
            .await;
        }
    }
    import_project_data(
        db,
        config,
        legacy,
        &project_id,
        &scope_revision,
        options,
        report,
        target_name,
    )
    .await
}

fn create_imported_project(
    db: &Db,
    legacy: &LegacyProject,
    target_name: &str,
    actor: &str,
) -> Result<Project> {
    let project = db.create_project(
        target_name,
        &legacy.client,
        &legacy.description,
        Some("lastest-1.x"),
        Some(&legacy.source_name),
        actor,
    )?;
    if !legacy.created_at.is_empty() {
        let conn = db.connect()?;
        let _ = conn.execute(
            "UPDATE projects SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![legacy.created_at, project.id],
        );
    }
    Ok(project)
}

#[allow(clippy::too_many_arguments)]
async fn import_project_data(
    db: &Db,
    config: &Config,
    legacy: &LegacyProject,
    project_id: &str,
    scope_revision: &ScopeRevision,
    options: &ImportOptions,
    report: &mut ProjectImportReport,
    target_name: &str,
) -> Result<String> {
    let mut imported = ImportCounts {
        scope_rules: legacy.scope.rules.len() as u64,
        ..ImportCounts::default()
    };
    let run_id = new_id("imp");
    let now = now_rfc3339();
    let summary_key = format!("legacy:summary-{}", legacy.source_name);
    let summary_job = if let Some(existing) = db.job_by_idempotency(project_id, &summary_key)? {
        existing.id
    } else {
        db.insert_import_job(
            project_id,
            &scope_revision.id,
            scope_revision.version,
            &format!("summary-{}", legacy.source_name),
            &ImportedJob {
                task_type: "import.legacy".to_string(),
                status: "succeeded".to_string(),
                params: json!({"source": legacy.path, "target": target_name}),
                result: json!({"warnings": legacy.warnings}),
                error: None,
                created_at: now.clone(),
                started_at: None,
                finished_at: Some(now.clone()),
            },
            &options.actor,
        )?
    };
    let scope = &scope_revision.scope;
    for (name, source) in &legacy.subdomains {
        if db.import_record_exists(project_id, "subdomain", name)? {
            continue;
        }
        let allowed = scope.allows_host(name);
        let observation = ImportedObservation {
            source: source.clone(),
            kind: "host".to_string(),
            asset_kind: "host".to_string(),
            asset: name.clone(),
            canonical: name.clone(),
            data: json!({"import": "1.x"}),
            scope_status: if allowed { "allowed" } else { "denied" }.to_string(),
            observed_at: now.clone(),
        };
        let target = db.insert_import_observation(project_id, Some(&summary_job), &observation)?;
        db.add_import_record(project_id, "subdomain", name, "observations", &target)?;
        imported.subdomains += 1;
    }
    for entry in &legacy.dns {
        let key = format!("{}|{}|{}", entry.host, entry.record_type, entry.value);
        if db.import_record_exists(project_id, "dns", &key)? {
            continue;
        }
        let allowed = scope.allows_host(&entry.host);
        let target = db.insert_import_observation(
            project_id,
            Some(&summary_job),
            &ImportedObservation {
                source: entry.source.clone(),
                kind: "dns".to_string(),
                asset_kind: "host".to_string(),
                asset: entry.host.clone(),
                canonical: normalize_domain(&entry.host).unwrap_or_else(|_| entry.host.clone()),
                data: json!({"record_type": entry.record_type, "value": entry.value}),
                scope_status: if allowed { "allowed" } else { "denied" }.to_string(),
                observed_at: now.clone(),
            },
        )?;
        if let Ok(ip) = canonical_ip(&entry.value) {
            let in_ip_scope = scope.allows_ip(ip);
            db.insert_import_observation(
                project_id,
                Some(&summary_job),
                &ImportedObservation {
                    source: "legacy.dns-records".to_string(),
                    kind: "ip".to_string(),
                    asset_kind: "ip".to_string(),
                    asset: ip.to_string(),
                    canonical: ip.to_string(),
                    data: json!({"host": entry.host, "record_type": entry.record_type}),
                    scope_status: if in_ip_scope { "allowed" } else { "observed" }.to_string(),
                    observed_at: now.clone(),
                },
            )?;
        }
        db.add_import_record(project_id, "dns", &key, "observations", &target)?;
        imported.dns_records += 1;
    }
    for entry in &legacy.http {
        let key = canonical_url_key(&entry.url).unwrap_or_else(|_| entry.url.clone());
        if db.import_record_exists(project_id, "http", &key)? {
            continue;
        }
        let host = if entry.host.is_empty() {
            url::Url::parse(&entry.url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .unwrap_or_default()
        } else {
            entry.host.clone()
        };
        let allowed = scope.allows_host(&host);
        let target = db.insert_import_observation(
            project_id,
            Some(&summary_job),
            &ImportedObservation {
                source: entry.source.clone(),
                kind: "http".to_string(),
                asset_kind: "url".to_string(),
                asset: entry.url.clone(),
                canonical: key.clone(),
                data: json!({
                    "url": entry.url,
                    "host": host,
                    "status_code": entry.status_code,
                    "title": entry.title,
                    "server": entry.server,
                    "tech": entry.tech,
                    "imported": true
                }),
                scope_status: if allowed { "allowed" } else { "denied" }.to_string(),
                observed_at: now.clone(),
            },
        )?;
        db.add_import_record(project_id, "http", &key, "observations", &target)?;
        imported.http_hosts += 1;
    }
    for entry in &legacy.urls {
        let key = canonical_url_key(&entry.url).unwrap_or_else(|_| entry.url.clone());
        if db.import_record_exists(project_id, "url", &key)? {
            continue;
        }
        let host = url::Url::parse(&entry.url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .unwrap_or_default();
        let allowed = scope.allows_host(&host);
        let target = db.insert_import_observation(
            project_id,
            Some(&summary_job),
            &ImportedObservation {
                source: entry.source.clone(),
                kind: "url".to_string(),
                asset_kind: "url".to_string(),
                asset: entry.url.clone(),
                canonical: key.clone(),
                data: json!({"import": "1.x"}),
                scope_status: if allowed { "allowed" } else { "denied" }.to_string(),
                observed_at: now.clone(),
            },
        )?;
        db.add_import_record(project_id, "url", &key, "observations", &target)?;
        imported.urls += 1;
    }
    for entry in &legacy.domain_ip {
        let key = format!("{}|{}", entry.domain, entry.ip);
        if db.import_record_exists(project_id, "domain_ip", &key)? {
            continue;
        }
        let target = db.insert_import_observation(
            project_id,
            Some(&summary_job),
            &ImportedObservation {
                source: "nmap.legacy".to_string(),
                kind: "ip".to_string(),
                asset_kind: "ip".to_string(),
                asset: entry.ip.clone(),
                canonical: entry.ip.clone(),
                data: json!({"host": entry.domain}),
                scope_status: "observed".to_string(),
                observed_at: now.clone(),
            },
        )?;
        db.add_import_record(project_id, "domain_ip", &key, "observations", &target)?;
        imported.ports += 0;
    }
    for entry in &legacy.ports {
        let key = format!("{}|{}|{}", entry.ip, entry.port, entry.state);
        if db.import_record_exists(project_id, "port", &key)? {
            continue;
        }
        let allowed = canonical_ip(&entry.ip)
            .map(|ip| scope.allows_ip(ip))
            .unwrap_or(false);
        let target = db.insert_import_observation(
            project_id,
            Some(&summary_job),
            &ImportedObservation {
                source: entry.source.clone(),
                kind: "port".to_string(),
                asset_kind: "ip".to_string(),
                asset: entry.ip.clone(),
                canonical: entry.ip.clone(),
                data: json!({
                    "port": entry.port,
                    "state": entry.state,
                    "service": entry.service,
                    "product": entry.product,
                    "version": entry.version,
                    "imported": true
                }),
                scope_status: if allowed { "allowed" } else { "observed" }.to_string(),
                observed_at: now.clone(),
            },
        )?;
        db.add_import_record(project_id, "port", &key, "observations", &target)?;
        imported.ports += 1;
    }
    for entry in &legacy.findings {
        let key = format!("{}|{}", entry.rule_id, entry.asset);
        if db.import_record_exists(project_id, "finding", &key)? {
            continue;
        }
        let target = db.insert_import_finding(
            project_id,
            Some(&summary_job),
            &ImportedFinding {
                source: entry.source.clone(),
                rule_id: entry.rule_id.clone(),
                severity: entry.severity.clone(),
                title: entry.title.clone(),
                asset: entry.asset.clone(),
                evidence: entry.evidence.clone(),
                first_seen: entry.observed_at.clone(),
                last_seen: entry.observed_at.clone(),
            },
        )?;
        db.add_import_record(project_id, "finding", &key, "findings", &target)?;
        imported.findings += 1;
    }
    for job in &legacy.jobs {
        if db.import_record_exists(project_id, "job", &job.source_id)? {
            continue;
        }
        let status = match job.status.as_str() {
            "succeeded" => "succeeded",
            "failed" => "failed",
            _ => "cancelled",
        };
        let target = db.insert_import_job(
            project_id,
            &scope_revision.id,
            scope_revision.version,
            &job.source_id,
            &ImportedJob {
                task_type: job.task_type.clone(),
                status: status.to_string(),
                params: job.params.clone(),
                result: job.result.clone(),
                error: if job.status == "queued" || job.status == "running" {
                    Some("archived: legacy job was not completed and is never executed".to_string())
                } else {
                    job.error.clone()
                },
                created_at: job.created_at.clone(),
                started_at: job.started_at.clone(),
                finished_at: job.finished_at.clone(),
            },
            &options.actor,
        )?;
        db.add_import_record(project_id, "job", &job.source_id, "jobs", &target)?;
        imported.jobs += 1;
    }
    // Preserve supported originals under the application-managed evidence tree.
    let mut artifact_count = 0u64;
    for source_path in &legacy.artifacts {
        if artifact_count >= 100 {
            report
                .warnings
                .push("artifact import stopped at the 100 file limit".to_string());
            break;
        }
        let relative = match source_path.strip_prefix(&legacy.path) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let target_rel = format!(
            "imports/{}/{}/{}",
            project_id,
            run_id,
            relative.to_string_lossy().replace('\\', "/")
        );
        match copy_evidence(
            config_limit(),
            source_path,
            &legacy.path,
            &config.evidence_dir(),
            &target_rel,
        ) {
            Ok((size, digest)) if size > 0 => {
                db.register_import_artifact(
                    project_id,
                    &target_rel,
                    "legacy_original",
                    size,
                    &digest,
                )?;
                artifact_count += 1;
            }
            Ok(_) => {}
            Err(err) => report.warnings.push(format!(
                "artifact {} was skipped: {err}",
                relative.display()
            )),
        }
    }
    imported.artifacts = artifact_count;
    let stats = serde_json::to_value(&imported)?;
    let conn = db.connect()?;
    let _ = conn.execute(
        "UPDATE jobs SET result = ?1 WHERE id = ?2",
        rusqlite::params![stats.to_string(), summary_job],
    );
    report.imported = Some(imported);
    Ok(project_id.to_string())
}

fn config_limit() -> u64 {
    64 * 1024 * 1024
}

fn copy_evidence(
    max_bytes: u64,
    source: &Path,
    root: &Path,
    evidence_dir: &Path,
    target_relative: &str,
) -> Result<(u64, String)> {
    let metadata = std::fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("not a regular file");
    }
    if metadata.len() > max_bytes {
        anyhow::bail!("file exceeds import size limit");
    }
    let canonical_root = std::fs::canonicalize(root)?;
    let canonical_source = std::fs::canonicalize(source)?;
    if !canonical_source.starts_with(&canonical_root) {
        anyhow::bail!("path escapes the legacy project directory");
    }
    let data = std::fs::read(&canonical_source)?;
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&data));
    let target = Path::new(target_relative);
    if target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("unsafe target path");
    }
    std::fs::create_dir_all(evidence_dir)?;
    let final_path = evidence_dir.join(target);
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = final_path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, &data)?;
    {
        let file = std::fs::File::open(&tmp)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)?;
    Ok((data.len() as u64, digest))
}

fn read_existing_target(path: &Path) -> Result<ExistingTarget> {
    if !path.is_file() {
        return Ok(ExistingTarget::default());
    }
    let conn = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut projects = HashSet::new();
    let mut stmt = conn.prepare("SELECT name FROM projects")?;
    for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
        projects.insert(row?);
    }
    Ok(ExistingTarget { projects })
}

#[derive(Debug, Default)]
struct ExistingTarget {
    projects: HashSet<String>,
}

fn import_history(
    db: &Db,
    config: &Config,
    options: &ImportOptions,
    project_id: &str,
    report: &mut ImportReport,
) -> Result<()> {
    let mut imported_jobs = 0u64;
    let mut imported_audit = 0u64;
    let mut imported_users = 0u64;
    let mut jobs_per_project: HashMap<String, u64> = HashMap::new();
    let Some(database) = &options.database else {
        if options.import_users {
            imported_users = import_users(db, options)?;
        }
        for project in &mut report.projects {
            let counts = project.imported.get_or_insert_with(ImportCounts::default);
            counts.users = imported_users;
        }
        report.totals.users = imported_users;
        return Ok(());
    };
    if !database.is_file() {
        report.warnings.push(format!(
            "legacy database was not found: {}",
            database.display()
        ));
        return Ok(());
    }
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = match conn.prepare(
        "SELECT id, project_name, task_type, status, params_json, result_json, error,
                created_at, started_at, finished_at FROM jobs ORDER BY created_at",
    ) {
        Ok(stmt) => stmt,
        Err(err) => {
            report
                .warnings
                .push(format!("legacy jobs were not imported: {err}"));
            return Ok(());
        }
    };
    let jobs = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                ImportedJob {
                    task_type: row.get(2)?,
                    status: row.get(3)?,
                    params: crate::db::json_or_empty(
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    ),
                    result: crate::db::json_or_empty(
                        row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    ),
                    error: row.get(6)?,
                    created_at: row.get(7)?,
                    started_at: row.get(8)?,
                    finished_at: row.get(9)?,
                },
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut job_projects: HashMap<String, String> = HashMap::new();
    for (source_job_id, project_name, _) in &jobs {
        job_projects.insert(source_job_id.clone(), project_name.clone());
    }
    let project_by_source: Vec<(String, String)> = db
        .list_projects(1000, 0)?
        .0
        .into_iter()
        .filter_map(|project| project.source_project_id.map(|source| (source, project.id)))
        .collect();
    for (source_job_id, project_name, mut job) in jobs {
        let Some((_, target_project)) = project_by_source
            .iter()
            .find(|(source, _)| source == &project_name)
        else {
            continue;
        };
        if db.import_record_exists(target_project, "job", &source_job_id)? {
            continue;
        }
        let status = match job.status.as_str() {
            "succeeded" => "succeeded",
            "failed" => "failed",
            _ => "cancelled",
        };
        job.status = status.to_string();
        if status == "cancelled" {
            job.error = Some("archived: legacy job was never executed by LasTest".to_string());
        }
        let revision = db
            .current_scope(target_project)?
            .context("target project has no scope revision")?;
        let target = db.insert_import_job(
            target_project,
            &revision.id,
            revision.version,
            &source_job_id,
            &job,
            &options.actor,
        )?;
        db.add_import_record(target_project, "job", &source_job_id, "jobs", &target)?;
        *jobs_per_project.entry(target_project.clone()).or_insert(0) += 1;
        imported_jobs += 1;
    }
    if let Ok(audit) = load_audit(database) {
        for entry in audit {
            if db.import_record_exists(project_id, "audit", &entry.source_id)? {
                continue;
            }
            db.insert_import_audit(
                &entry.actor,
                &entry.action,
                &entry.entity_type,
                entry.entity_id.as_deref(),
                &entry.details,
                &entry.created_at,
            )?;
            db.add_import_record(
                project_id,
                "audit",
                &entry.source_id,
                "audit_events",
                "imported",
            )?;
            imported_audit += 1;
        }
    } else {
        report
            .warnings
            .push("legacy audit log could not be read".to_string());
    }
    let mut imported_logs = 0u64;
    let mut logs_per_project: HashMap<String, u64> = HashMap::new();
    if let Some(logs_root) = &options.logs_root {
        logs_per_project = import_logs(
            db,
            config,
            logs_root,
            &job_projects,
            &project_by_source,
            report,
        )?;
        imported_logs = logs_per_project.values().sum();
    }
    if options.import_users {
        imported_users = import_users(db, options)?;
    }
    for project in &mut report.projects {
        let key = project.source_name.clone();
        let matching_id = project_by_source
            .iter()
            .find(|(source, _)| source == &key)
            .map(|(_, id)| id.clone());
        let counts = project.imported.get_or_insert_with(ImportCounts::default);
        counts.jobs = matching_id
            .as_ref()
            .and_then(|id| jobs_per_project.get(id).copied())
            .unwrap_or(0);
        counts.audit = imported_audit;
        counts.logs = matching_id
            .as_ref()
            .and_then(|id| logs_per_project.get(id).copied())
            .unwrap_or(0);
        counts.users = imported_users;
    }
    report.totals.jobs = imported_jobs;
    report.totals.audit = imported_audit;
    report.totals.logs = imported_logs;
    report.totals.users = imported_users;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn import_logs(
    db: &Db,
    config: &Config,
    logs_root: &Path,
    job_projects: &HashMap<String, String>,
    project_by_source: &[(String, String)],
    report: &mut ImportReport,
) -> Result<HashMap<String, u64>> {
    let root = std::fs::canonicalize(logs_root)
        .with_context(|| format!("cannot read logs root {}", logs_root.display()))?;
    let jobs_dir = root.join("jobs");
    if !jobs_dir.is_dir() {
        report
            .warnings
            .push("logs root does not contain a jobs/ directory".to_string());
        return Ok(HashMap::new());
    }
    let mut imported: HashMap<String, u64> = HashMap::new();
    for (index, entry) in std::fs::read_dir(&jobs_dir)?.enumerate() {
        let entry = entry?;
        if index >= 500 {
            report
                .warnings
                .push("log import stopped at the 500 file limit".to_string());
            break;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            report.warnings.push(format!(
                "log {} was skipped: not a regular file",
                path.display()
            ));
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("log") {
            continue;
        }
        if metadata.len() > 16 * 1024 * 1024 {
            report.warnings.push(format!(
                "log {} was skipped: exceeds the size limit",
                path.display()
            ));
            continue;
        }
        let canonical = match std::fs::canonicalize(&path) {
            Ok(value) if value.starts_with(&root) => value,
            _ => {
                report.warnings.push(format!(
                    "log {} was skipped: path escapes the logs root",
                    path.display()
                ));
                continue;
            }
        };
        let Some(job_id) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(project_name) = job_projects.get(job_id) else {
            report.warnings.push(format!(
                "log {job_id} has no matching legacy job and was skipped"
            ));
            continue;
        };
        let Some((_, target_project)) = project_by_source
            .iter()
            .find(|(source, _)| source == project_name)
        else {
            continue;
        };
        if db.import_record_exists(target_project, "log", job_id)? {
            continue;
        }
        let data = std::fs::read(&canonical)?;
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&data));
        let relative = format!(
            "imports/{}/{}/logs/{}.log",
            target_project,
            new_id("imp"),
            job_id
        );
        let target = config.evidence_dir().join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, &data)?;
        db.register_import_artifact(
            target_project,
            &relative,
            "legacy_log",
            data.len() as u64,
            &digest,
        )?;
        db.add_import_record(target_project, "log", job_id, "artifacts", &relative)?;
        *imported.entry(target_project.clone()).or_insert(0) += 1;
    }
    Ok(imported)
}

fn import_users(db: &Db, options: &ImportOptions) -> Result<u64> {
    let Some(database) = &options.database else {
        return Ok(0);
    };
    if !database.is_file() {
        return Ok(0);
    }
    let conn = rusqlite::Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt =
        conn.prepare("SELECT username, role, is_active, created_at FROM users ORDER BY username")?;
    let users = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut imported = 0u64;
    for (username, role, active, _created_at) in users {
        if db.user_by_username(&username)?.is_some() {
            continue;
        }
        let role = crate::domain::Role::parse(&role).map_err(anyhow::Error::msg)?;
        let placeholder = crate::auth::new_password_placeholder()?;
        let user = db.insert_user(&username, &placeholder, role, true, Some("lastest-1.x"))?;
        if !active {
            db.update_user(&user.id, None, Some(false), None, None)?;
        }
        db.audit(
            &options.actor,
            "user.import",
            "user",
            Some(&user.id),
            &json!({"username": username, "active": active, "sessions_imported": false}),
        )?;
        imported += 1;
    }
    Ok(imported)
}

fn sanitize_import_details(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, item) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("password")
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("authorization")
                    || lower.contains("cookie")
                    || lower.contains("jwt")
                {
                    out.insert(key.clone(), Value::String("[redacted]".to_string()));
                } else {
                    out.insert(key.clone(), sanitize_import_details(item));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(sanitize_import_details)
                .collect::<Vec<_>>(),
        ),
        other => other.clone(),
    }
}

fn yaml_section<'a>(value: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    value.get(key)
}

fn yaml_string(value: Option<&serde_yaml::Value>, key: &str) -> String {
    value
        .and_then(|value| value.get(key))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn yaml_list(value: Option<&serde_yaml::Value>, key: &str) -> Option<Vec<String>> {
    value
        .and_then(|value| value.get(key))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
}

fn yaml_nested_list(value: &serde_yaml::Value, keys: &[&str]) -> Option<Vec<String>> {
    let mut current = value;
    for key in keys {
        current = current.get(*key)?;
    }
    current.as_sequence().map(|items| {
        items
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

fn safe_read_to_string(path: &Path, root: &Path, max_bytes: usize) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("not a regular file");
    }
    if metadata.len() > max_bytes as u64 {
        anyhow::bail!("file exceeds import size limit");
    }
    let canonical_root = std::fs::canonicalize(root)?;
    let canonical = std::fs::canonicalize(path)?;
    if !canonical.starts_with(&canonical_root) {
        anyhow::bail!("path escapes the legacy project directory");
    }
    Ok(std::fs::read_to_string(canonical)?)
}

fn read_json_optional(
    path: &Path,
    root: &Path,
    max_bytes: usize,
    warnings: &mut Vec<String>,
) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    match safe_read_to_string(path, root, max_bytes) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(value) => Some(value),
            Err(err) => {
                warnings.push(format!("{}: invalid JSON: {err}", path.display()));
                None
            }
        },
        Err(err) => {
            warnings.push(format!("{}: {err:#}", path.display()));
            None
        }
    }
}
