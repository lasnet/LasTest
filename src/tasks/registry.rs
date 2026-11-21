use crate::config::Config;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct TaskTypeInfo {
    pub name: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub result_format_version: &'static str,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub requires_explicit_scope: &'static str,
    pub params_schema: Value,
    pub limits: Value,
    pub inputs: Vec<&'static str>,
    pub outputs: Vec<&'static str>,
}

pub const TASK_NAMES: &[&str] = &[
    "subdomains.discover",
    "subdomains.subfinder",
    "dns.records",
    "dns.wordlist",
    "reverse.ip",
    "assets.enrich",
    "assets.classify",
    "http.probe",
    "urls.passive",
    "http.crawl",
    "paths.discover",
    "tcp.connect",
    "nmap.profile",
    "web.checks",
];

pub fn is_known(name: &str) -> bool {
    TASK_NAMES.contains(&name)
}

pub fn task_types(config: &Config) -> Vec<TaskTypeInfo> {
    let nmap_available = nmap_available(config);
    let mut items = vec![
        TaskTypeInfo {
            name: "subdomains.subfinder",
            title: "Subfinder passive discovery and DNS resolution",
            category: "recon",
            result_format_version: "1",
            available: crate::tasks::subfinder::available(config),
            unavailable_reason: (!crate::tasks::subfinder::available(config)).then(|| {
                "Subfinder is not installed or LASTEST_SUBFINDER_PATH is not configured".into()
            }),
            requires_explicit_scope: "domain",
            params_schema: json!({"type":"object","properties":{
                "domains":{"type":"array","items":{"type":"string"}},
                "sources":{"type":"array","items":{"type":"string"}},
                "resolve":{"type":"boolean","deprecated":true,"description":"Legacy field; A/AAAA verification is always enabled"}
            },"additionalProperties":false}),
            limits: json!({"timeout_seconds":config.subfinder_timeout_seconds,"max_output_bytes":config.max_artifact_bytes}),
            inputs: vec!["approved DNS scope or explicit domains"],
            outputs: vec![
                "host observations",
                "DNS and IP observations",
                "subdomains artifact",
            ],
        },
        TaskTypeInfo {
            name: "subdomains.discover",
            title: "Certificate Transparency discovery and DNS resolution",
            category: "recon",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "domains": {"type": "array", "items": {"type": "string"}},
                    "providers": {"type": "array", "items": {"enum": ["certspotter"]}}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_pages_per_domain": 10, "timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["scope domains or explicit in-scope domains"],
            outputs: vec![
                "verified host and IP observations",
                "issuance and rejection artifact",
            ],
        },
        TaskTypeInfo {
            name: "dns.records",
            title: "DNS records",
            category: "recon",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "record_types": {"type": "array", "items": {"enum": ["A","AAAA","CNAME","MX","NS","TXT","PTR"]}}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_targets": config.max_queue_targets, "timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["scope domains", "chain URL/host observations"],
            outputs: vec!["DNS observations", "dns_records artifact"],
        },
        TaskTypeInfo {
            name: "dns.wordlist",
            title: "DNS wordlist search with wildcard detection (dnsmap)",
            category: "recon",
            result_format_version: "1",
            available: crate::tasks::dnsmap::available(config),
            unavailable_reason: (!crate::tasks::dnsmap::available(config))
                .then(|| "dnsmap is not installed or LASTEST_DNSMAP_PATH is not configured".into()),
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "wordlist": {"type": "string", "enum": ["default"], "default": "default"},
                    "concurrency": {"type": "integer", "enum": [4,8,16], "default": 8},
                    "words": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["domain"],
                "additionalProperties": false
            }),
            limits: json!({"timeout_seconds": config.dnsmap_timeout_seconds}),
            inputs: vec!["one in-scope domain"],
            outputs: vec!["host observations", "wildcard diagnostics"],
        },
        TaskTypeInfo {
            name: "reverse.ip",
            title: "PTR and passive reverse IP",
            category: "recon",
            result_format_version: "2",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "ip/cidr",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "sources": {
                        "type": "array",
                        "items": {"enum": ["ptr","shodan_internetdb","censys"]},
                        "description": "Select exactly the passive sources; an empty list is rejected"
                    },
                    "providers": {
                        "type": "array",
                        "items": {"enum": ["shodan_internetdb","censys"]},
                        "deprecated": true,
                        "description": "Legacy parameter; keeps PTR and defaults to Shodan when empty"
                    }
                },
                "required": ["ips"],
                "additionalProperties": false
            }),
            limits: json!({"max_ips": 128, "max_candidates": config.provider_max_candidates, "timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["explicit IP/CIDR scope"],
            outputs: vec![
                "candidates and evidence",
                "IP and PTR observations",
                "provider observations",
            ],
        },
        TaskTypeInfo {
            name: "assets.enrich",
            title: "Asset enrichment (DNS, stored HTTP, optional active HTTP)",
            category: "assets",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "candidate",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "candidate_ids": {"type": "array", "items": {"type": "string"}},
                    "asset_ids": {"type": "array", "items": {"type": "string"}},
                    "http_enrichment": {"type": "boolean", "default": false},
                    "limit": {"type": "integer", "minimum": 1, "maximum": config.max_queue_targets}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_candidates": config.max_discovery_candidates, "http_timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["project-local candidate IDs", "committed chain candidates"],
            outputs: vec!["enrichment snapshot", "DNS/HTTP observations"],
        },
        TaskTypeInfo {
            name: "assets.classify",
            title: "Asset classification and technology routing",
            category: "assets",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "candidate",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "candidate_ids": {"type": "array", "items": {"type": "string"}},
                    "asset_ids": {"type": "array", "items": {"type": "string"}},
                    "limit": {"type": "integer", "minimum": 1, "maximum": config.max_queue_targets}
                },
                "additionalProperties": false
            }),
            limits: json!({"catalog_version": crate::tasks::tech_catalog::CATALOG_VERSION, "max_candidates": config.max_discovery_candidates}),
            inputs: vec![
                "project-local candidates/assets",
                "committed chain candidates and enrichments",
            ],
            outputs: vec![
                "technology groups",
                "categories and confidence/interest with evidence",
            ],
        },
        TaskTypeInfo {
            name: "http.probe",
            title: "HTTP probe for roots and full URLs",
            category: "web",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "mode": {"enum": ["root", "url"]}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_targets": config.max_queue_targets, "max_body_bytes": config.max_body_bytes, "max_redirects": config.max_redirects}),
            inputs: vec!["scope domains", "explicit in-scope roots/URLs"],
            outputs: vec!["host/URL observations", "HTTP artifact", "technology hints"],
        },
        TaskTypeInfo {
            name: "urls.passive",
            title: "Passive URL collection (Wayback CDX and Common Crawl)",
            category: "recon",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "domains": {"type": "array", "items": {"type": "string"}},
                    "sources": {"type": "array", "items": {"enum": ["wayback","commoncrawl"]}},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 5000}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_urls": config.max_queue_targets, "timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["in-scope domains"],
            outputs: vec!["URL observations with source"],
        },
        TaskTypeInfo {
            name: "http.crawl",
            title: "Bounded HTML crawler",
            category: "web",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "seeds": {"type": "array", "items": {"type": "string"}},
                    "max_pages": {"type": "integer"},
                    "max_depth": {"type": "integer"}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_pages": config.max_crawl_pages, "max_depth": config.max_crawl_depth, "max_body_bytes": config.max_body_bytes}),
            inputs: vec!["in-scope HTTPS/HTTP URLs"],
            outputs: vec!["URL observations", "crawl diagnostics"],
        },
        TaskTypeInfo {
            name: "paths.discover",
            title: "HTTP path wordlist search with soft-404 detection",
            category: "web",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "base_urls": {"type": "array", "items": {"type": "string"}},
                    "words": {"type": "array", "items": {"type": "string"}}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_words": config.max_wordlist_entries, "max_body_bytes": config.max_body_bytes}),
            inputs: vec!["in-scope base URLs"],
            outputs: vec!["URL/HTTP observations", "soft-404 diagnostics"],
        },
        TaskTypeInfo {
            name: "tcp.connect",
            title: "Native TCP connect and optional SOCKS5",
            category: "network",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "ip/cidr",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "ports": {"type": "array", "items": {"type": "integer"}},
                    "proxy_profile": {"type": "string"}
                },
                "required": ["ips"],
                "additionalProperties": false
            }),
            limits: json!({"max_ips": 256, "max_ports": 1024, "timeout_seconds": config.http_timeout_seconds}),
            inputs: vec!["explicit IP/CIDR scope"],
            outputs: vec!["confirmed port observations", "candidate/error diagnostics"],
        },
        TaskTypeInfo {
            name: "nmap.profile",
            title: "Optional fixed unprivileged Nmap service profile",
            category: "network",
            result_format_version: "1",
            available: nmap_available,
            unavailable_reason: if nmap_available {
                None
            } else {
                Some("Nmap is not installed or nmap_path is not configured; the rest of the catalog remains available".to_string())
            },
            requires_explicit_scope: "ip/cidr",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "ports": {"type": "array", "items": {"type": "integer"}}
                },
                "required": ["ips"],
                "additionalProperties": false
            }),
            limits: json!({"max_ips": 128, "max_ports": 1024, "timeout_seconds": config.nmap_timeout_seconds, "max_output_bytes": config.nmap_max_output_bytes}),
            inputs: vec!["explicit IP/CIDR scope"],
            outputs: vec!["service observations", "Nmap XML artifact"],
        },
        TaskTypeInfo {
            name: "web.checks",
            title: "Versioned HTTP/TLS checks",
            category: "web",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}},
                    "cookie_names": {"type": "array", "items": {"type": "string"}}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_targets": config.max_queue_targets, "tls_expiry_warning_days": config.tls_expiry_warning_days}),
            inputs: vec!["in-scope HTTPS URLs/domains"],
            outputs: vec!["findings with evidence", "rule coverage report"],
        },
        TaskTypeInfo {
            name: "chain.all_in_one",
            title: "All in one preset chain",
            category: "chain",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "domain",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "domains": {"type": "array", "items": {"type": "string"}},
                    "targets": {"type": "array", "items": {"type": "string"}}
                },
                "additionalProperties": false
            }),
            limits: json!({}),
            inputs: vec!["in-scope domains/targets"],
            outputs: vec!["linked stage jobs"],
        },
        TaskTypeInfo {
            name: "chain.asset_discovery",
            title: "Asset Discovery preset chain",
            category: "chain",
            result_format_version: "1",
            available: true,
            unavailable_reason: None,
            requires_explicit_scope: "ip/cidr",
            params_schema: json!({
                "type": "object",
                "properties": {
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "sources": {"type": "array", "items": {"enum": ["ptr","shodan_internetdb","censys"]}},
                    "http_enrichment": {"type": "boolean", "default": false}
                },
                "additionalProperties": false
            }),
            limits: json!({"max_ips": 128}),
            inputs: vec!["approved explicit IP scope"],
            outputs: vec!["reverse.ip -> assets.enrich -> assets.classify"],
        },
    ];
    items.sort_by(|a, b| a.name.cmp(b.name));
    items
}

pub fn nmap_available(config: &Config) -> bool {
    let Some(path) = &config.nmap_path else {
        return false;
    };
    path.is_file()
}

pub fn chain_task_type() -> &'static str {
    "chain.all_in_one"
}
