//! Versioned technology signatures and surface classification helpers.
//!
//! Detection uses only data already returned by an HTTP probe (headers, all
//! Set-Cookie headers, a bounded body) or data already stored with an HTTP
//! observation. It never starts extra requests.
use crate::net::http::FetchResult;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const CATALOG_VERSION: i64 = 2;

#[derive(Debug, Clone)]
struct Signal {
    name: String,
    version: Option<String>,
    source: String,
    evidence: String,
}

fn push_signal(
    signals: &mut Vec<Signal>,
    name: &'static str,
    version: Option<String>,
    source: &str,
    evidence: &str,
) {
    signals.push(Signal {
        name: name.to_string(),
        version,
        source: source.to_string(),
        evidence: evidence.to_string(),
    });
}

fn cookie_markers(fetch: &FetchResult) -> Vec<String> {
    fetch
        .header_values("set-cookie")
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

/// Extract technology evidence from a live probe result.
pub fn detect(fetch: &FetchResult) -> Vec<Value> {
    let mut signals = Vec::new();
    if let Some(server) = fetch.header("server") {
        let lower = server.to_ascii_lowercase();
        for (name, marker) in [
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("cloudflare", "cloudflare"),
            ("microsoft-iis", "microsoft-iis"),
            ("caddy", "caddy"),
        ] {
            if lower.contains(marker) {
                let version = server
                    .split('/')
                    .nth(1)
                    .and_then(|value| value.split_whitespace().next())
                    .map(str::to_string);
                push_signal(
                    &mut signals,
                    name,
                    version,
                    "header:server",
                    &format!("Server header contains {marker}"),
                );
            }
        }
        if lower.contains("atlassian") {
            push_signal(
                &mut signals,
                "atlassian",
                None,
                "header:server",
                "Server header contains atlassian",
            );
            if lower.contains("jira") {
                push_signal(
                    &mut signals,
                    "jira",
                    None,
                    "header:server",
                    "Server header contains Atlassian Jira",
                );
            }
        }
    }
    if let Some(powered) = fetch.header("x-powered-by") {
        let product = powered.split('/').next().unwrap_or(powered);
        let version = powered.split('/').nth(1).map(str::to_string);
        push_signal(
            &mut signals,
            if product.eq_ignore_ascii_case("php") {
                "php"
            } else if product.eq_ignore_ascii_case("express") {
                "express"
            } else {
                "x-powered-by"
            },
            version,
            "header:x-powered-by",
            &format!("X-Powered-By is {product}"),
        );
    }
    for (header, name, marker) in [
        ("x-arequestid", "jira", "x-arequestid"),
        ("x-asessionid", "jira", "x-asessionid"),
        ("x-seraph-loginreason", "jira", "x-seraph-loginreason"),
        ("x-application-context", "spring", "x-application-context"),
        ("x-grafana-org-id", "grafana", "x-grafana-org-id"),
        ("x-tilda-server", "tilda", "x-tilda-server"),
    ] {
        if fetch.header(header).is_some() {
            push_signal(
                &mut signals,
                name,
                None,
                &format!("header:{header}"),
                &format!("{marker} header is present"),
            );
        }
    }
    let cookies = cookie_markers(fetch);
    let cookie_joined = cookies.join("; ");
    if cookie_joined.contains("phpsessid") {
        push_signal(
            &mut signals,
            "php",
            None,
            "cookie",
            "Set-Cookie contains PHPSESSID",
        );
    }
    if cookie_joined.contains("jsessionid") {
        push_signal(
            &mut signals,
            "java",
            None,
            "cookie",
            "Set-Cookie contains JSESSIONID",
        );
    }
    let jira_cookie = cookies.iter().any(|value| {
        value.contains("atlassian.xsrf.token")
            || value.contains("jira.session")
            || value.contains("seraph.")
    });
    if jira_cookie {
        push_signal(
            &mut signals,
            "jira",
            None,
            "cookie",
            "Jira-specific session/CSRF cookie is present",
        );
    }
    if cookie_joined.contains("grafana_sess") {
        push_signal(
            &mut signals,
            "grafana",
            None,
            "cookie",
            "Set-Cookie contains grafana_sess",
        );
    }
    let body_lower = fetch.body.to_ascii_lowercase();
    if body_lower.contains("wp-content/") || body_lower.contains("wp-includes/") {
        push_signal(
            &mut signals,
            "wordpress",
            None,
            "body",
            "body contains WordPress asset paths",
        );
    } else if body_lower.contains("wordpress") {
        push_signal(
            &mut signals,
            "wordpress",
            None,
            "body",
            "body contains wordpress",
        );
    }
    if body_lower.contains("_next/static") {
        push_signal(
            &mut signals,
            "next.js",
            None,
            "body",
            "body contains _next/static",
        );
    }
    if body_lower.contains("ng-version") {
        push_signal(
            &mut signals,
            "angular",
            None,
            "body",
            "body contains ng-version",
        );
    }
    if body_lower.contains("id=\"grafana-app\"")
        || body_lower.contains("grafana-app")
        || body_lower.contains("window.grafanabootdata")
    {
        push_signal(
            &mut signals,
            "grafana",
            None,
            "body",
            "body contains a Grafana application marker",
        );
    }
    if body_lower.contains("org.springframework")
        || body_lower.contains("spring-boot")
        || body_lower.contains("whitelabel error page")
    {
        push_signal(
            &mut signals,
            "spring",
            None,
            "body",
            "body contains a Spring/Spring Boot marker",
        );
    }
    if body_lower.contains("com.atlassian.jira") {
        push_signal(
            &mut signals,
            "jira",
            None,
            "body",
            "body contains a Jira application marker",
        );
    }
    merge_signals(signals)
}

/// Rebuild technologies from data stored with `http.probe` observations without
/// performing any network request.
pub fn from_stored(observations: &[Value]) -> Vec<Value> {
    let mut signals = Vec::new();
    for observation in observations {
        let data = observation.get("data").unwrap_or(observation);
        if let Some(existing) = data.get("technologies").and_then(Value::as_array) {
            for item in existing {
                let Some(name) = item.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let version = item
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let source = item
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("stored");
                if let Some(evidence) = item.get("evidence").and_then(Value::as_array) {
                    for entry in evidence {
                        signals.push(Signal {
                            name: name.to_string(),
                            version: entry
                                .get("version")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                                .or_else(|| version.clone()),
                            source: entry
                                .get("source")
                                .and_then(Value::as_str)
                                .unwrap_or(source)
                                .to_string(),
                            evidence: entry
                                .get("evidence")
                                .and_then(Value::as_str)
                                .unwrap_or("stored technology hint")
                                .to_string(),
                        });
                    }
                    if !evidence.is_empty() {
                        continue;
                    }
                }
                signals.push(Signal {
                    name: name.to_string(),
                    version,
                    source: source.to_string(),
                    evidence: item
                        .get("evidence")
                        .and_then(Value::as_str)
                        .unwrap_or("stored technology hint")
                        .to_string(),
                });
            }
        }
        if let Some(server) = data.get("server").and_then(Value::as_str) {
            if !server.is_empty() {
                let lower = server.to_ascii_lowercase();
                for (name, marker) in [
                    ("nginx", "nginx"),
                    ("apache", "apache"),
                    ("cloudflare", "cloudflare"),
                    ("microsoft-iis", "microsoft-iis"),
                    ("caddy", "caddy"),
                ] {
                    if lower.contains(marker) {
                        push_signal(
                            &mut signals,
                            name,
                            None,
                            "stored:header:server",
                            &format!("stored Server header contains {marker}"),
                        );
                    }
                }
            }
        }
        for cookie in data
            .get("cookie_names")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let lower = cookie.to_ascii_lowercase();
            if lower.contains("phpsessid") {
                push_signal(
                    &mut signals,
                    "php",
                    None,
                    "stored:cookie",
                    "stored cookie name contains PHPSESSID",
                );
            }
            if lower.contains("grafana_sess") {
                push_signal(
                    &mut signals,
                    "grafana",
                    None,
                    "stored:cookie",
                    "stored cookie name contains grafana_sess",
                );
            }
            if lower.contains("jira") || lower.contains("seraph") {
                push_signal(
                    &mut signals,
                    "jira",
                    None,
                    "stored:cookie",
                    "stored cookie name is Jira-specific",
                );
            }
        }
        if let Some(title) = data.get("title").and_then(Value::as_str) {
            let lower = title.to_ascii_lowercase();
            if lower.contains("grafana") {
                push_signal(
                    &mut signals,
                    "grafana",
                    None,
                    "stored:title",
                    "stored title contains Grafana",
                );
            }
            if lower.contains("jira") {
                push_signal(
                    &mut signals,
                    "jira",
                    None,
                    "stored:title",
                    "stored title contains Jira",
                );
            }
        }
    }
    merge_signals(signals)
}

fn merge_signals(signals: Vec<Signal>) -> Vec<Value> {
    let mut by_name: BTreeMap<String, Vec<Signal>> = BTreeMap::new();
    for signal in signals {
        by_name.entry(signal.name.clone()).or_default().push(signal);
    }
    let mut out = Vec::new();
    for (name, group) in by_name {
        let mut evidence: Vec<Value> = group
            .iter()
            .map(|signal| {
                json!({
                    "source": signal.source,
                    "evidence": signal.evidence,
                    "version": signal.version,
                })
            })
            .collect();
        evidence.sort_by_key(|item| item.to_string());
        evidence.dedup_by(|a, b| a == b);
        // Keep every distinct version so conflicting evidence is visible.
        let versions: Vec<Value> = group
            .iter()
            .filter_map(|signal| signal.version.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(Value::String)
            .collect();
        let sources: std::collections::BTreeSet<String> =
            group.iter().map(|signal| signal.source.clone()).collect();
        out.push(json!({
            "name": name,
            "version": if versions.len() == 1 { versions[0].clone() } else { Value::Null },
            "versions": versions,
            "source": sources.iter().next().cloned().unwrap_or_default(),
            "sources": sources,
            "evidence": evidence,
            "catalog_version": CATALOG_VERSION,
        }));
    }
    out
}

/// Map detected technologies to routing groups. Multiple groups are allowed.
pub fn groups_for(technologies: &[Value]) -> Vec<String> {
    let names: Vec<String> = technologies
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let mut groups = Vec::new();
    for (group, members) in [
        ("wordpress", &["wordpress"][..]),
        ("jira", &["jira"][..]),
        ("grafana", &["grafana"][..]),
        ("nginx", &["nginx"][..]),
        ("php", &["php"][..]),
        ("spring", &["spring"][..]),
    ] {
        if names.iter().any(|name| members.contains(&name.as_str())) {
            groups.push(group.to_string());
        }
    }
    if groups.is_empty() {
        groups.push("unknown".to_string());
    }
    groups.sort();
    groups
}

/// Label-boundary token check. This prevents `notamazonaws.com` and accidental
/// `api` substrings from matching.
pub fn has_token(host: &str, token: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<_> = host.split('.').collect();
    labels
        .iter()
        .take(labels.len().saturating_sub(1).max(1))
        .any(|label| {
            *label == token
                || label
                    .split(['-', '_'])
                    .any(|part| !part.is_empty() && part == token)
        })
}

pub fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.trim_matches('.').to_ascii_lowercase();
    host == suffix || host.ends_with(&format!(".{suffix}"))
}
