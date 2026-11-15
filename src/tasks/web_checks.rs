use crate::domain::Job;
use crate::scope::{normalize_domain, parse_target_url};
use crate::tasks::{dedup_strings, ensure_target_limit, parse_params, TaskContext, TaskOutcome};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: &'static str,
    pub version: u32,
    pub severity: &'static str,
    pub applicability: &'static str,
}

pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "web.hsts_missing",
        version: 1,
        severity: "medium",
        applicability: "HTTPS responses",
    },
    RuleInfo {
        id: "web.tls_cert_expiry",
        version: 1,
        severity: "high",
        applicability: "HTTPS responses with a readable certificate",
    },
    RuleInfo {
        id: "web.cookie_secure_missing",
        version: 1,
        severity: "medium",
        applicability: "HTTPS responses setting an explicitly configured session cookie",
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckParams {
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    cookie_names: Vec<String>,
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

fn chain_https_urls(ctx: &TaskContext) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for observation in ctx.chain_input_observations("url")? {
        if observation.asset.starts_with("https://") {
            out.push(observation.asset);
        }
    }
    for observation in ctx.chain_input_observations("http")? {
        if let Some(url) = observation.data.get("url").and_then(Value::as_str) {
            if url.starts_with("https://") {
                out.push(url.to_string());
            }
        }
    }
    Ok(out)
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: CheckParams = parse_params(&job.params)?;
    let mut targets = if params.targets.is_empty() {
        let chained = chain_https_urls(ctx)?;
        if chained.is_empty() {
            scope_hosts(ctx)
                .into_iter()
                .map(|host| format!("https://{host}/"))
                .collect()
        } else {
            chained
        }
    } else {
        params.targets
    };
    targets = dedup_strings(&targets);
    ensure_target_limit(targets.len(), &ctx.config)?;
    if targets.is_empty() {
        anyhow::bail!("web.checks requires at least one HTTPS target or allowed domain in scope");
    }
    let cookie_names: Vec<String> = if params.cookie_names.is_empty() {
        ctx.config.session_cookie_names.clone()
    } else {
        params.cookie_names
    };
    let prober = ctx.prober()?;
    let policy = ctx.config.network_policy();
    let mut outcome = TaskOutcome::new();
    outcome.target(targets.len());
    let mut coverage: BTreeMap<&'static str, Value> = BTreeMap::new();
    for rule in RULES {
        coverage.insert(
            rule.id,
            json!({
                "id": rule.id,
                "version": rule.version,
                "severity": rule.severity,
                "applicability": rule.applicability,
                "evaluated": 0,
                "findings": 0,
                "not_applicable": 0,
                "measurement_errors": 0
            }),
        );
    }
    for raw_target in targets {
        ctx.ensure_active()?;
        let target = if raw_target.contains("://") {
            raw_target
        } else {
            let host = match normalize_domain(&raw_target) {
                Ok(value) => value,
                Err(err) => {
                    outcome.error(format!("{raw_target}: {err}"));
                    outcome.skipped();
                    continue;
                }
            };
            format!("https://{host}/")
        };
        let url = match parse_target_url(&target) {
            Ok(url) => url,
            Err(err) => {
                outcome.error(format!("{target}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if url.scheme() != "https" {
            increment(&mut coverage, "web.hsts_missing", "not_applicable");
            increment(&mut coverage, "web.cookie_secure_missing", "not_applicable");
            increment(&mut coverage, "web.tls_cert_expiry", "not_applicable");
            outcome.observe(
                "web.checks",
                "web_check",
                "url",
                url.as_str(),
                json!({"status": "not_applicable", "reason": "rule set applies to HTTPS only"}),
                "allowed",
            );
            outcome.skipped();
            continue;
        }
        let host = url.host_str().unwrap_or_default().to_string();
        if !ctx.allows_host_now(&host) {
            outcome.error(format!("{host} is outside the effective scope"));
            outcome.skipped();
            continue;
        }
        let fetch = match prober
            .get_with_authorizer(url.as_str(), &policy, |candidate| {
                ctx.authorize_url_now(candidate)
            })
            .await
        {
            Ok(fetch) => fetch,
            Err(err) => {
                outcome.error(format!("{target}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        outcome.observe(
            "web.checks",
            "web_check",
            "url",
            &fetch.final_url,
            json!({
                "status_code": fetch.status,
                "verified_ip": fetch.remote_ip.to_string(),
                "cookie_names": cookie_names,
                "tls_cert_not_after": fetch.tls_cert_not_after
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            }),
            "allowed",
        );
        let before = outcome.findings.len();
        // HSTS rule.
        let hsts = fetch.header("strict-transport-security");
        let hsts_valid = hsts_is_valid(hsts);
        increment(&mut coverage, "web.hsts_missing", "evaluated");
        if !hsts_valid {
            outcome.finding(
                "web.hsts_missing",
                1,
                "medium",
                "HTTPS response does not set a valid HSTS policy",
                url.as_str(),
                json!({
                    "target": fetch.final_url,
                    "header_present": hsts.is_some(),
                    "evidence": "Strict-Transport-Security is missing or has max-age=0"
                }),
                "web.checks",
            );
            increment(&mut coverage, "web.hsts_missing", "findings");
        }
        // Certificate expiry rule.
        match fetch.tls_cert_not_after {
            Some(not_after) => {
                increment(&mut coverage, "web.tls_cert_expiry", "evaluated");
                let now = chrono::Utc::now();
                let seconds = (not_after - now).num_seconds();
                let days = certificate_days_remaining(not_after);
                if seconds <= 0 {
                    outcome.finding(
                        "web.tls_cert_expiry",
                        1,
                        "critical",
                        "TLS certificate has expired",
                        url.as_str(),
                        json!({
                            "not_after": not_after.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            "days_remaining": days,
                            "threshold_days": ctx.config.tls_expiry_warning_days
                        }),
                        "web.checks",
                    );
                    increment(&mut coverage, "web.tls_cert_expiry", "findings");
                } else if days <= ctx.config.tls_expiry_warning_days {
                    outcome.finding(
                        "web.tls_cert_expiry",
                        1,
                        "high",
                        "TLS certificate expires soon",
                        url.as_str(),
                        json!({
                            "not_after": not_after.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            "days_remaining": days,
                            "threshold_days": ctx.config.tls_expiry_warning_days
                        }),
                        "web.checks",
                    );
                    increment(&mut coverage, "web.tls_cert_expiry", "findings");
                }
            }
            None => {
                increment(&mut coverage, "web.tls_cert_expiry", "measurement_errors");
                outcome.error(format!(
                    "certificate expiry could not be measured for {}",
                    url.as_str()
                ));
            }
        }
        // Cookie Secure rule. Values are parsed in memory and never persisted.
        let mut matched_cookie = false;
        for header in fetch.header_values("set-cookie") {
            let Some((name, attrs)) = parse_cookie(header) else {
                continue;
            };
            if !cookie_names
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            matched_cookie = true;
            increment(&mut coverage, "web.cookie_secure_missing", "evaluated");
            let secure = cookie_has_secure(&attrs);
            if !secure {
                outcome.finding(
                    "web.cookie_secure_missing",
                    1,
                    "medium",
                    "Session cookie is set without the Secure attribute",
                    url.as_str(),
                    json!({
                        "target": fetch.final_url,
                        "cookie_name": name,
                        "attributes": attrs,
                        "value_recorded": false
                    }),
                    "web.checks",
                );
                increment(&mut coverage, "web.cookie_secure_missing", "findings");
            }
        }
        if !matched_cookie {
            increment(&mut coverage, "web.cookie_secure_missing", "not_applicable");
        }
        if outcome.findings.len() == before {
            // no finding is a valid negative result
        }
        outcome.processed();
    }
    outcome.result = json!({
        "format_version": "1",
        "rules": coverage.values().cloned().collect::<Vec<_>>(),
        "targets": outcome.counters.targets,
    });
    let result = outcome.result.clone();
    outcome.add_artifact(
        "web_checks",
        &format!("{}-web-checks.json", job.id),
        &result,
    )?;
    Ok(outcome.finalize())
}

fn increment(coverage: &mut BTreeMap<&'static str, Value>, rule: &str, field: &str) {
    if let Some(value) = coverage.get_mut(rule) {
        let current = value.get(field).and_then(Value::as_u64).unwrap_or(0);
        value[field] = json!(current + 1);
    }
}

pub fn hsts_is_valid(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.split(';').any(|part| {
            let part = part.trim();
            part.to_ascii_lowercase()
                .strip_prefix("max-age=")
                .and_then(|raw| raw.parse::<u64>().ok())
                .is_some_and(|seconds| seconds > 0)
        })
    })
}

pub fn certificate_days_remaining(not_after: chrono::DateTime<chrono::Utc>) -> i64 {
    (not_after - chrono::Utc::now()).num_seconds() / 86_400
}

pub fn cookie_has_secure(attrs: &[String]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.trim().eq_ignore_ascii_case("secure"))
}

pub fn parse_cookie(header: &str) -> Option<(String, Vec<String>)> {
    let mut parts = header.split(';');
    let first = parts.next()?.trim();
    let (name, _value) = first.split_once('=')?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let attrs = parts
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect();
    Some((name, attrs))
}

pub fn rules_catalog() -> Vec<Value> {
    RULES
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "version": rule.version,
                "severity": rule.severity,
                "applicability": rule.applicability,
                "source": "web.checks"
            })
        })
        .collect()
}

#[allow(dead_code)]
fn _url_marker() -> Option<String> {
    Url::parse("https://example.com")
        .ok()
        .map(|url| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsts_positive_and_negative() {
        assert!(hsts_is_valid(Some("max-age=31536000; includeSubDomains")));
        assert!(!hsts_is_valid(None));
        assert!(!hsts_is_valid(Some("max-age=0")));
        assert!(!hsts_is_valid(Some("includeSubDomains")));
    }

    #[test]
    fn certificate_expiry_positive_and_negative() {
        let now = chrono::Utc::now();
        assert!(certificate_days_remaining(now + chrono::Duration::days(5)) <= 30);
        assert!(certificate_days_remaining(now + chrono::Duration::days(90)) > 30);
        assert!(certificate_days_remaining(now - chrono::Duration::days(1)) < 0);
    }

    #[test]
    fn cookie_secure_positive_and_negative() {
        let secure = vec![
            "Path=/".to_string(),
            "Secure".to_string(),
            "HttpOnly".to_string(),
        ];
        let insecure = vec!["Path=/".to_string(), "HttpOnly".to_string()];
        assert!(cookie_has_secure(&secure));
        assert!(!cookie_has_secure(&insecure));
        let (name, attrs) = parse_cookie("session=abc123; Path=/; HttpOnly").unwrap();
        assert_eq!(name, "session");
        assert!(!cookie_has_secure(&attrs));
    }

    #[test]
    fn cookie_values_are_not_part_of_evidence_shape() {
        let (_, attrs) = parse_cookie("session=super-secret; Path=/; HttpOnly").unwrap();
        assert!(!attrs.iter().any(|attr| attr.contains("super-secret")));
    }
}
