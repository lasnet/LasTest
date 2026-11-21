//! Point-in-time JSON and CSV reports over normalized observations.

use crate::db::Db;
use crate::domain::{now_rfc3339, Job};
use anyhow::{Context, Result};
use serde_json::{json, Value};

pub struct ReportSnapshot {
    pub value: Value,
}

pub fn build_report(db: &Db, project_id: &str) -> Result<ReportSnapshot> {
    let project = db.project_by_id(project_id)?.context("project not found")?;
    let current_scope = db.current_scope(project_id)?;
    let revisions = db.scope_revisions(project_id)?;
    let jobs: Vec<Job> = db.list_jobs(Some(project_id), None, 1000, 0)?.0;
    let observations = db.all_observations(project_id, 100_000)?;
    let findings = db.all_findings(project_id)?;
    let assets = db.list_assets(project_id, 100_000)?;
    let candidates = db.recent_candidates(project_id, 5_000)?;
    let enrichments = db.enrichments_for_project(project_id, 5_000)?;
    let classifications = db.classifications_for_project(project_id, 10_000)?;
    let counts = db.project_observation_counts(project_id)?;
    let mut history = Vec::new();
    for revision in &revisions {
        history.push(json!({
            "version": revision.version,
            "status": revision.status.as_str(),
            "created_at": revision.created_at,
            "created_by": revision.created_by,
            "approved_at": revision.approved_at,
            "approved_by": revision.approved_by,
            "rules": revision.scope.rules,
        }));
    }
    let mut scopes = Vec::new();
    if let Some(scope) = &current_scope {
        scopes.push(scope.to_json());
    }
    let mut dns = Vec::new();
    let mut http = Vec::new();
    let mut services = Vec::new();
    let mut urls = Vec::new();
    let mut sources = serde_json::Map::new();
    for observation in &observations {
        let source_count = sources
            .entry(observation.source.clone())
            .or_insert_with(|| json!(0));
        if let Some(value) = source_count.as_u64() {
            *source_count = json!(value + 1);
        }
        match observation.kind.as_str() {
            "dns" | "ptr" | "dns_empty" => dns.push(json!({
                "asset": observation.asset,
                "source": observation.source,
                "scope_status": observation.scope_status,
                "observed_at": observation.observed_at,
                "data": observation.data,
            })),
            "http" => http.push(json!({
                "asset": observation.asset,
                "source": observation.source,
                "scope_status": observation.scope_status,
                "observed_at": observation.observed_at,
                "data": observation.data,
            })),
            "url" => urls.push(json!({
                "asset": observation.asset,
                "source": observation.source,
                "scope_status": observation.scope_status,
                "observed_at": observation.observed_at,
                "data": observation.data,
            })),
            "port" | "service" => services.push(json!({
                "asset": observation.asset,
                "kind": observation.kind,
                "source": observation.source,
                "observed_at": observation.observed_at,
                "data": observation.data,
            })),
            _ => {}
        }
    }
    let domain_ip: Vec<Value> = observations
        .iter()
        .filter(|observation| observation.kind == "ip")
        .filter_map(|observation| {
            observation
                .data
                .get("host")
                .and_then(Value::as_str)
                .map(|host| {
                    json!({
                        "domain": host,
                        "ip": observation.asset,
                        "source": observation.source,
                        "observed_at": observation.observed_at
                    })
                })
        })
        .collect();
    let confirmed_ports: Vec<&Value> = services
        .iter()
        .filter(|item| item["kind"] == "port")
        .filter(|item| item["data"]["state"] == "open")
        .collect();
    let candidate_ports: Vec<&Value> = services
        .iter()
        .filter(|item| item["kind"] == "port")
        .filter(|item| item["data"]["state"] != "open" && item["data"]["state"] != "closed")
        .collect();
    let value = json!({
        "format_version": "2.0",
        "generated_at": now_rfc3339(),
        "project": project,
        "scope": {
            "current": scopes.first(),
            "history": history,
        },
        "history": jobs,
        "counts": counts,
        "assets": assets,
        "domain_ip": domain_ip,
        "dns": dns,
        "http": http,
        "urls": urls,
        "services": services,
        "confirmed_ports": confirmed_ports,
        "candidate_ports": candidate_ports,
        "findings": findings,
        "sources": sources,
        "candidates": candidates,
        "enrichment": enrichments,
        "classification": {
            "catalog_version": crate::tasks::tech_catalog::CATALOG_VERSION,
            "generated_at": now_rfc3339(),
            "subjects": classifications,
        },
    });
    Ok(ReportSnapshot { value })
}

pub fn render_json(snapshot: &ReportSnapshot) -> Result<Vec<u8>> {
    let mut data = serde_json::to_vec_pretty(&snapshot.value)?;
    data.push(b'\n');
    Ok(data)
}

pub fn render_csv(snapshot: &ReportSnapshot) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "section",
        "record_type",
        "asset",
        "source",
        "severity",
        "scope_status",
        "observed_at",
        "data",
    ])?;
    if let Some(scope) = snapshot
        .value
        .get("scope")
        .and_then(|value| value.get("current"))
    {
        if let Some(rules) = scope.get("rules").and_then(Value::as_array) {
            for rule in rules {
                writer.write_record([
                    csv_cell("scope"),
                    csv_cell(rule.get("kind").and_then(Value::as_str).unwrap_or("rule")),
                    csv_cell(rule.get("value").and_then(Value::as_str).unwrap_or("")),
                    csv_cell("scope_revision"),
                    String::new(),
                    csv_cell(
                        if rule.get("exclusion").and_then(Value::as_bool) == Some(true) {
                            "excluded"
                        } else {
                            "allowed"
                        },
                    ),
                    String::new(),
                    csv_cell(&rule.to_string()),
                ])?;
            }
        }
    }
    if let Some(history) = snapshot.value.get("history").and_then(Value::as_array) {
        for job in history {
            writer.write_record([
                csv_cell("history"),
                csv_cell(job.get("task_type").and_then(Value::as_str).unwrap_or("")),
                csv_cell(job.get("project_id").and_then(Value::as_str).unwrap_or("")),
                csv_cell(job.get("created_by").and_then(Value::as_str).unwrap_or("")),
                String::new(),
                csv_cell(job.get("status").and_then(Value::as_str).unwrap_or("")),
                csv_cell(job.get("created_at").and_then(Value::as_str).unwrap_or("")),
                csv_cell(&job.to_string()),
            ])?;
        }
    }
    for section in [
        "dns",
        "http",
        "urls",
        "services",
        "confirmed_ports",
        "candidate_ports",
    ] {
        if let Some(items) = snapshot.value.get(section).and_then(Value::as_array) {
            for item in items {
                let data = item.get("data").cloned().unwrap_or_else(|| item.clone());
                writer.write_record([
                    csv_cell(section),
                    csv_cell(
                        item.get("kind")
                            .and_then(Value::as_str)
                            .or_else(|| data.get("record_type").and_then(Value::as_str))
                            .unwrap_or(""),
                    ),
                    csv_cell(item.get("asset").and_then(Value::as_str).unwrap_or("")),
                    csv_cell(item.get("source").and_then(Value::as_str).unwrap_or("")),
                    String::new(),
                    csv_cell(
                        item.get("scope_status")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    csv_cell(
                        item.get("observed_at")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    ),
                    csv_cell(&data.to_string()),
                ])?;
            }
        }
    }
    if let Some(findings) = snapshot.value.get("findings").and_then(Value::as_array) {
        for finding in findings {
            writer.write_record([
                csv_cell("findings"),
                csv_cell(finding.get("rule_id").and_then(Value::as_str).unwrap_or("")),
                csv_cell(finding.get("asset").and_then(Value::as_str).unwrap_or("")),
                csv_cell(finding.get("source").and_then(Value::as_str).unwrap_or("")),
                csv_cell(
                    finding
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ),
                String::new(),
                csv_cell(
                    finding
                        .get("last_seen")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                ),
                csv_cell(&finding.to_string()),
            ])?;
        }
    }
    let data = writer
        .into_inner()
        .map_err(|err| anyhow::anyhow!("CSV error: {err}"))?;
    Ok(data)
}

/// Explicit extended discovery export. The standard Assets CSV/TXT and the
/// standard report remain unchanged.
pub fn render_discovery_json(snapshot: &ReportSnapshot) -> Result<Vec<u8>> {
    let value = json!({
        "format_version": "1",
        "generated_at": now_rfc3339(),
        "project": snapshot.value.get("project").cloned().unwrap_or(Value::Null),
        "candidates": snapshot.value.get("candidates").cloned().unwrap_or_else(|| json!([])),
        "enrichment": snapshot.value.get("enrichment").cloned().unwrap_or_else(|| json!([])),
        "classification": snapshot.value.get("classification").cloned().unwrap_or(Value::Null),
    });
    let mut data = serde_json::to_vec_pretty(&value)?;
    data.push(b'\n');
    Ok(data)
}

pub fn render_discovery_csv(snapshot: &ReportSnapshot) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "section",
        "host",
        "sources",
        "dns_status",
        "ip_match",
        "scope_status",
        "confidence",
        "interest",
        "groups",
        "categories",
        "technologies",
        "observed_at",
    ])?;
    if let Some(candidates) = snapshot.value.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            writer.write_record([
                csv_cell("candidate"),
                csv_cell(candidate["hostname"].as_str().unwrap_or("")),
                csv_cell(&candidate["sources"].to_string()),
                csv_cell(candidate["dns_status"].as_str().unwrap_or("")),
                csv_cell(candidate["ip_match"].as_str().unwrap_or("")),
                csv_cell(candidate["scope_status"].as_str().unwrap_or("")),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                csv_cell(candidate["last_seen"].as_str().unwrap_or("")),
            ])?;
        }
    }
    if let Some(subjects) = snapshot
        .value
        .pointer("/classification/subjects")
        .and_then(Value::as_array)
    {
        for subject in subjects {
            writer.write_record([
                csv_cell("classification"),
                csv_cell(subject["host"].as_str().unwrap_or("")),
                csv_cell(subject["subject_type"].as_str().unwrap_or("")),
                String::new(),
                String::new(),
                String::new(),
                csv_cell(subject["confidence"].as_str().unwrap_or("")),
                csv_cell(subject["interest"].as_str().unwrap_or("")),
                csv_cell(&subject["groups"].to_string()),
                csv_cell(&subject["categories"].to_string()),
                csv_cell(&subject["technologies"].to_string()),
                csv_cell(subject["updated_at"].as_str().unwrap_or("")),
            ])?;
        }
    }
    writer
        .into_inner()
        .map_err(|err| anyhow::anyhow!("CSV error: {err}"))
}

/// Prevent spreadsheet formula interpretation of attacker-controlled values.
pub fn csv_cell(value: &str) -> String {
    let cleaned: String = value.chars().filter(|c| *c != '\0').collect();
    let dangerous = cleaned
        .trim_start_matches([' ', '\t'])
        .starts_with(['=', '+', '-', '@', '\t', '\r']);
    if dangerous || cleaned.starts_with(['\t', '\r']) {
        format!("'{cleaned}")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_formula_injection_is_neutralized() {
        assert_eq!(csv_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("normal"), "normal");
        assert_eq!(csv_cell("  =cmd"), "'  =cmd");
    }
}
