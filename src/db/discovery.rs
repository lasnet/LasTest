//! Project-scoped discovery candidates, evidence, enrichment snapshots and
//! classification results. Publication happens inside the queue completion
//! transaction after ownership has been verified.
use super::{json_or_empty, Db};
use crate::domain::{new_id, NewCandidate, NewClassification, NewEnrichment};
use crate::scope::{canonical_ip, normalize_domain};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::{json, Value};
use std::collections::HashSet;

fn canonical_host(value: &str) -> Option<String> {
    normalize_domain(value).ok()
}

fn text_array(value: &[String]) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_discovery(
    tx: &Transaction<'_>,
    project_id: &str,
    job_id: &str,
    attempt_id: &str,
    now: &str,
    candidates: &[NewCandidate],
    enrichments: &[NewEnrichment],
    classifications: &[NewClassification],
) -> Result<()> {
    for candidate in candidates {
        let Some(hostname) = canonical_host(&candidate.hostname) else {
            continue;
        };
        let source_ip = candidate
            .source_ip
            .as_deref()
            .and_then(|value| canonical_ip(value).ok())
            .map(|ip| ip.to_string());
        tx.execute(
            "INSERT INTO discovery_candidates(
                 id, project_id, hostname, first_seen, last_seen, dns_status, ip_match,
                 addresses, last_checked_at, scope_status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4, COALESCE(?5, 'not_checked'), ?6, ?7, ?8, ?9, ?4, ?4)
             ON CONFLICT(project_id, hostname) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 dns_status = CASE WHEN ?5 IS NULL THEN discovery_candidates.dns_status
                                   ELSE excluded.dns_status END,
                 ip_match = CASE WHEN ?5 IS NULL THEN discovery_candidates.ip_match
                                 ELSE excluded.ip_match END,
                 addresses = CASE WHEN ?5 IS NULL THEN discovery_candidates.addresses
                                  ELSE excluded.addresses END,
                 last_checked_at = CASE WHEN ?5 IS NULL THEN discovery_candidates.last_checked_at
                                        ELSE excluded.last_checked_at END,
                 scope_status = CASE WHEN ?5 IS NULL THEN discovery_candidates.scope_status
                                     ELSE excluded.scope_status END,
                 updated_at = excluded.updated_at",
            params![
                new_id("cnd"),
                project_id,
                hostname,
                now,
                candidate.dns_status,
                candidate.ip_match.as_deref().unwrap_or("unknown"),
                text_array(&candidate.addresses),
                candidate.dns_status.as_ref().map(|_| now),
                candidate.scope_status,
            ],
        )?;
        let candidate_id: String = tx.query_row(
            "SELECT id FROM discovery_candidates WHERE project_id = ?1 AND hostname = ?2",
            params![project_id, hostname],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO candidate_evidence(
                 id, project_id, candidate_id, job_id, attempt_id, attempt_key, source, source_ip,
                 source_ip_key, data_type, dns_status, addresses, ip_match, reason, error, details,
                 observed_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, COALESCE(?7, ''), ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)",
            params![
                new_id("cev"),
                project_id,
                candidate_id,
                job_id,
                attempt_id,
                candidate.source,
                source_ip,
                candidate.data_type,
                candidate.dns_status,
                text_array(&candidate.addresses),
                candidate.ip_match,
                candidate.reason,
                candidate.error,
                candidate.details.to_string(),
                now
            ],
        )?;
        // Only a permitted, verified, non-empty DNS answer may create a host
        // Asset. Provider discovery alone must not publish an unverified host.
        let verified =
            candidate.dns_status.as_deref() == Some("verified") && !candidate.addresses.is_empty();
        if verified {
            tx.execute(
                "INSERT INTO assets(id, project_id, kind, value, canonical_value, first_seen, last_seen)
                 VALUES (?1, ?2, 'host', ?3, ?3, ?4, ?4)
                 ON CONFLICT(project_id, kind, canonical_value)
                 DO UPDATE SET last_seen = excluded.last_seen",
                params![new_id("ast"), project_id, hostname, now],
            )?;
            let asset_id: String = tx.query_row(
                "SELECT id FROM assets WHERE project_id = ?1 AND kind = 'host' AND canonical_value = ?2",
                params![project_id, hostname],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE discovery_candidates SET asset_id = ?1 WHERE id = ?2
                 AND (asset_id IS NULL OR asset_id = ?1)",
                params![asset_id, candidate_id],
            )?;
        }
    }
    for enrichment in enrichments {
        let candidate_id = match &enrichment.candidate_id {
            Some(id) => Some(id.clone()),
            None => tx
                .query_row(
                    "SELECT id FROM discovery_candidates WHERE project_id = ?1 AND hostname = ?2",
                    params![
                        project_id,
                        canonical_host(&enrichment.host).unwrap_or_else(|| enrichment.host.clone())
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?,
        };
        let asset_id = match &enrichment.asset_id {
            Some(id) => Some(id.clone()),
            None => {
                let host = canonical_host(&enrichment.host);
                match host {
                    Some(host) => tx
                        .query_row(
                            "SELECT id FROM assets WHERE project_id = ?1 AND kind = 'host'
                             AND canonical_value = ?2",
                            params![project_id, host],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?,
                    None => None,
                }
            }
        };
        tx.execute(
            "INSERT INTO asset_enrichments(id, project_id, candidate_id, asset_id, job_id,
                 attempt_id, host, format_version, data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                new_id("enr"),
                project_id,
                candidate_id,
                asset_id,
                job_id,
                attempt_id,
                canonical_host(&enrichment.host).unwrap_or_else(|| enrichment.host.clone()),
                enrichment
                    .data
                    .get("format_version")
                    .and_then(Value::as_str)
                    .unwrap_or("1"),
                enrichment.data.to_string(),
                now
            ],
        )?;
    }
    for classification in classifications {
        // Previous versions remain in immutable job artifacts and source
        // evidence. Do not recursively nest the whole history in each row.
        let data = classification.data.clone();
        let field = |name: &str, default: Value| data.get(name).cloned().unwrap_or(default);
        tx.execute(
            "INSERT INTO asset_classifications(
                 id, project_id, subject_type, subject_id, host, catalog_version, confidence,
                 interest, groups, categories, technologies, surface_hints, reasons, evidence,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)
             ON CONFLICT(project_id, subject_type, subject_id) DO UPDATE SET
                 host = excluded.host,
                 catalog_version = excluded.catalog_version,
                 confidence = excluded.confidence,
                 interest = excluded.interest,
                 groups = excluded.groups,
                 categories = excluded.categories,
                 technologies = excluded.technologies,
                 surface_hints = excluded.surface_hints,
                 reasons = excluded.reasons,
                 evidence = excluded.evidence,
                 updated_at = excluded.updated_at",
            params![
                new_id("cls"),
                project_id,
                classification.subject_type,
                classification.subject_id,
                classification.host,
                data.get("catalog_version")
                    .and_then(Value::as_i64)
                    .unwrap_or(1),
                field("confidence", json!("unknown"))
                    .as_str()
                    .unwrap_or("unknown"),
                field("interest", json!("unknown"))
                    .as_str()
                    .unwrap_or("unknown"),
                field("groups", json!([])).to_string(),
                field("categories", json!([])).to_string(),
                field("technologies", json!([])).to_string(),
                field("surface_hints", json!([])).to_string(),
                field("reasons", json!([])).to_string(),
                field("evidence", json!({})).to_string(),
                now
            ],
        )?;
    }
    Ok(())
}

fn candidate_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, String>(0)?,
        "project_id": row.get::<_, String>(1)?,
        "hostname": row.get::<_, String>(2)?,
        "first_seen": row.get::<_, String>(3)?,
        "last_seen": row.get::<_, String>(4)?,
        "asset_id": row.get::<_, Option<String>>(5)?,
        "dns_status": row.get::<_, String>(6)?,
        "ip_match": row.get::<_, String>(7)?,
        "addresses": json_or_empty(row.get::<_, String>(8)?),
        "last_checked_at": row.get::<_, Option<String>>(9)?,
        "scope_status": row.get::<_, String>(10)?,
        "sources": row.get::<_, Option<String>>(11)?
            .and_then(|value| serde_json::from_str::<Value>(&value).ok())
            .unwrap_or_else(|| json!([])),
        "confidence": row.get::<_, Option<String>>(12)?.unwrap_or_else(|| "unknown".into()),
        "interest": row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "unknown".into()),
    }))
}

const CANDIDATE_SELECT: &str = "SELECT c.id, c.project_id, c.hostname, c.first_seen, c.last_seen,
    c.asset_id, c.dns_status, c.ip_match, c.addresses, c.last_checked_at, c.scope_status,
    (SELECT json_group_array(DISTINCT e.source) FROM candidate_evidence e
       WHERE e.candidate_id = c.id AND e.source IN ('ptr', 'shodan_internetdb', 'censys')) AS sources,
    cc.confidence, cc.interest
    FROM discovery_candidates c LEFT JOIN asset_classifications cc
      ON cc.project_id = c.project_id AND cc.subject_type = 'candidate' AND cc.subject_id = c.id";

pub(super) fn inventory_candidates(conn: &Connection, project_id: &str) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(&format!(
        "{CANDIDATE_SELECT} WHERE c.project_id = ?1 ORDER BY c.last_seen DESC"
    ))?;
    let rows = stmt
        .query_map([project_id], candidate_row)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

#[derive(Debug, Clone, Default)]
pub struct CandidateFilter {
    pub query: String,
    pub source: Option<String>,
    pub dns_status: Option<String>,
    pub ip_match: Option<String>,
    pub confidence: Option<String>,
    pub interest: Option<String>,
    pub scope_status: Option<String>,
}

fn scope_status_now(scope: &crate::scope::Scope, host: &str) -> &'static str {
    if scope.allows_host(host) {
        "allowed"
    } else {
        "denied"
    }
}

impl Db {
    pub fn list_candidates(
        &self,
        project_id: &str,
        filter: &CandidateFilter,
        scope: &crate::scope::Scope,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Value>, i64)> {
        let conn = self.connect()?;
        let mut sql = String::from(CANDIDATE_SELECT);
        let mut conditions = vec!["c.project_id = ?1".to_string()];
        conditions.push("(?2 = '' OR c.hostname LIKE ?2 ESCAPE '\\')".to_string());
        conditions.push(
            "(?3 IS NULL OR EXISTS (SELECT 1 FROM candidate_evidence se WHERE se.candidate_id = c.id AND se.source = ?3))"
                .to_string(),
        );
        conditions.push("(?4 IS NULL OR c.dns_status = ?4)".to_string());
        conditions.push("(?5 IS NULL OR c.ip_match = ?5)".to_string());
        conditions.push(
            "((?6 IS NULL AND ?7 IS NULL) OR EXISTS (
                SELECT 1 FROM asset_classifications cl
                WHERE cl.project_id = c.project_id AND cl.subject_type = 'candidate'
                  AND cl.subject_id = c.id
                  AND (?6 IS NULL OR cl.confidence = ?6)
                  AND (?7 IS NULL OR cl.interest = ?7)))"
                .to_string(),
        );
        let where_clause = conditions.join(" AND ");
        let query = filter.query.trim();
        let like = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
        if let Some(expected) = &filter.scope_status {
            let mut stmt = conn.prepare(&format!(
                "{sql} WHERE {where_clause} ORDER BY c.last_seen DESC, c.hostname"
            ))?;
            let rows = stmt.query_map(
                params![
                    project_id,
                    like,
                    filter.source,
                    filter.dns_status,
                    filter.ip_match,
                    filter.confidence,
                    filter.interest
                ],
                candidate_row,
            )?;
            let mut total = 0;
            let mut items = Vec::new();
            for row in rows {
                let mut row = row?;
                let host = row["hostname"].as_str().unwrap_or_default();
                if scope_status_now(scope, host) != expected {
                    continue;
                }
                if total >= i64::from(offset) && items.len() < limit as usize {
                    row["current_scope_status"] = json!(expected);
                    row["scope_status_at_check"] = row["scope_status"].clone();
                    items.push(row);
                }
                total += 1;
            }
            return Ok((items, total));
        }
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM ({sql} WHERE {where_clause})"),
            params![
                project_id,
                like,
                filter.source,
                filter.dns_status,
                filter.ip_match,
                filter.confidence,
                filter.interest
            ],
            |row| row.get(0),
        )?;
        sql.push_str(&format!(
            " WHERE {where_clause} ORDER BY c.last_seen DESC, c.hostname LIMIT ?8 OFFSET ?9"
        ));
        let mut stmt = conn.prepare(&sql)?;
        let mut items = stmt
            .query_map(
                params![
                    project_id,
                    like,
                    filter.source,
                    filter.dns_status,
                    filter.ip_match,
                    filter.confidence,
                    filter.interest,
                    limit,
                    offset
                ],
                candidate_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            let host = item["hostname"].as_str().unwrap_or_default();
            item["current_scope_status"] = json!(scope_status_now(scope, host));
            item["scope_status_at_check"] = item["scope_status"].clone();
        }
        Ok((items, total))
    }

    pub fn candidate_detail(
        &self,
        project_id: &str,
        candidate_id: &str,
        scope: &crate::scope::Scope,
    ) -> Result<Option<Value>> {
        let conn = self.connect()?;
        let candidate = conn
            .query_row(
                &format!("{CANDIDATE_SELECT} WHERE c.project_id = ?1 AND c.id = ?2"),
                params![project_id, candidate_id],
                candidate_row,
            )
            .optional()?;
        let Some(mut candidate) = candidate else {
            return Ok(None);
        };
        let mut stmt = conn.prepare(
            "SELECT id, source, source_ip, data_type, dns_status, addresses, ip_match, reason,
                    error, details, observed_at, job_id
             FROM candidate_evidence WHERE candidate_id = ?1 ORDER BY observed_at DESC, rowid DESC LIMIT 200",
        )?;
        let evidence = stmt
            .query_map(params![candidate_id], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "source": row.get::<_, String>(1)?,
                    "source_ip": row.get::<_, Option<String>>(2)?,
                    "data_type": row.get::<_, String>(3)?,
                    "dns_status": row.get::<_, Option<String>>(4)?,
                    "addresses": json_or_empty(row.get::<_, String>(5)?),
                    "ip_match": row.get::<_, Option<String>>(6)?,
                    "reason": row.get::<_, Option<String>>(7)?,
                    "error": row.get::<_, Option<String>>(8)?,
                    "details": json_or_empty(row.get::<_, String>(9)?),
                    "observed_at": row.get::<_, String>(10)?,
                    "job_id": row.get::<_, Option<String>>(11)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        candidate["evidence"] = Value::Array(evidence);
        let host = candidate["hostname"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        candidate["current_scope_status"] = json!(scope_status_now(scope, &host));
        candidate["scope_status_at_check"] = candidate["scope_status"].clone();
        candidate["enrichment"] = self
            .latest_enrichment(project_id, &host)?
            .unwrap_or(Value::Null);
        candidate["classification"] = self
            .classification_for(project_id, "candidate", candidate_id)?
            .or_else(|| {
                self.classification_for_host(project_id, &host)
                    .ok()
                    .flatten()
            })
            .unwrap_or(Value::Null);
        if let Some(asset_id) = candidate["asset_id"].as_str() {
            candidate["asset"] = self
                .asset_detail(project_id, asset_id)?
                .unwrap_or(Value::Null);
        }
        Ok(Some(candidate))
    }

    pub fn candidates_for_job(&self, job_id: &str) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(&format!(
            "{CANDIDATE_SELECT} WHERE c.id IN (
                SELECT candidate_id FROM candidate_evidence WHERE job_id = ?1)
             ORDER BY c.hostname"
        ))?;
        let mut items = stmt
            .query_map(params![job_id], candidate_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for candidate in &mut items {
            let id = candidate["id"].as_str().unwrap_or_default().to_string();
            let mut evidence = conn.prepare(
                "SELECT source, source_ip, dns_status, addresses, ip_match, observed_at
                 FROM candidate_evidence WHERE candidate_id = ?1 AND job_id = ?2
                 ORDER BY rowid DESC",
            )?;
            let evidence = evidence
                .query_map(params![id, job_id], |row| {
                    Ok(json!({
                        "source": row.get::<_, String>(0)?,
                        "source_ip": row.get::<_, Option<String>>(1)?,
                        "dns_status": row.get::<_, Option<String>>(2)?,
                        "addresses": json_or_empty(row.get::<_, String>(3)?),
                        "ip_match": row.get::<_, Option<String>>(4)?,
                        "observed_at": row.get::<_, String>(5)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            candidate["sources"] = json!(evidence
                .iter()
                .filter_map(|e| e["source"].as_str())
                .filter(|source| matches!(*source, "ptr" | "censys" | "shodan_internetdb"))
                .collect::<std::collections::BTreeSet<_>>());
            candidate["source_ips"] = json!(evidence
                .iter()
                .filter_map(|e| e["source_ip"].as_str())
                .collect::<std::collections::BTreeSet<_>>());
            if let Some(check) = evidence.iter().find(|e| !e["dns_status"].is_null()) {
                for key in ["dns_status", "addresses", "ip_match"] {
                    candidate[key] = check[key].clone();
                }
                candidate["last_checked_at"] = check["observed_at"].clone();
            } else {
                candidate["dns_status"] = json!("not_checked");
                candidate["addresses"] = json!([]);
                candidate["ip_match"] = json!("unknown");
                candidate["last_checked_at"] = Value::Null;
            }
        }
        Ok(items)
    }

    pub fn candidate_by_id_raw(&self, project_id: &str, id: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        Ok(conn
            .query_row(
                &format!("{CANDIDATE_SELECT} WHERE c.project_id = ?1 AND c.id = ?2"),
                params![project_id, id],
                candidate_row,
            )
            .optional()?)
    }

    pub fn candidates_by_ids(&self, project_id: &str, ids: &[String]) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for id in ids {
            if let Some(candidate) = self.candidate_by_id_raw(project_id, id)? {
                if seen.insert(id.clone()) {
                    out.push(candidate);
                }
            }
        }
        Ok(out)
    }

    pub fn candidate_source_ips(
        &self,
        project_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<String>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT DISTINCT source_ip FROM candidate_evidence
             WHERE project_id = ?1 AND candidate_id = ?2 AND source_ip IS NOT NULL",
        )?;
        let items = stmt
            .query_map(params![project_id, candidate_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub fn candidate_for_asset(&self, project_id: &str, asset_id: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        Ok(conn
            .query_row(
                &format!(
                    "{CANDIDATE_SELECT} WHERE c.project_id = ?1
                     AND (c.asset_id = ?2 OR c.hostname = (
                         SELECT canonical_value FROM assets WHERE id = ?2 AND project_id = ?1))
                     ORDER BY c.last_seen DESC LIMIT 1"
                ),
                params![project_id, asset_id],
                candidate_row,
            )
            .optional()?)
    }

    pub fn recent_candidates(&self, project_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(&format!(
            "{CANDIDATE_SELECT} WHERE c.project_id = ?1 ORDER BY c.last_seen DESC LIMIT ?2"
        ))?;
        let items = stmt
            .query_map(params![project_id, limit], candidate_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub fn latest_enrichment(&self, project_id: &str, host: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        let result = conn
            .query_row(
                "SELECT id, host, format_version, data, created_at, job_id, candidate_id, asset_id
                 FROM asset_enrichments WHERE project_id = ?1 AND host = ?2
                 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![project_id, host],
                |row| {
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "host": row.get::<_, String>(1)?,
                        "format_version": row.get::<_, String>(2)?,
                        "data": json_or_empty(row.get::<_, String>(3)?),
                        "created_at": row.get::<_, String>(4)?,
                        "job_id": row.get::<_, Option<String>>(5)?,
                        "candidate_id": row.get::<_, Option<String>>(6)?,
                        "asset_id": row.get::<_, Option<String>>(7)?,
                    }))
                },
            )
            .optional()?;
        Ok(result)
    }

    pub fn classification_for(
        &self,
        project_id: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Option<Value>> {
        let conn = self.connect()?;
        classification_query(
            &conn,
            "project_id = ?1 AND subject_type = ?2 AND subject_id = ?3",
            params![project_id, subject_type, subject_id],
        )
    }

    pub fn classification_for_host(&self, project_id: &str, host: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        classification_query(
            &conn,
            "project_id = ?1 AND host = ?2 AND subject_type IN ('asset', 'candidate') ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            params![project_id, host],
        )
    }

    pub fn classifications_for_project(&self, project_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {CLASSIFICATION_COLUMNS} FROM asset_classifications
             WHERE project_id = ?1 ORDER BY updated_at DESC, id LIMIT ?2"
        ))?;
        let items = stmt
            .query_map(params![project_id, limit], classification_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub fn enrichments_for_job(&self, job_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, host, format_version, data, created_at, job_id, candidate_id, asset_id
             FROM asset_enrichments WHERE job_id = ?1
             ORDER BY created_at DESC, id LIMIT ?2",
        )?;
        let items = stmt
            .query_map(params![job_id, limit], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "host": row.get::<_, String>(1)?,
                    "format_version": row.get::<_, String>(2)?,
                    "data": json_or_empty(row.get::<_, String>(3)?),
                    "created_at": row.get::<_, String>(4)?,
                    "job_id": row.get::<_, Option<String>>(5)?,
                    "candidate_id": row.get::<_, Option<String>>(6)?,
                    "asset_id": row.get::<_, Option<String>>(7)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub fn enrichments_for_project(&self, project_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, host, format_version, data, created_at, job_id, candidate_id, asset_id
             FROM asset_enrichments WHERE project_id = ?1
             ORDER BY created_at DESC, id LIMIT ?2",
        )?;
        let items = stmt
            .query_map(params![project_id, limit], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "host": row.get::<_, String>(1)?,
                    "format_version": row.get::<_, String>(2)?,
                    "data": json_or_empty(row.get::<_, String>(3)?),
                    "created_at": row.get::<_, String>(4)?,
                    "job_id": row.get::<_, Option<String>>(5)?,
                    "candidate_id": row.get::<_, Option<String>>(6)?,
                    "asset_id": row.get::<_, Option<String>>(7)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub fn observations_for_host(&self, project_id: &str, host: &str) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, source, kind, asset, canonical_asset, data, scope_status, observed_at, job_id
             FROM observations WHERE project_id = ?1
               AND (canonical_asset = ?2 OR asset = ?2
                    OR json_extract(data, '$.host') = ?2
                    OR (kind = 'http' AND (
                        canonical_asset LIKE ?3 OR canonical_asset LIKE ?4
                        OR canonical_asset LIKE ?5 OR canonical_asset LIKE ?6)))
             ORDER BY observed_at DESC, rowid DESC LIMIT 500",
        )?;
        let items = stmt
            .query_map(
                params![
                    project_id,
                    host,
                    format!("http://{host}/%"),
                    format!("https://{host}/%"),
                    format!("http://{host}:%"),
                    format!("https://{host}:%")
                ],
                |row| {
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "source": row.get::<_, String>(1)?,
                        "kind": row.get::<_, String>(2)?,
                        "asset": row.get::<_, String>(3)?,
                        "canonical_asset": row.get::<_, String>(4)?,
                        "data": json_or_empty(row.get::<_, String>(5)?),
                        "scope_status": row.get::<_, String>(6)?,
                        "observed_at": row.get::<_, String>(7)?,
                        "job_id": row.get::<_, Option<String>>(8)?,
                    }))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items
            .into_iter()
            .filter(|item| {
                item["kind"] != "http"
                    || item["data"]["url"]
                        .as_str()
                        .or_else(|| item["canonical_asset"].as_str())
                        .and_then(|raw| url::Url::parse(raw).ok())
                        .and_then(|url| url.host_str().map(str::to_string))
                        .as_deref()
                        == Some(host)
            })
            .collect())
    }
}

const CLASSIFICATION_COLUMNS: &str = "id, project_id, subject_type, subject_id, host,
    catalog_version, confidence, interest, groups, categories, technologies, surface_hints,
    reasons, evidence, created_at, updated_at";

pub(super) fn inventory_classifications(conn: &Connection, project_id: &str) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(
        "SELECT subject_type, subject_id, host, confidence, interest, groups, categories, technologies
         FROM asset_classifications WHERE project_id = ?1 AND subject_type IN ('asset', 'candidate')
         ORDER BY updated_at DESC, rowid DESC",
    )?;
    let rows = stmt
        .query_map([project_id], |row| {
            Ok(json!({
                "subject_type": row.get::<_, String>(0)?,
                "subject_id": row.get::<_, String>(1)?,
                "host": row.get::<_, Option<String>>(2)?,
                "confidence": row.get::<_, String>(3)?,
                "interest": row.get::<_, String>(4)?,
                "groups": json_or_empty(row.get::<_, String>(5)?),
                "categories": json_or_empty(row.get::<_, String>(6)?),
                "technologies": json_or_empty(row.get::<_, String>(7)?),
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn classification_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, String>(0)?,
        "project_id": row.get::<_, String>(1)?,
        "subject_type": row.get::<_, String>(2)?,
        "subject_id": row.get::<_, String>(3)?,
        "host": row.get::<_, Option<String>>(4)?,
        "catalog_version": row.get::<_, i64>(5)?,
        "confidence": row.get::<_, String>(6)?,
        "interest": row.get::<_, String>(7)?,
        "groups": json_or_empty(row.get::<_, String>(8)?),
        "categories": json_or_empty(row.get::<_, String>(9)?),
        "technologies": json_or_empty(row.get::<_, String>(10)?),
        "surface_hints": json_or_empty(row.get::<_, String>(11)?),
        "reasons": json_or_empty(row.get::<_, String>(12)?),
        "evidence": json_or_empty(row.get::<_, String>(13)?),
        "created_at": row.get::<_, String>(14)?,
        "updated_at": row.get::<_, String>(15)?,
    }))
}

fn classification_query(
    conn: &Connection,
    where_clause: &str,
    values: impl rusqlite::Params,
) -> Result<Option<Value>> {
    let result = conn
        .query_row(
            &format!(
                "SELECT {CLASSIFICATION_COLUMNS} FROM asset_classifications WHERE {where_clause}"
            ),
            values,
            classification_row,
        )
        .optional()?;
    Ok(result)
}
