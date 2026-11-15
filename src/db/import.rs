//! Low-level idempotent writes used by the legacy importer.

use crate::db::Db;
use crate::domain::{new_id, now_rfc3339};
use anyhow::Result;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct ImportedJob {
    pub task_type: String,
    pub status: String,
    pub params: Value,
    pub result: Value,
    pub error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedObservation {
    pub source: String,
    pub kind: String,
    pub asset_kind: String,
    pub asset: String,
    pub canonical: String,
    pub data: Value,
    pub scope_status: String,
    pub observed_at: String,
}

#[derive(Debug, Clone)]
pub struct ImportedFinding {
    pub source: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub asset: String,
    pub evidence: Value,
    pub first_seen: String,
    pub last_seen: String,
}

impl Db {
    pub fn project_by_source_id(
        &self,
        source_project_id: &str,
    ) -> Result<Option<crate::domain::Project>> {
        let conn = self.connect()?;
        let project = conn
            .query_row(
                "SELECT id, name, client, description, created_at, updated_at, source, source_project_id
                 FROM projects WHERE source = 'lastest-1.x' AND source_project_id = ?1 LIMIT 1",
                params![source_project_id],
                |row| {
                    Ok(crate::domain::Project {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        client: row.get(2)?,
                        description: row.get(3)?,
                        created_at: row.get(4)?,
                        updated_at: row.get(5)?,
                        source: row.get(6)?,
                        source_project_id: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(project)
    }

    pub fn create_import_run(
        &self,
        source_root: &str,
        mode: &str,
        stats: &Value,
        report: &Value,
    ) -> Result<String> {
        let id = new_id("imp");
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO import_runs(id, source_root, mode, stats, report, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                source_root,
                mode,
                stats.to_string(),
                report.to_string(),
                now_rfc3339()
            ],
        )?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_import_job(
        &self,
        project_id: &str,
        scope_revision_id: &str,
        scope_version: i64,
        source_job_id: &str,
        job: &ImportedJob,
        actor: &str,
    ) -> Result<String> {
        let id = new_id("job");
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO jobs(id, project_id, task_type, params, status, scope_revision_id,
                              scope_version, idempotency_key, created_by, created_at, started_at,
                              finished_at, error, result, counters, archived)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, '{}', 1)",
            params![
                id,
                project_id,
                job.task_type,
                job.params.to_string(),
                job.status,
                scope_revision_id,
                scope_version,
                format!("legacy:{source_job_id}"),
                actor,
                job.created_at,
                job.started_at,
                job.finished_at,
                job.error,
                job.result.to_string()
            ],
        )?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_import_observation(
        &self,
        project_id: &str,
        job_id: Option<&str>,
        observation: &ImportedObservation,
    ) -> Result<String> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO assets(id, project_id, kind, value, canonical_value, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(project_id, kind, canonical_value)
             DO UPDATE SET last_seen = excluded.last_seen",
            params![
                new_id("ast"),
                project_id,
                observation.asset_kind,
                observation.asset,
                observation.canonical,
                observation.observed_at
            ],
        )?;
        let asset_id: String = conn.query_row(
            "SELECT id FROM assets WHERE project_id = ?1 AND kind = ?2 AND canonical_value = ?3",
            params![project_id, observation.asset_kind, observation.canonical],
            |row| row.get(0),
        )?;
        let id = new_id("obs");
        conn.execute(
            "INSERT INTO observations(id, project_id, job_id, source, kind, asset, canonical_asset,
                                      asset_id, data, scope_status, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                project_id,
                job_id,
                observation.source,
                observation.kind,
                observation.asset,
                observation.canonical,
                asset_id,
                observation.data.to_string(),
                observation.scope_status,
                observation.observed_at
            ],
        )?;
        Ok(id)
    }

    pub fn insert_import_finding(
        &self,
        project_id: &str,
        job_id: Option<&str>,
        finding: &ImportedFinding,
    ) -> Result<String> {
        let conn = self.connect()?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT id FROM findings WHERE project_id = ?1 AND rule_id = ?2 AND asset = ?3
                 AND rule_version = 1",
                params![project_id, finding.rule_id, finding.asset],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(id);
        }
        let id = new_id("fnd");
        conn.execute(
            "INSERT INTO findings(id, project_id, job_id, rule_id, rule_version, severity, title,
                                  asset, evidence, source, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                project_id,
                job_id,
                finding.rule_id,
                finding.severity,
                finding.title,
                finding.asset,
                finding.evidence.to_string(),
                finding.source,
                finding.first_seen,
                finding.last_seen
            ],
        )?;
        Ok(id)
    }

    pub fn register_import_artifact(
        &self,
        project_id: &str,
        relative_path: &str,
        kind: &str,
        size: u64,
        sha256: &str,
    ) -> Result<String> {
        let id = new_id("art");
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO artifacts(id, project_id, relative_path, kind, size, sha256, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(project_id, relative_path) DO UPDATE SET
                 size = excluded.size, sha256 = excluded.sha256",
            params![
                id,
                project_id,
                relative_path,
                kind,
                size as i64,
                sha256,
                now_rfc3339()
            ],
        )?;
        Ok(id)
    }

    pub fn import_record_exists(
        &self,
        project_id: &str,
        source_kind: &str,
        source_id: &str,
    ) -> Result<bool> {
        let conn = self.connect()?;
        let value: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM import_records WHERE project_id = ?1 AND source_kind = ?2
                 AND source_id = ?3",
                params![project_id, source_kind, source_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.is_some())
    }

    pub fn add_import_record(
        &self,
        project_id: &str,
        source_kind: &str,
        source_id: &str,
        target_table: &str,
        target_id: &str,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR IGNORE INTO import_records(id, project_id, source_kind, source_id,
                                                  target_table, target_id, import_version, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '1.x-json', ?7)",
            params![
                new_id("imr"),
                project_id,
                source_kind,
                source_id,
                target_table,
                target_id,
                now_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn insert_import_audit(
        &self,
        actor: &str,
        action: &str,
        entity_type: &str,
        entity_id: Option<&str>,
        details: &Value,
        created_at: &str,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO audit_events(id, actor, action, entity_type, entity_id, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                new_id("aud"),
                format!("legacy:{actor}"),
                action,
                entity_type,
                entity_id,
                details.to_string(),
                created_at
            ],
        )?;
        Ok(())
    }

    pub fn imported_job_count(&self, project_id: &str) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE project_id = ?1 AND archived = 1",
            params![project_id],
            |row| row.get(0),
        )?)
    }

    pub fn mark_import_summary(
        &self,
        project_id: &str,
        scope_revision_id: &str,
        scope_version: i64,
        stats: &Value,
        actor: &str,
    ) -> Result<()> {
        let job = ImportedJob {
            task_type: "import.legacy".to_string(),
            status: "succeeded".to_string(),
            params: json!({"source": "lastest-1.x"}),
            result: stats.clone(),
            error: None,
            created_at: now_rfc3339(),
            started_at: None,
            finished_at: Some(now_rfc3339()),
        };
        self.insert_import_job(
            project_id,
            scope_revision_id,
            scope_version,
            &format!("summary-{}", now_rfc3339()),
            &job,
            actor,
        )?;
        Ok(())
    }
}
