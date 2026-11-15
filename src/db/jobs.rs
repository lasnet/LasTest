use crate::db::{json_or_empty, Db};
use crate::domain::{
    new_id, now_rfc3339, Artifact, Finding, Job, JobCounters, JobStatus, Observation,
};
use anyhow::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum EnqueueError {
    #[error("idempotency key was already used with different request content")]
    Conflict,
    #[error("project not found")]
    ProjectNotFound,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct Claim {
    pub job: Job,
    pub attempt_id: String,
    pub worker_id: String,
    pub lease_until: String,
}

#[derive(Debug, Clone, Copy)]
pub struct HeartbeatState {
    pub active: bool,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone)]
pub struct NewObservation {
    pub source: String,
    pub kind: String,
    pub asset_kind: String,
    pub asset: String,
    pub canonical_asset: String,
    pub data: Value,
    pub scope_status: String,
}

#[derive(Debug, Clone)]
pub struct NewFinding {
    pub rule_id: String,
    pub rule_version: u32,
    pub severity: String,
    pub title: String,
    pub asset: String,
    pub evidence: Value,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct NewArtifact {
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct CompleteOutcome {
    pub status: JobStatus,
    pub result: Value,
    pub counters: JobCounters,
    pub error: Option<String>,
    pub observations: Vec<NewObservation>,
    pub findings: Vec<NewFinding>,
    pub artifacts: Vec<NewArtifact>,
}

fn map_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    let status_raw: String = row.get(4)?;
    Ok(Job {
        id: row.get(0)?,
        project_id: row.get(1)?,
        task_type: row.get(2)?,
        params: json_or_empty(row.get::<_, String>(3)?),
        status: JobStatus::parse(&status_raw).unwrap_or(JobStatus::Failed),
        scope_revision_id: row.get(5)?,
        scope_version: row.get(6)?,
        idempotency_key: row.get(7)?,
        created_by: row.get(8)?,
        created_at: row.get(9)?,
        started_at: row.get(10)?,
        finished_at: row.get(11)?,
        error: row.get(12)?,
        result: json_or_empty(row.get::<_, String>(13)?),
        counters: serde_json::from_str(&row.get::<_, String>(14)?).unwrap_or_default(),
        archived: row.get::<_, i64>(15)? != 0,
        chain_run_id: row.get(16)?,
        chain_order: row.get(17)?,
    })
}

const JOB_COLUMNS: &str = "id, project_id, task_type, params, status, scope_revision_id,
    scope_version, idempotency_key, created_by, created_at, started_at, finished_at,
    error, result, counters, archived, chain_run_id, chain_order";

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_job(
        &self,
        project_id: &str,
        task_type: &str,
        params: &Value,
        scope_revision_id: &str,
        scope_version: i64,
        idempotency_key: Option<&str>,
        actor: &str,
        chain_run_id: Option<&str>,
        chain_order: Option<i64>,
    ) -> std::result::Result<Job, EnqueueError> {
        let project = self
            .project_by_id(project_id)
            .map_err(EnqueueError::Other)?
            .ok_or(EnqueueError::ProjectNotFound)?;
        let _ = &project;
        if let Some(key) = idempotency_key {
            let conn = self.connect().map_err(EnqueueError::Other)?;
            let existing = conn
                .query_row(
                    &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE project_id = ?1 AND idempotency_key = ?2"),
                    params![project_id, key],
                    map_job,
                )
                .optional()
                .map_err(|err| EnqueueError::Other(anyhow::Error::from(err)))?;
            if let Some(job) = existing {
                if job.task_type == task_type && job.params == *params {
                    return Ok(job);
                }
                return Err(EnqueueError::Conflict);
            }
        }
        let job = Job {
            id: new_id("job"),
            project_id: project_id.to_string(),
            task_type: task_type.to_string(),
            params: params.clone(),
            status: JobStatus::Queued,
            scope_revision_id: scope_revision_id.to_string(),
            scope_version,
            idempotency_key: idempotency_key.map(str::to_string),
            created_by: actor.to_string(),
            created_at: now_rfc3339(),
            started_at: None,
            finished_at: None,
            error: None,
            result: json!({}),
            counters: JobCounters::default(),
            archived: false,
            chain_run_id: chain_run_id.map(str::to_string),
            chain_order,
        };
        let conn = self.connect().map_err(EnqueueError::Other)?;
        let inserted = conn.execute(
            "INSERT INTO jobs(id, project_id, task_type, params, status, scope_revision_id,
                              scope_version, idempotency_key, created_by, created_at, result,
                              counters, chain_run_id, chain_order)
             VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?6, ?7, ?8, ?9, '{}', '{}', ?10, ?11)",
            params![
                job.id,
                job.project_id,
                job.task_type,
                job.params.to_string(),
                job.scope_revision_id,
                job.scope_version,
                job.idempotency_key,
                job.created_by,
                job.created_at,
                job.chain_run_id,
                job.chain_order
            ],
        );
        if let Err(err) = inserted {
            // A concurrent idempotent submission may have won the unique index.
            if idempotency_key.is_some() {
                let conn = self.connect().map_err(EnqueueError::Other)?;
                let existing = conn
                    .query_row(
                        &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE project_id = ?1 AND idempotency_key = ?2"),
                        params![project_id, idempotency_key],
                        map_job,
                    )
                    .optional()
                    .map_err(|err| EnqueueError::Other(anyhow::Error::from(err)))?;
                if let Some(existing) = existing {
                    if existing.task_type == task_type && existing.params == *params {
                        return Ok(existing);
                    }
                    return Err(EnqueueError::Conflict);
                }
            }
            return Err(EnqueueError::Other(anyhow::Error::from(err)));
        }
        self.audit(
            actor,
            "job.submit",
            "job",
            Some(&job.id),
            &json!({"task_type": job.task_type, "project": project.name, "chain": chain_run_id}),
        )
        .map_err(EnqueueError::Other)?;
        Ok(job)
    }

    pub fn job_by_id(&self, id: &str) -> Result<Option<Job>> {
        let conn = self.connect()?;
        let job = conn
            .query_row(
                &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
                params![id],
                map_job,
            )
            .optional()?;
        Ok(job)
    }

    pub fn job_by_idempotency(&self, project_id: &str, key: &str) -> Result<Option<Job>> {
        let conn = self.connect()?;
        let job = conn
            .query_row(
                &format!(
                    "SELECT {JOB_COLUMNS} FROM jobs WHERE project_id = ?1 AND idempotency_key = ?2"
                ),
                params![project_id, key],
                map_job,
            )
            .optional()?;
        Ok(job)
    }

    pub fn list_jobs(
        &self,
        project_id: Option<&str>,
        status: Option<JobStatus>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Job>, i64)> {
        let conn = self.connect()?;
        let status_value = status.map(JobStatus::as_str);
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE (?1 IS NULL OR project_id = ?1)
               AND (?2 IS NULL OR status = ?2)",
            params![project_id, status_value],
            |row| row.get(0),
        )?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {JOB_COLUMNS} FROM jobs
             WHERE (?1 IS NULL OR project_id = ?1) AND (?2 IS NULL OR status = ?2)
             ORDER BY created_at DESC LIMIT ?3 OFFSET ?4"
        ))?;
        let items = stmt
            .query_map(params![project_id, status_value, limit, offset], map_job)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((items, total))
    }

    pub fn queued_job_count(&self, project_id: Option<&str>) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')
               AND archived = 0 AND (?1 IS NULL OR project_id = ?1)",
            params![project_id],
            |row| row.get(0),
        )?)
    }

    pub fn claim_next_job(&self, worker_id: &str, lease_seconds: i64) -> Result<Option<Claim>> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Stage jobs wait until every earlier stage in the chain is terminal.
        let candidate: Option<String> = tx
            .query_row(
                "SELECT j.id FROM jobs j
                 WHERE j.status = 'queued' AND j.archived = 0
                   AND (j.chain_run_id IS NULL OR NOT EXISTS (
                       SELECT 1 FROM jobs p
                       WHERE p.chain_run_id = j.chain_run_id
                         AND p.chain_order < j.chain_order
                         AND p.status IN ('queued','running')
                   ))
                 ORDER BY j.created_at, j.id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(job_id) = candidate else {
            tx.commit()?;
            return Ok(None);
        };
        let now = now_rfc3339();
        let lease_until = (chrono::Utc::now() + chrono::Duration::seconds(lease_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let attempt_id = new_id("att");
        let changed = tx.execute(
            "UPDATE jobs SET status = 'running', started_at = ?1, current_attempt_id = ?2,
                             cancel_requested = 0
             WHERE id = ?3 AND status = 'queued'",
            params![now, attempt_id, job_id],
        )?;
        if changed == 0 {
            tx.rollback()?;
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO job_attempts(id, job_id, worker_id, status, started_at, heartbeat_at, lease_until)
             VALUES (?1, ?2, ?3, 'running', ?4, ?4, ?5)",
            params![attempt_id, job_id, worker_id, now, lease_until],
        )?;
        let job = tx.query_row(
            &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
            params![job_id],
            map_job,
        )?;
        tx.commit()?;
        Ok(Some(Claim {
            job,
            attempt_id,
            worker_id: worker_id.to_string(),
            lease_until,
        }))
    }

    pub fn heartbeat(
        &self,
        job_id: &str,
        attempt_id: &str,
        lease_seconds: i64,
    ) -> Result<HeartbeatState> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        let lease_until = (chrono::Utc::now() + chrono::Duration::seconds(lease_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let changed = conn.execute(
            "UPDATE job_attempts SET heartbeat_at = ?1, lease_until = ?2
             WHERE id = ?3 AND status = 'running'
               AND EXISTS (SELECT 1 FROM jobs WHERE id = ?4 AND status = 'running'
                           AND current_attempt_id = ?3)",
            params![now, lease_until, attempt_id, job_id],
        )?;
        if changed == 0 {
            return Ok(HeartbeatState {
                active: false,
                cancel_requested: false,
            });
        }
        let cancel: i64 = conn.query_row(
            "SELECT cancel_requested FROM jobs WHERE id = ?1",
            params![job_id],
            |row| row.get(0),
        )?;
        Ok(HeartbeatState {
            active: true,
            cancel_requested: cancel != 0,
        })
    }

    pub fn update_progress(
        &self,
        job_id: &str,
        attempt_id: &str,
        counters: &JobCounters,
    ) -> Result<bool> {
        let conn = self.connect()?;
        let changed = conn.execute(
            "UPDATE jobs SET counters = ?1
             WHERE id = ?2 AND status = 'running' AND current_attempt_id = ?3",
            params![serde_json::to_string(counters)?, job_id, attempt_id],
        )?;
        Ok(changed > 0)
    }

    pub fn complete_attempt(
        &self,
        job_id: &str,
        attempt_id: &str,
        outcome: CompleteOutcome,
    ) -> Result<bool> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owns: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM jobs WHERE id = ?1 AND status = 'running' AND current_attempt_id = ?2",
                params![job_id, attempt_id],
                |row| row.get(0),
            )
            .optional()?;
        if owns.is_none() {
            tx.rollback()?;
            return Ok(false);
        }
        let now = now_rfc3339();
        let project_id: String = tx.query_row(
            "SELECT project_id FROM jobs WHERE id = ?1",
            params![job_id],
            |row| row.get(0),
        )?;
        for observation in &outcome.observations {
            tx.execute(
                "INSERT INTO assets(id, project_id, kind, value, canonical_value, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(project_id, kind, canonical_value)
                 DO UPDATE SET last_seen = excluded.last_seen",
                params![
                    new_id("ast"),
                    project_id,
                    observation.asset_kind,
                    observation.asset,
                    observation.canonical_asset,
                    now
                ],
            )?;
            let asset_id: String = tx.query_row(
                "SELECT id FROM assets WHERE project_id = ?1 AND kind = ?2 AND canonical_value = ?3",
                params![project_id, observation.asset_kind, observation.canonical_asset],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT INTO observations(id, project_id, job_id, attempt_id, asset_id, source, kind,
                                          asset, canonical_asset, data, scope_status, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    new_id("obs"),
                    project_id,
                    job_id,
                    attempt_id,
                    asset_id,
                    observation.source,
                    observation.kind,
                    observation.asset,
                    observation.canonical_asset,
                    observation.data.to_string(),
                    observation.scope_status,
                    now
                ],
            )?;
        }
        for finding in &outcome.findings {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT id FROM findings WHERE project_id = ?1 AND rule_id = ?2 AND asset = ?3
                     AND rule_version = ?4",
                    params![
                        project_id,
                        finding.rule_id,
                        finding.asset,
                        finding.rule_version
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                tx.execute(
                    "UPDATE findings SET severity = ?1, title = ?2, evidence = ?3, source = ?4,
                                         last_seen = ?5, job_id = ?6
                     WHERE id = ?7",
                    params![
                        finding.severity,
                        finding.title,
                        finding.evidence.to_string(),
                        finding.source,
                        now,
                        job_id,
                        id
                    ],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO findings(id, project_id, job_id, rule_id, rule_version, severity,
                                          title, asset, evidence, source, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                    params![
                        new_id("fnd"),
                        project_id,
                        job_id,
                        finding.rule_id,
                        finding.rule_version,
                        finding.severity,
                        finding.title,
                        finding.asset,
                        finding.evidence.to_string(),
                        finding.source,
                        now
                    ],
                )?;
            }
        }
        for artifact in &outcome.artifacts {
            tx.execute(
                "INSERT INTO artifacts(id, project_id, job_id, attempt_id, relative_path, kind, size, sha256, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(project_id, relative_path) DO UPDATE SET
                     job_id = excluded.job_id, attempt_id = excluded.attempt_id,
                     size = excluded.size, sha256 = excluded.sha256, created_at = excluded.created_at",
                params![
                    new_id("art"),
                    project_id,
                    job_id,
                    attempt_id,
                    artifact.relative_path,
                    artifact.kind,
                    artifact.size as i64,
                    artifact.sha256,
                    now
                ],
            )?;
        }
        tx.execute(
            "UPDATE jobs SET status = ?1, finished_at = ?2, error = ?3, result = ?4,
                             counters = ?5, current_attempt_id = NULL, cancel_requested = 0
             WHERE id = ?6",
            params![
                outcome.status.as_str(),
                now,
                outcome.error,
                outcome.result.to_string(),
                serde_json::to_string(&outcome.counters)?,
                job_id
            ],
        )?;
        tx.execute(
            "UPDATE job_attempts SET status = ?1, finished_at = ?2, error = ?3
             WHERE id = ?4",
            params![outcome.status.as_str(), now, outcome.error, attempt_id],
        )?;
        tx.commit()?;
        if let Some(job) = self.job_by_id(job_id)? {
            if let Some(run_id) = job.chain_run_id {
                self.refresh_chain_status(&run_id)?;
            }
        }
        Ok(true)
    }

    pub fn cancel_job(&self, job_id: &str, actor: &str) -> Result<Option<Job>> {
        let Some(job) = self.job_by_id(job_id)? else {
            return Ok(None);
        };
        if job.status.is_terminal() {
            return Ok(Some(job));
        }
        let conn = self.connect()?;
        let now = now_rfc3339();
        if job.status == JobStatus::Queued {
            conn.execute(
                "UPDATE jobs SET status = 'cancelled', finished_at = ?1, cancel_requested = 0,
                                 error = 'cancelled before start'
                 WHERE id = ?2 AND status = 'queued'",
                params![now, job_id],
            )?;
        } else {
            conn.execute(
                "UPDATE jobs SET cancel_requested = 1 WHERE id = ?1 AND status = 'running'",
                params![job_id],
            )?;
        }
        self.audit(
            actor,
            "job.cancel",
            "job",
            Some(job_id),
            &json!({"previous_status": job.status.as_str()}),
        )?;
        if let Some(run_id) = job.chain_run_id {
            self.refresh_chain_status(&run_id)?;
        }
        self.job_by_id(job_id)
    }

    pub fn cancel_chain(&self, run_id: &str, actor: &str) -> Result<()> {
        let jobs = self.chain_jobs(run_id)?;
        for job in jobs {
            if !job.status.is_terminal() {
                self.cancel_job(&job.id, actor)?;
            }
        }
        let conn = self.connect()?;
        conn.execute(
            "UPDATE chain_runs SET status = 'cancelled', finished_at = ?1 WHERE id = ?2",
            params![now_rfc3339(), run_id],
        )?;
        Ok(())
    }

    pub fn interrupt_expired_attempts(&self) -> Result<u64> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_rfc3339();
        let expired: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT j.id, a.id FROM jobs j JOIN job_attempts a ON a.id = j.current_attempt_id
                 WHERE j.status = 'running' AND a.lease_until < ?1",
            )?;
            let rows = stmt
                .query_map(params![now], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for (job_id, attempt_id) in &expired {
            tx.execute(
                "UPDATE jobs SET status = 'interrupted', finished_at = ?1, current_attempt_id = NULL,
                                 error = 'worker lease expired; explicit restart required'
                 WHERE id = ?2",
                params![now, job_id],
            )?;
            tx.execute(
                "UPDATE job_attempts SET status = 'interrupted', finished_at = ?1,
                        error = 'worker lease expired'
                 WHERE id = ?2",
                params![now, attempt_id],
            )?;
        }
        tx.commit()?;
        Ok(expired.len() as u64)
    }

    pub fn recent_observations(
        &self,
        project_id: &str,
        kind: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Observation>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, attempt_id, source, kind, asset, canonical_asset,
                    data, scope_status, observed_at
             FROM observations
             WHERE project_id = ?1 AND (?2 IS NULL OR kind = ?2)
             ORDER BY observed_at DESC LIMIT ?3",
        )?;
        let items = stmt
            .query_map(params![project_id, kind, limit], |row| {
                Ok(Observation {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    attempt_id: row.get(3)?,
                    source: row.get(4)?,
                    kind: row.get(5)?,
                    asset: row.get(6)?,
                    canonical_asset: row.get(7)?,
                    data: json_or_empty(row.get(8)?),
                    scope_status: row.get(9)?,
                    observed_at: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn all_observations(&self, project_id: &str, limit: u32) -> Result<Vec<Observation>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, attempt_id, source, kind, asset, canonical_asset,
                    data, scope_status, observed_at
             FROM observations WHERE project_id = ?1
             ORDER BY observed_at DESC, id LIMIT ?2",
        )?;
        let items = stmt
            .query_map(params![project_id, limit], |row| {
                Ok(Observation {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    attempt_id: row.get(3)?,
                    source: row.get(4)?,
                    kind: row.get(5)?,
                    asset: row.get(6)?,
                    canonical_asset: row.get(7)?,
                    data: json_or_empty(row.get(8)?),
                    scope_status: row.get(9)?,
                    observed_at: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn list_assets(&self, project_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, value, canonical_value, first_seen, last_seen
             FROM assets WHERE project_id = ?1 ORDER BY kind, canonical_value LIMIT ?2",
        )?;
        let items = stmt
            .query_map(params![project_id, limit], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "kind": row.get::<_, String>(1)?,
                    "value": row.get::<_, String>(2)?,
                    "canonical_value": row.get::<_, String>(3)?,
                    "first_seen": row.get::<_, String>(4)?,
                    "last_seen": row.get::<_, String>(5)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn all_findings(&self, project_id: &str) -> Result<Vec<Finding>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, rule_id, rule_version, severity, title, asset,
                    evidence, source, first_seen, last_seen
             FROM findings WHERE project_id = ?1 ORDER BY last_seen DESC",
        )?;
        let items = stmt
            .query_map(params![project_id], |row| {
                Ok(Finding {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    rule_id: row.get(3)?,
                    rule_version: row.get(4)?,
                    severity: row.get(5)?,
                    title: row.get(6)?,
                    asset: row.get(7)?,
                    evidence: json_or_empty(row.get(8)?),
                    source: row.get(9)?,
                    first_seen: row.get(10)?,
                    last_seen: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn list_findings(&self, project_id: &str, limit: u32) -> Result<Vec<Finding>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, rule_id, rule_version, severity, title, asset,
                    evidence, source, first_seen, last_seen
             FROM findings WHERE project_id = ?1
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC
             LIMIT ?2",
        )?;
        let items = stmt
            .query_map(params![project_id, limit], |row| {
                Ok(Finding {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    rule_id: row.get(3)?,
                    rule_version: row.get(4)?,
                    severity: row.get(5)?,
                    title: row.get(6)?,
                    asset: row.get(7)?,
                    evidence: json_or_empty(row.get(8)?),
                    source: row.get(9)?,
                    first_seen: row.get(10)?,
                    last_seen: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn artifact_by_id(&self, id: &str) -> Result<Option<Artifact>> {
        let conn = self.connect()?;
        let item = conn
            .query_row(
                "SELECT id, project_id, job_id, attempt_id, relative_path, kind, size, sha256, created_at
                 FROM artifacts WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Artifact {
                        id: row.get(0)?,
                        project_id: row.get(1)?,
                        job_id: row.get(2)?,
                        attempt_id: row.get(3)?,
                        relative_path: row.get(4)?,
                        kind: row.get(5)?,
                        size: row.get::<_, i64>(6)? as u64,
                        sha256: row.get(7)?,
                        created_at: row.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(item)
    }

    pub fn list_artifacts(&self, job_id: &str) -> Result<Vec<Artifact>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, attempt_id, relative_path, kind, size, sha256, created_at
             FROM artifacts WHERE job_id = ?1 ORDER BY created_at",
        )?;
        let items = stmt
            .query_map(params![job_id], |row| {
                Ok(Artifact {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    attempt_id: row.get(3)?,
                    relative_path: row.get(4)?,
                    kind: row.get(5)?,
                    size: row.get::<_, i64>(6)? as u64,
                    sha256: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn observations_for_job(&self, job_id: &str) -> Result<Vec<Observation>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, job_id, attempt_id, source, kind, asset, canonical_asset,
                    data, scope_status, observed_at
             FROM observations WHERE job_id = ?1 ORDER BY observed_at",
        )?;
        let items = stmt
            .query_map(params![job_id], |row| {
                Ok(Observation {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    job_id: row.get(2)?,
                    attempt_id: row.get(3)?,
                    source: row.get(4)?,
                    kind: row.get(5)?,
                    asset: row.get(6)?,
                    canonical_asset: row.get(7)?,
                    data: json_or_empty(row.get(8)?),
                    scope_status: row.get(9)?,
                    observed_at: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn create_chain_run(
        &self,
        project_id: &str,
        name: &str,
        idempotency_key: Option<&str>,
        actor: &str,
    ) -> Result<String> {
        let id = new_id("chn");
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO chain_runs(id, project_id, name, status, idempotency_key, created_by, created_at)
             VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6)",
            params![id, project_id, name, idempotency_key, actor, now_rfc3339()],
        )?;
        Ok(id)
    }

    pub fn chain_run_by_idempotency(&self, project_id: &str, key: &str) -> Result<Option<String>> {
        let conn = self.connect()?;
        let id = conn
            .query_row(
                "SELECT id FROM chain_runs WHERE project_id = ?1 AND idempotency_key = ?2",
                params![project_id, key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_chain_stage(
        &self,
        run_id: &str,
        position: i64,
        task_type: &str,
        input_from: Option<&str>,
        required: bool,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO chain_stages(id, chain_run_id, position, task_type, input_from, required)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                new_id("chs"),
                run_id,
                position,
                task_type,
                input_from,
                i64::from(required)
            ],
        )?;
        Ok(())
    }

    pub fn set_chain_stage_job(&self, run_id: &str, position: i64, job_id: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE chain_stages SET job_id = ?1 WHERE chain_run_id = ?2 AND position = ?3",
            params![job_id, run_id, position],
        )?;
        Ok(())
    }

    pub fn skip_chain_stage(&self, run_id: &str, position: i64, reason: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE chain_stages SET skipped_reason = ?1 WHERE chain_run_id = ?2 AND position = ?3",
            params![reason, run_id, position],
        )?;
        Ok(())
    }

    pub fn chain_jobs(&self, run_id: &str) -> Result<Vec<Job>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {JOB_COLUMNS} FROM jobs WHERE chain_run_id = ?1 ORDER BY chain_order"
        ))?;
        let items = stmt
            .query_map(params![run_id], map_job)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn chain_run_json(&self, run_id: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        let base = conn
            .query_row(
                "SELECT id, project_id, name, status, created_by, created_at, finished_at
                 FROM chain_runs WHERE id = ?1",
                params![run_id],
                |row| {
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "project_id": row.get::<_, String>(1)?,
                        "name": row.get::<_, String>(2)?,
                        "status": row.get::<_, String>(3)?,
                        "created_by": row.get::<_, String>(4)?,
                        "created_at": row.get::<_, String>(5)?,
                        "finished_at": row.get::<_, Option<String>>(6)?,
                    }))
                },
            )
            .optional()?;
        let Some(mut base) = base else {
            return Ok(None);
        };
        let mut stmt = conn.prepare(
            "SELECT id, position, task_type, job_id, input_from, required, skipped_reason
             FROM chain_stages WHERE chain_run_id = ?1 ORDER BY position",
        )?;
        let stages = stmt
            .query_map(params![run_id], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "position": row.get::<_, i64>(1)?,
                    "task_type": row.get::<_, String>(2)?,
                    "job_id": row.get::<_, Option<String>>(3)?,
                    "input_from": row.get::<_, Option<String>>(4)?,
                    "required": row.get::<_, i64>(5)? != 0,
                    "skipped_reason": row.get::<_, Option<String>>(6)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        base["stages"] = Value::Array(stages);
        Ok(Some(base))
    }

    pub fn refresh_chain_status(&self, run_id: &str) -> Result<()> {
        let jobs = self.chain_jobs(run_id)?;
        if jobs.is_empty() {
            return Ok(());
        }
        let all_terminal = jobs.iter().all(|job| job.status.is_terminal());
        if !all_terminal {
            return Ok(());
        }
        let any_incomplete = jobs.iter().any(|job| {
            matches!(
                job.status,
                JobStatus::Failed
                    | JobStatus::Interrupted
                    | JobStatus::Cancelled
                    | JobStatus::Partial
            )
        });
        let status = if any_incomplete {
            "partial"
        } else {
            "succeeded"
        };
        let conn = self.connect()?;
        conn.execute(
            "UPDATE chain_runs SET status = ?1, finished_at = ?2 WHERE id = ?3 AND status != 'cancelled'",
            params![status, now_rfc3339(), run_id],
        )?;
        Ok(())
    }

    pub fn previous_chain_job(&self, run_id: &str, position: i64) -> Result<Option<Job>> {
        let conn = self.connect()?;
        let job = conn
            .query_row(
                &format!(
                    "SELECT {JOB_COLUMNS} FROM jobs WHERE chain_run_id = ?1 AND chain_order < ?2
                     ORDER BY chain_order DESC LIMIT 1"
                ),
                params![run_id, position],
                map_job,
            )
            .optional()?;
        Ok(job)
    }

    pub fn project_observation_counts(&self, project_id: &str) -> Result<Value> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT kind, COUNT(*) FROM observations WHERE project_id = ?1 GROUP BY kind",
        )?;
        let mut map = serde_json::Map::new();
        let rows = stmt.query_map(params![project_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (kind, count) = row?;
            map.insert(kind, json!(count));
        }
        Ok(Value::Object(map))
    }

    pub fn project_job_history(&self, project_id: &str, limit: u32) -> Result<Vec<Job>> {
        let (jobs, _) = self.list_jobs(Some(project_id), None, limit, 0)?;
        Ok(jobs)
    }

    pub fn register_worker(&self, worker_id: &str) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO workers(id, status, started_at, heartbeat_at)
             VALUES (?1, 'running', ?2, ?2)
             ON CONFLICT(id) DO UPDATE SET status = 'running', heartbeat_at = ?2, stopped_at = NULL",
            params![worker_id, now],
        )?;
        Ok(())
    }

    pub fn worker_heartbeat(&self, worker_id: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE workers SET status = 'running', heartbeat_at = ?1 WHERE id = ?2",
            params![now_rfc3339(), worker_id],
        )?;
        Ok(())
    }

    pub fn stop_worker(&self, worker_id: &str) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        conn.execute(
            "UPDATE workers SET status = 'stopped', stopped_at = ?1, heartbeat_at = ?1 WHERE id = ?2",
            params![now, worker_id],
        )?;
        Ok(())
    }

    pub fn worker_health(&self, stale_after_seconds: i64) -> Result<Value> {
        let conn = self.connect()?;
        let latest: Option<(String, String, String)> = conn
            .query_row(
                "SELECT id, status, heartbeat_at FROM workers ORDER BY heartbeat_at DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();
        let Some((id, status, heartbeat_at)) = latest else {
            return Ok(json!({"state": "unknown", "reason": "no worker has registered"}));
        };
        let stale_cutoff = (chrono::Utc::now()
            - chrono::Duration::seconds(stale_after_seconds.max(10)))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let state = if status == "running" && heartbeat_at >= stale_cutoff {
            "ready"
        } else if status == "running" {
            "stale"
        } else {
            "stopped"
        };
        let queued = self.queued_job_count(None).unwrap_or(0);
        Ok(json!({
            "state": state,
            "worker_id": id,
            "status": status,
            "last_heartbeat": heartbeat_at,
            "queued_or_running_jobs": queued,
            "stale_after_seconds": stale_after_seconds.max(10)
        }))
    }
}
