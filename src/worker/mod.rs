//! Queue worker with leases, heartbeats, cancellation and atomic publication.

use crate::config::Config;
use crate::db::jobs::{CompleteOutcome, HeartbeatState, NewArtifact};
use crate::db::Db;
use crate::domain::{new_id, Job, JobCounters, JobStatus};
use crate::scope::{EffectiveScope, Scope};
use crate::tasks::{self, TaskCancelled, TaskContext, TaskOutcome};
use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct Worker {
    pub config: Config,
    pub db: Db,
    pub worker_id: String,
}

impl Worker {
    pub fn new(config: Config, db: Db) -> Self {
        let worker_id = format!(
            "{}-{}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| "host".to_string()),
            new_id("wrk")
        );
        Self {
            config,
            db,
            worker_id,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let shutdown = Arc::new(AtomicBool::new(false));
        {
            let flag = shutdown.clone();
            tokio::spawn(async move {
                crate::wait_for_shutdown_signal().await;
                tracing::info!("worker shutdown signal received");
                flag.store(true, Ordering::SeqCst);
            });
        }
        self.run_until_shutdown(shutdown).await
    }

    /// Run independent jobs in bounded parallel slots; chain dependencies are
    /// enforced atomically by claim_next_job. Drain active jobs on shutdown.
    pub async fn run_until_shutdown(&self, shutdown: Arc<AtomicBool>) -> Result<()> {
        anyhow::ensure!(
            self.config.max_concurrent_jobs > 0,
            "max_concurrent_jobs must be at least 1"
        );
        self.cleanup_stale_files();
        self.cleanup_orphaned_evidence();
        if let Ok(count) = self.db.interrupt_expired_attempts() {
            if count > 0 {
                tracing::warn!(count, "expired job leases were marked interrupted");
            }
        }
        self.db.register_worker(&self.worker_id)?;
        tracing::info!(worker = %self.worker_id, slots = self.config.max_concurrent_jobs, "worker started");
        let mut active = tokio::task::JoinSet::new();
        let mut poll =
            tokio::time::interval(Duration::from_millis(self.config.worker_poll_ms.max(1)));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut result = async {
            while !shutdown.load(Ordering::SeqCst) {
                while active.len() < self.config.max_concurrent_jobs as usize
                    && !shutdown.load(Ordering::SeqCst)
                {
                    let Some(claim) = self
                        .db
                        .claim_next_job(&self.worker_id, self.config.worker_lease_seconds)?
                    else {
                        break;
                    };
                    tracing::info!(job = %claim.job.id, task = %claim.job.task_type, "job claimed");
                    let worker = self.clone();
                    let shutdown = shutdown.clone();
                    active.spawn(async move {
                        worker
                            .run_claimed(claim.job, claim.attempt_id, shutdown)
                            .await
                    });
                }
                tokio::select! {
                    completed = active.join_next(), if !active.is_empty() => {
                        if let Some(completed) = completed {
                            completed.context("job execution panicked")??;
                        }
                    }
                    _ = poll.tick() => self.db.worker_heartbeat(&self.worker_id)?,
                    _ = wait_for_shutdown(shutdown.clone()) => {}
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            shutdown.store(true, Ordering::SeqCst);
        }
        while let Some(completed) = active.join_next().await {
            if let Err(error) = completed
                .context("job execution panicked")
                .and_then(|value| value)
            {
                if result.is_ok() {
                    result = Err(error);
                }
            }
        }
        let _ = self.db.stop_worker(&self.worker_id);
        tracing::info!("worker stopped");
        result
    }

    pub async fn run_claimed(
        &self,
        job: Job,
        attempt_id: String,
        shutdown: Arc<AtomicBool>,
    ) -> Result<()> {
        let cancel = Arc::new(AtomicBool::new(false));
        if let Some(run_id) = &job.chain_run_id {
            if let Some(previous) = self
                .db
                .previous_chain_job(run_id, job.chain_order.unwrap_or(0))?
            {
                if matches!(
                    previous.status,
                    JobStatus::Failed | JobStatus::Cancelled | JobStatus::Interrupted
                ) {
                    let reason = format!(
                        "skipped: previous chain stage {} ended with {}",
                        previous.id,
                        previous.status.as_str()
                    );
                    self.db
                        .skip_chain_stage(run_id, job.chain_order.unwrap_or(0), &reason)?;
                    let outcome = CompleteOutcome {
                        status: JobStatus::Cancelled,
                        result: serde_json::json!({"skipped": true, "reason": reason}),
                        counters: JobCounters::default(),
                        error: Some(reason),
                        observations: Vec::new(),
                        findings: Vec::new(),
                        artifacts: Vec::new(),
                    };
                    let _ = self.db.complete_attempt(&job.id, &attempt_id, outcome)?;
                    return Ok(());
                }
            }
        }
        let snapshot_revision = self.db.scope_by_id(&job.scope_revision_id)?;
        let current_revision = self.db.current_scope(&job.project_id)?;
        let (Some(snapshot_revision), Some(current_revision)) =
            (snapshot_revision, current_revision)
        else {
            let outcome = CompleteOutcome {
                status: JobStatus::Failed,
                result: serde_json::json!({}),
                counters: JobCounters::default(),
                error: Some("job scope snapshot is missing or project scope was deleted".into()),
                observations: Vec::new(),
                findings: Vec::new(),
                artifacts: Vec::new(),
            };
            self.db.complete_attempt(&job.id, &attempt_id, outcome)?;
            return Ok(());
        };
        let effective = EffectiveScope::new(snapshot_revision.scope, current_revision.scope);
        let heartbeat = spawn_heartbeat(
            self.db.clone(),
            self.worker_id.clone(),
            job.id.clone(),
            attempt_id.clone(),
            self.config.worker_lease_seconds,
            cancel.clone(),
            shutdown.clone(),
        );
        let ctx = TaskContext {
            db: self.db.clone(),
            config: self.config.clone(),
            project_id: job.project_id.clone(),
            job_id: job.id.clone(),
            attempt_id: attempt_id.clone(),
            scope: effective,
            cancel: cancel.clone(),
            previous_job: if let Some(run_id) = &job.chain_run_id {
                self.db
                    .previous_chain_job(run_id, job.chain_order.unwrap_or(0))?
            } else {
                None
            },
        };
        let mut result = tasks::execute(&job, &ctx).await;
        let was_cancelled = cancel.load(Ordering::SeqCst) || shutdown.load(Ordering::SeqCst);
        if was_cancelled {
            result = Err(anyhow::Error::new(TaskCancelled));
        }
        cancel.store(true, Ordering::SeqCst);
        heartbeat.abort();
        let _ = heartbeat.await;
        match result {
            Ok(outcome) => match self.prepare_outcome(&job, &attempt_id, outcome).await {
                Ok(outcome) => {
                    let published = self.db.complete_attempt(&job.id, &attempt_id, outcome)?;
                    if !published {
                        self.remove_unindexed_artifacts(&job);
                    }
                }
                Err(err) => {
                    let outcome = CompleteOutcome {
                        status: JobStatus::Failed,
                        result: serde_json::json!({"artifact_error": true}),
                        counters: JobCounters::default(),
                        error: Some(format!("artifact publication failed: {err:#}")),
                        observations: Vec::new(),
                        findings: Vec::new(),
                        artifacts: Vec::new(),
                    };
                    let _ = self.db.complete_attempt(&job.id, &attempt_id, outcome)?;
                }
            },
            Err(err) => {
                let cancelled = err.downcast_ref::<TaskCancelled>().is_some() || was_cancelled;
                let (status, message) = if cancelled {
                    (
                        JobStatus::Cancelled,
                        "cancelled by operator or worker shutdown".to_string(),
                    )
                } else {
                    (JobStatus::Failed, format!("{err:#}"))
                };
                let outcome = CompleteOutcome {
                    status,
                    result: serde_json::json!({"cancelled": cancelled}),
                    counters: JobCounters::default(),
                    error: Some(message),
                    observations: Vec::new(),
                    findings: Vec::new(),
                    artifacts: Vec::new(),
                };
                let _ = self.db.complete_attempt(&job.id, &attempt_id, outcome)?;
            }
        }
        Ok(())
    }

    async fn prepare_outcome(
        &self,
        job: &Job,
        attempt_id: &str,
        mut outcome: TaskOutcome,
    ) -> Result<CompleteOutcome> {
        let mut artifacts = Vec::new();
        let total_size: u64 = outcome
            .artifacts
            .iter()
            .map(|artifact| artifact.content.len() as u64)
            .sum();
        if total_size > self.config.max_artifact_bytes {
            anyhow::bail!(
                "artifact set is {} bytes, exceeding the configured {} byte limit",
                total_size,
                self.config.max_artifact_bytes
            );
        }
        for artifact in outcome.artifacts.drain(..) {
            let filename = sanitize_filename(&artifact.filename);
            let relative = format!("projects/{}/jobs/{}/{}", job.project_id, job.id, filename);
            let target = self.config.evidence_dir().join(&relative);
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let tmp = self.config.tmp_dir().join(format!(
                "{}-{}",
                attempt_id,
                sanitize_filename(&filename)
            ));
            if let Some(parent) = tmp.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            {
                use tokio::io::AsyncWriteExt;
                let mut file = tokio::fs::File::create(&tmp).await?;
                file.write_all(&artifact.content).await?;
                file.sync_all().await?;
            }
            tokio::fs::rename(&tmp, &target).await?;
            if let Some(parent) = target.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            let digest = Sha256::digest(&artifact.content);
            artifacts.push(NewArtifact {
                relative_path: relative,
                kind: artifact.kind,
                size: artifact.content.len() as u64,
                sha256: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
            });
        }
        Ok(CompleteOutcome {
            status: outcome.status,
            result: outcome.result,
            counters: outcome.counters,
            error: outcome.error,
            observations: outcome.observations,
            findings: outcome.findings,
            artifacts,
        })
    }

    fn remove_unindexed_artifacts(&self, job: &Job) {
        let dir = self
            .config
            .evidence_dir()
            .join("projects")
            .join(&job.project_id)
            .join("jobs")
            .join(&job.id);
        let _ = std::fs::remove_dir_all(dir);
    }

    pub fn cleanup_stale_files(&self) {
        let Ok(entries) = std::fs::read_dir(self.config.tmp_dir()) else {
            return;
        };
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(86_400);
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.modified().ok().is_some_and(|value| value < cutoff) {
                if metadata.is_dir() {
                    let _ = std::fs::remove_dir_all(entry.path());
                } else {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    /// Remove only files under the evidence root that have no index row and are
    /// older than the safety window. Indexed artifacts and imported originals
    /// are never touched; retention remains an explicit operator decision.
    pub fn cleanup_orphaned_evidence(&self) {
        let Ok(conn) = self.db.connect() else {
            return;
        };
        let Ok(mut stmt) = conn.prepare("SELECT relative_path FROM artifacts") else {
            return;
        };
        let indexed: std::collections::HashSet<String> =
            match stmt.query_map([], |row| row.get::<_, String>(0)) {
                Ok(rows) => rows.flatten().collect(),
                Err(_) => return,
            };
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(86_400);
        let mut stack = vec![self.config.evidence_dir()];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if metadata.is_dir() {
                    stack.push(path);
                    continue;
                }
                let Ok(relative) = path.strip_prefix(self.config.evidence_dir()) else {
                    continue;
                };
                let relative = relative.to_string_lossy().replace('\\', "/");
                if indexed.contains(&relative) {
                    continue;
                }
                if metadata.modified().ok().is_some_and(|value| value < cutoff) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    pub fn evidence_path(&self, relative: &str) -> Result<PathBuf> {
        let normalized = normalize_relative_path(relative)?;
        Ok(self.config.evidence_dir().join(normalized))
    }
}

fn spawn_heartbeat(
    db: Db,
    worker_id: String,
    job_id: String,
    attempt_id: String,
    lease_seconds: i64,
    cancel: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_secs((lease_seconds.max(3) as u64) / 3);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = wait_for_shutdown(shutdown.clone()) => {
                    cancel.store(true, Ordering::SeqCst);
                    break;
                }
            }
            let _ = db.worker_heartbeat(&worker_id);
            if shutdown.load(Ordering::SeqCst) {
                cancel.store(true, Ordering::SeqCst);
            }
            match db.heartbeat(&job_id, &attempt_id, lease_seconds) {
                Ok(HeartbeatState { active: false, .. }) => {
                    cancel.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(HeartbeatState {
                    cancel_requested: true,
                    ..
                }) => {
                    cancel.store(true, Ordering::SeqCst);
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(job = %job_id, error = %err, "heartbeat failed");
                }
            }
            if cancel.load(Ordering::SeqCst) {
                break;
            }
        }
    })
}

async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub fn sanitize_filename(value: &str) -> String {
    let base = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    base.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(180)
        .collect()
}

pub fn normalize_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("artifact path must be a relative path without '..'");
    }
    if value.trim().is_empty() {
        anyhow::bail!("artifact path is empty");
    }
    Ok(path.to_path_buf())
}

pub fn parse_scope_json(value: &serde_json::Value) -> Result<Scope> {
    Scope::from_json(value).context("invalid scope snapshot")
}
