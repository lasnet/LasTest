mod support;

use lastest::db::jobs::{CompleteOutcome, EnqueueError, NewArtifact, NewFinding, NewObservation};
use lastest::domain::{JobCounters, JobStatus};
use lastest::worker::Worker;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use support::{scope_rules, spawn_http_server, HttpResponse, TestEnv};

fn setup_job(
    env: &TestEnv,
    task: &str,
    params: serde_json::Value,
    key: &str,
) -> (String, String, i64) {
    let (_, revision) = env.project_with_scope(
        &format!("queue-{key}"),
        scope_rules(&[("exact", "localhost"), ("ip", "127.0.0.1")]),
        true,
    );
    let project = env
        .db
        .project_by_name(&format!("queue-{key}"))
        .unwrap()
        .unwrap();
    let job = env
        .db
        .enqueue_job(
            &project.id,
            task,
            &params,
            &revision.id,
            revision.version,
            Some(key),
            "admin",
            None,
            None,
        )
        .unwrap();
    (job.id, revision.id, revision.version)
}

#[tokio::test]
async fn idempotency_replays_same_id_and_rejects_conflicts() {
    let env = TestEnv::new();
    let (_, revision) =
        env.project_with_scope("idem", scope_rules(&[("tree", "example.com")]), true);
    let project = env.db.project_by_name("idem").unwrap().unwrap();
    let params = json!({"targets": ["example.com"]});
    let first = env
        .db
        .enqueue_job(
            &project.id,
            "dns.records",
            &params,
            &revision.id,
            revision.version,
            Some("request-1"),
            "admin",
            None,
            None,
        )
        .unwrap();
    let second = env
        .db
        .enqueue_job(
            &project.id,
            "dns.records",
            &params,
            &revision.id,
            revision.version,
            Some("request-1"),
            "admin",
            None,
            None,
        )
        .unwrap();
    assert_eq!(first.id, second.id);
    let conflict = env.db.enqueue_job(
        &project.id,
        "dns.records",
        &json!({"targets": ["other.example.com"]}),
        &revision.id,
        revision.version,
        Some("request-1"),
        "admin",
        None,
        None,
    );
    assert!(matches!(conflict, Err(EnqueueError::Conflict)));
}

#[tokio::test]
async fn two_workers_cannot_claim_the_same_job() {
    let env = TestEnv::new();
    let (job_id, _, _) = setup_job(&env, "dns.records", json!({"targets": []}), "claim");
    let first = env.db.claim_next_job("worker-a", 30).unwrap().unwrap();
    assert_eq!(first.job.id, job_id);
    let second = env.db.claim_next_job("worker-b", 30).unwrap();
    assert!(second.is_none());
    let state = env
        .db
        .heartbeat(&first.job.id, &first.attempt_id, 30)
        .unwrap();
    assert!(state.active);
    assert!(!state.cancel_requested);
}

#[tokio::test]
async fn queued_and_running_cancellation() {
    let env = TestEnv::new();
    let (queued_id, _, _) = setup_job(&env, "dns.records", json!({"targets": []}), "cancel-q");
    let cancelled = env.db.cancel_job(&queued_id, "admin").unwrap().unwrap();
    assert_eq!(cancelled.status, JobStatus::Cancelled);
    assert!(env.db.claim_next_job("worker", 30).unwrap().is_none());

    let (running_id, _, _) = setup_job(&env, "dns.records", json!({"targets": []}), "cancel-r");
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    assert_eq!(claim.job.id, running_id);
    let requested = env.db.cancel_job(&running_id, "admin").unwrap().unwrap();
    assert_eq!(requested.status, JobStatus::Running);
    let state = env
        .db
        .heartbeat(&running_id, &claim.attempt_id, 30)
        .unwrap();
    assert!(state.cancel_requested);
    let outcome = CompleteOutcome {
        status: JobStatus::Cancelled,
        result: json!({"cancelled": true}),
        counters: JobCounters::default(),
        error: Some("cancelled".to_string()),
        observations: Vec::new(),
        findings: Vec::new(),
        artifacts: Vec::new(),
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    assert!(env
        .db
        .complete_attempt(&running_id, &claim.attempt_id, outcome)
        .unwrap());
    let job = env.db.job_by_id(&running_id).unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Cancelled);
}

#[tokio::test]
async fn expired_lease_interrupts_and_stale_attempt_cannot_publish() {
    let env = TestEnv::new();
    let (job_id, _, _) = setup_job(&env, "dns.records", json!({"targets": []}), "stale");
    let claim = env.db.claim_next_job("worker-a", 30).unwrap().unwrap();
    let conn = env.db.connect().unwrap();
    conn.execute(
        "UPDATE job_attempts SET lease_until = '2000-01-01T00:00:00Z' WHERE id = ?1",
        [&claim.attempt_id],
    )
    .unwrap();
    drop(conn);
    assert_eq!(env.db.interrupt_expired_attempts().unwrap(), 1);
    let job = env.db.job_by_id(&job_id).unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Interrupted);
    let outcome = CompleteOutcome {
        status: JobStatus::Succeeded,
        result: json!({"late": true}),
        counters: JobCounters::default(),
        error: None,
        observations: vec![NewObservation {
            source: "late".to_string(),
            kind: "host".to_string(),
            asset_kind: "host".to_string(),
            asset: "late.example.com".to_string(),
            canonical_asset: "late.example.com".to_string(),
            data: json!({}),
            scope_status: "observed".to_string(),
        }],
        findings: Vec::new(),
        artifacts: Vec::new(),
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    assert!(!env
        .db
        .complete_attempt(&job_id, &claim.attempt_id, outcome)
        .unwrap());
    assert!(env
        .db
        .recent_observations(&job.project_id, None, 10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn publication_is_atomic_and_indexed() {
    let env = TestEnv::new();
    let (job_id, _, _) = setup_job(&env, "dns.records", json!({"targets": []}), "publish");
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    let outcome = CompleteOutcome {
        status: JobStatus::Partial,
        result: json!({"records": 1}),
        counters: JobCounters {
            targets: 1,
            processed: 1,
            skipped: 0,
            errors: 1,
        },
        error: Some("source partially unavailable".to_string()),
        observations: vec![NewObservation {
            source: "dns".to_string(),
            kind: "dns".to_string(),
            asset_kind: "host".to_string(),
            asset: "www.example.com".to_string(),
            canonical_asset: "www.example.com".to_string(),
            data: json!({"record_type": "A", "value": "203.0.113.9"}),
            scope_status: "allowed".to_string(),
        }],
        findings: vec![NewFinding {
            rule_id: "test.rule".to_string(),
            rule_version: 1,
            severity: "low".to_string(),
            title: "test".to_string(),
            asset: "www.example.com".to_string(),
            evidence: json!({}),
            source: "test".to_string(),
        }],
        artifacts: vec![NewArtifact {
            relative_path: "projects/test/job/result.json".to_string(),
            kind: "test".to_string(),
            size: 2,
            sha256: "digest".to_string(),
        }],
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    assert!(env
        .db
        .complete_attempt(&job_id, &claim.attempt_id, outcome)
        .unwrap());
    let job = env.db.job_by_id(&job_id).unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Partial);
    assert_eq!(job.counters.processed, 1);
    let observations = env.db.observations_for_job(&job_id).unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(env.db.list_findings(&job.project_id, 10).unwrap().len(), 1);
    assert_eq!(env.db.list_artifacts(&job_id).unwrap().len(), 1);
    // The attempt no longer owns the job.
    let duplicate = CompleteOutcome {
        status: JobStatus::Succeeded,
        result: json!({}),
        counters: JobCounters::default(),
        error: None,
        observations: Vec::new(),
        findings: Vec::new(),
        artifacts: Vec::new(),
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    assert!(!env
        .db
        .complete_attempt(&job_id, &claim.attempt_id, duplicate)
        .unwrap());
}

#[tokio::test]
async fn worker_runs_http_job_and_publishes_evidence() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| {
        HttpResponse::new(
            200,
            "<html><title>Local Stand</title><body>ok</body></html>",
        )
        .header("Server", "nginx/1.24.0")
    })
    .await;
    let (project, revision) =
        env.project_with_scope("worker-http", scope_rules(&[("exact", "localhost")]), true);
    let job = env
        .db
        .enqueue_job(
            &project.id,
            "http.probe",
            &json!({
                "targets": [format!("http://localhost:{}/", server.addr.port())],
                "mode": "url"
            }),
            &revision.id,
            revision.version,
            Some("http-job"),
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    let worker = Worker::new(env.config.clone(), env.db.clone());
    worker
        .run_claimed(
            claim.job,
            claim.attempt_id.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = env.db.job_by_id(&job.id).unwrap().unwrap();
    assert_eq!(
        finished.status,
        JobStatus::Succeeded,
        "{:?}",
        finished.error
    );
    let observations = env.db.observations_for_job(&job.id).unwrap();
    assert!(observations.iter().any(|item| item.kind == "http"));
    let artifacts = env.db.list_artifacts(&job.id).unwrap();
    assert_eq!(artifacts.len(), 1);
    let path = env.config.evidence_dir().join(&artifacts[0].relative_path);
    assert!(path.is_file());
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(report["format_version"], "1");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn worker_marks_partial_when_one_target_fails() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| HttpResponse::new(200, "ok")).await;
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let (project, revision) = env.project_with_scope(
        "worker-partial",
        scope_rules(&[("exact", "localhost")]),
        true,
    );
    let job = env
        .db
        .enqueue_job(
            &project.id,
            "http.probe",
            &json!({
                "targets": [
                    format!("http://localhost:{}/", server.addr.port()),
                    format!("http://localhost:{closed}/")
                ],
                "mode": "url"
            }),
            &revision.id,
            revision.version,
            Some("partial-job"),
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    Worker::new(env.config.clone(), env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = env.db.job_by_id(&job.id).unwrap().unwrap();
    assert_eq!(finished.status, JobStatus::Partial);
    let observations = env.db.observations_for_job(&job.id).unwrap();
    assert!(observations.iter().any(|item| item.kind == "http"));
    assert_eq!(
        observations
            .iter()
            .filter(|item| item.kind == "http")
            .count(),
        1
    );
}

#[tokio::test]
async fn artifact_size_limit_fails_job_cleanly() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| HttpResponse::new(200, "ok")).await;
    let (project, revision) = env.project_with_scope(
        "artifact-limit",
        scope_rules(&[("exact", "localhost")]),
        true,
    );
    let job = env
        .db
        .enqueue_job(
            &project.id,
            "http.probe",
            &json!({
                "targets": [format!("http://localhost:{}/", server.addr.port())],
                "mode": "url"
            }),
            &revision.id,
            revision.version,
            Some("artifact-job"),
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    let mut config = env.config.clone();
    config.max_artifact_bytes = 10;
    Worker::new(config, env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = env.db.job_by_id(&job.id).unwrap().unwrap();
    assert_eq!(finished.status, JobStatus::Failed);
    assert!(finished.error.unwrap().contains("artifact"));
    assert!(env.db.list_artifacts(&job.id).unwrap().is_empty());
}

#[tokio::test]
async fn chain_stage_is_skipped_after_failed_predecessor() {
    let env = TestEnv::new();
    let (project, revision) =
        env.project_with_scope("chain-skip", scope_rules(&[("tree", "example.com")]), true);
    let run_id = env
        .db
        .create_chain_run(&project.id, "All in one", None, "admin")
        .unwrap();
    env.db
        .add_chain_stage(&run_id, 1, "dns.records", None, true)
        .unwrap();
    env.db
        .add_chain_stage(&run_id, 2, "http.probe", None, true)
        .unwrap();
    let first = env
        .db
        .enqueue_job(
            &project.id,
            "dns.records",
            &json!({}),
            &revision.id,
            revision.version,
            None,
            "admin",
            Some(&run_id),
            Some(1),
        )
        .unwrap();
    let second = env
        .db
        .enqueue_job(
            &project.id,
            "http.probe",
            &json!({}),
            &revision.id,
            revision.version,
            None,
            "admin",
            Some(&run_id),
            Some(2),
        )
        .unwrap();
    env.db.set_chain_stage_job(&run_id, 1, &first.id).unwrap();
    env.db.set_chain_stage_job(&run_id, 2, &second.id).unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    assert_eq!(claim.job.id, first.id);
    let outcome = CompleteOutcome {
        status: JobStatus::Failed,
        result: json!({}),
        counters: JobCounters::default(),
        error: Some("source unavailable".to_string()),
        observations: Vec::new(),
        findings: Vec::new(),
        artifacts: Vec::new(),
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    env.db
        .complete_attempt(&first.id, &claim.attempt_id, outcome)
        .unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    assert_eq!(claim.job.id, second.id);
    Worker::new(env.config.clone(), env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = env.db.job_by_id(&second.id).unwrap().unwrap();
    assert_eq!(finished.status, JobStatus::Cancelled);
    let chain = env.db.chain_run_json(&run_id).unwrap().unwrap();
    assert_eq!(chain["status"], "partial");
    assert!(chain["stages"][1]["skipped_reason"]
        .as_str()
        .unwrap()
        .contains("previous chain stage"));
}

#[tokio::test]
async fn chain_stage_consumes_published_results_from_previous_job() {
    let env = TestEnv::new();
    let server =
        spawn_http_server(|_| HttpResponse::new(200, "<html><title>chained</title></html>")).await;
    let (project, revision) =
        env.project_with_scope("chain-input", scope_rules(&[("exact", "localhost")]), true);
    let run_id = env
        .db
        .create_chain_run(&project.id, "All in one", None, "admin")
        .unwrap();
    env.db
        .add_chain_stage(&run_id, 1, "http.probe", None, true)
        .unwrap();
    env.db
        .add_chain_stage(&run_id, 2, "http.crawl", None, true)
        .unwrap();
    let first = env
        .db
        .enqueue_job(
            &project.id,
            "http.probe",
            &json!({"targets": [], "mode": "url"}),
            &revision.id,
            revision.version,
            None,
            "admin",
            Some(&run_id),
            Some(1),
        )
        .unwrap();
    env.db.set_chain_stage_job(&run_id, 1, &first.id).unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    let url = format!("http://localhost:{}/", server.addr.port());
    let outcome = CompleteOutcome {
        status: JobStatus::Succeeded,
        result: json!({}),
        counters: JobCounters::default(),
        error: None,
        observations: vec![NewObservation {
            source: "http.probe".to_string(),
            kind: "url".to_string(),
            asset_kind: "url".to_string(),
            asset: url.clone(),
            canonical_asset: url,
            data: json!({"chain_fixture": true}),
            scope_status: "allowed".to_string(),
        }],
        findings: Vec::new(),
        artifacts: Vec::new(),
        candidates: Vec::new(),
        enrichments: Vec::new(),
        classifications: Vec::new(),
    };
    env.db
        .complete_attempt(&first.id, &claim.attempt_id, outcome)
        .unwrap();
    let second = env
        .db
        .enqueue_job(
            &project.id,
            "http.crawl",
            &json!({}),
            &revision.id,
            revision.version,
            None,
            "admin",
            Some(&run_id),
            Some(2),
        )
        .unwrap();
    env.db.set_chain_stage_job(&run_id, 2, &second.id).unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    assert_eq!(claim.job.id, second.id);
    Worker::new(env.config.clone(), env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = env.db.job_by_id(&second.id).unwrap().unwrap();
    assert_eq!(
        finished.status,
        JobStatus::Succeeded,
        "{:?}",
        finished.error
    );
    assert!(env
        .db
        .observations_for_job(&second.id)
        .unwrap()
        .iter()
        .any(|item| item.kind == "http"));
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
}
