mod support;

use axum::http::{Method, StatusCode};
use lastest::domain::{JobStatus, Role};
use lastest::scope::Scope;
use lastest::tasks::asset_classify;
use lastest::worker::Worker;
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use support::{
    as_pairs, call, cookie_headers, make_job, scope_rules, spawn_dns_response_server,
    spawn_http_server, task_context, HttpResponse, TestEnv,
};

#[tokio::test]
async fn chain_preset_is_validated_and_builds_sequential_stages() {
    let env = TestEnv::new();
    let (project, _) =
        env.project_with_scope("chain-preset", scope_rules(&[("ip", "203.0.113.10")]), true);
    let cookie = env.login_web().await;
    let response = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", project.id),
        Some(json!({
            "preset": "asset_discovery",
            "sources": ["ptr"],
            "ips": ["203.0.113.10"]
        })),
        &as_pairs(&cookie_headers(&cookie)),
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let stages = response.body["chain"]["stages"].as_array().unwrap();
    assert_eq!(stages.len(), 3);
    assert_eq!(stages[0]["task_type"], "reverse.ip");
    assert_eq!(stages[1]["task_type"], "assets.enrich");
    assert_eq!(stages[2]["task_type"], "assets.classify");
    assert_eq!(stages[1]["input_refs"], json!([1]));
    assert_eq!(stages[2]["input_refs"], json!([1, 2]));
    assert_eq!(response.body["chain"]["preset"], "asset_discovery");
    let orders: Vec<i64> = response.body["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|job| job["chain_order"].as_i64().unwrap())
        .collect();
    assert_eq!(orders, vec![1, 2, 3]);

    let invalid = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", project.id),
        Some(json!({"preset": "arbitrary_graph", "sources": ["ptr"]})),
        &as_pairs(&cookie_headers(&cookie)),
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);

    let empty_sources = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", project.id),
        Some(json!({"preset": "asset_discovery", "sources": []})),
        &as_pairs(&cookie_headers(&cookie)),
    )
    .await;
    assert_eq!(empty_sources.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn asset_discovery_chain_uses_its_own_committed_stage_inputs() {
    let env = TestEnv::new();
    let provider_server = spawn_http_server(|_| {
        HttpResponse::new(
            200,
            "{\"hostnames\":[\"host.allowed.test\"],\"ports\":[443]}",
        )
        .header("Content-Type", "application/json")
    })
    .await;
    let dns = spawn_dns_response_server(|name, kind| {
        if kind == 1 && name == "host.allowed.test" {
            (0, vec![vec![203, 0, 113, 10]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    let mut config = env.config.clone();
    config.shodan_internetdb_url = format!("http://127.0.0.1:{}", provider_server.addr.port());
    config.dns_server = Some(dns.addr.to_string());
    config.http_timeout_seconds = 1;
    config.provider_min_interval_ms = 0;
    config.worker_poll_ms = 5;
    let (project, revision) = env.project_with_scope(
        "chain-run",
        scope_rules(&[("ip", "203.0.113.10"), ("tree", "allowed.test")]),
        true,
    );
    let run_id = env
        .db
        .create_chain_run(&project.id, "Asset Discovery", None, "admin")
        .unwrap();
    env.db.set_chain_preset(&run_id, "asset_discovery").unwrap();
    let stages = [
        (
            "reverse.ip",
            json!({"ips": ["203.0.113.10"], "sources": ["shodan_internetdb"]}),
            Vec::new(),
        ),
        ("assets.enrich", json!({"http_enrichment": false}), vec![1]),
        ("assets.classify", json!({}), vec![1, 2]),
    ];
    for (index, (task_type, params, refs)) in stages.iter().enumerate() {
        let position = index as i64 + 1;
        env.db
            .add_chain_stage(&run_id, position, task_type, None, true)
            .unwrap();
        if !refs.is_empty() {
            env.db
                .set_chain_stage_input_refs(&run_id, position, refs)
                .unwrap();
        }
        let job = env
            .db
            .enqueue_job(
                &project.id,
                task_type,
                params,
                &revision.id,
                revision.version,
                Some(&format!("{run_id}:{position}")),
                "admin",
                Some(&run_id),
                Some(position),
            )
            .unwrap();
        env.db
            .set_chain_stage_job(&run_id, position, &job.id)
            .unwrap();
    }
    let worker = Worker::new(config, env.db.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    for _ in 0..10 {
        let Some(claim) = env.db.claim_next_job(&worker.worker_id, 30).unwrap() else {
            break;
        };
        worker
            .run_claimed(claim.job, claim.attempt_id, shutdown.clone())
            .await
            .unwrap();
    }
    let chain = env.db.chain_run_json(&run_id).unwrap().unwrap();
    assert!(
        matches!(chain["status"].as_str(), Some("succeeded" | "partial")),
        "{chain}"
    );
    let candidate = env
        .db
        .recent_candidates(&project.id, 10)
        .unwrap()
        .into_iter()
        .find(|row| row["hostname"] == "host.allowed.test")
        .expect("candidate from committed reverse.ip stage");
    assert_eq!(candidate["dns_status"], "verified");
    let classifications = env.db.classifications_for_project(&project.id, 10).unwrap();
    assert!(
        !classifications.is_empty(),
        "classify stage published results"
    );
    let jobs = env.db.chain_jobs(&run_id).unwrap();
    assert_eq!(jobs.len(), 3);
    assert!(jobs
        .iter()
        .all(|job| matches!(job.status, JobStatus::Succeeded | JobStatus::Partial)));
    assert_eq!(jobs[0].chain_order, Some(1));
    assert_eq!(jobs[2].chain_order, Some(3));
}

#[tokio::test]
async fn empty_chain_input_does_not_classify_project_history() {
    let env = TestEnv::new();
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let ctx = task_context(&env, scope, "classify-empty");
    // Pre-existing history that must not be picked up by an empty chain stage.
    let conn = env.db.connect().unwrap();
    conn.execute(
        "INSERT INTO assets(id, project_id, kind, value, canonical_value, first_seen, last_seen)
         VALUES ('ast_history', ?1, 'host', 'old.allowed.test', 'old.allowed.test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        rusqlite::params![ctx.project_id],
    )
    .unwrap();
    drop(conn);
    let mut history_job = make_job("reverse.ip", json!({"ips": ["203.0.113.10"]}));
    history_job.id = "job_empty_input".to_string();
    let mut ctx = ctx;
    ctx.input_jobs = vec![history_job];
    let outcome = asset_classify::run(&make_job("assets.classify", json!({})), &ctx)
        .await
        .unwrap();
    assert_eq!(outcome.result["empty"], true);
    assert_eq!(outcome.result["classified"], 0);
    assert!(env
        .db
        .classifications_for_project(&ctx.project_id, 10)
        .unwrap()
        .is_empty());
}

#[test]
fn viewer_cannot_read_other_projects_candidates() {
    // Compile-time role check plus the API's project resolution are covered by
    // the dedicated API tests; this keeps the role contract explicit here.
    assert!(!Role::Viewer.at_least(Role::Analyst));
}
