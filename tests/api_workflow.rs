mod support;

use axum::http::{Method, StatusCode};
use lastest::domain::JobStatus;
use lastest::worker::Worker;
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use support::{call, spawn_http_server, HttpResponse, TestEnv};

#[tokio::test]
async fn scope_approval_idempotency_dashboard_evidence_and_reports() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let project = call(
        &env.app,
        Method::POST,
        "/api/projects",
        Some(json!({"name": "api-flow", "client": "ACME"})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(project.status, StatusCode::CREATED, "{}", project.text);
    let project_id = project.body["project"]["id"].as_str().unwrap().to_string();
    let blocked = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/jobs"),
        Some(json!({"task_type": "dns.records", "params": {}})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(blocked.status, StatusCode::CONFLICT);
    assert_eq!(blocked.body["error"]["code"], "scope_not_approved");

    let draft = call(
        &env.app,
        Method::PUT,
        &format!("/api/projects/{project_id}/scope"),
        Some(json!({
            "rules": [{"kind": "exact_domain", "value": "localhost"}],
            "expected_version": 1,
            "note": "draft"
        })),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(draft.status, StatusCode::OK, "{}", draft.text);
    assert_eq!(draft.body["scope"]["version"], 2);
    assert_eq!(draft.body["scope"]["status"], "draft");
    let stale = call(
        &env.app,
        Method::PUT,
        &format!("/api/projects/{project_id}/scope"),
        Some(json!({
            "rules": [{"kind": "exact_domain", "value": "localhost"}],
            "expected_version": 1
        })),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["error"]["code"], "scope_version_conflict");

    let approved = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/scope/2/approve"),
        Some(json!({})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    let scope = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{project_id}/scope?version=1"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(scope.status, StatusCode::OK);
    assert_eq!(scope.body["scope"]["rules"].as_array().unwrap().len(), 0);

    let server = spawn_http_server(|_| {
        HttpResponse::new(200, "<html><title>API Flow</title><body>ok</body></html>")
            .header("Server", "nginx/1.24.0")
    })
    .await;
    let target = format!("http://localhost:{}/", server.addr.port());
    let body = json!({
        "task_type": "http.probe",
        "params": {"targets": [target], "mode": "url"},
        "idempotency_key": "flow-http"
    });
    let first = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/jobs"),
        Some(body.clone()),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.text);
    let job_id = first.body["job"]["id"].as_str().unwrap().to_string();
    let replay = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/jobs"),
        Some(body),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(replay.body["job"]["id"], job_id);
    let conflict = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/jobs"),
        Some(json!({
            "task_type": "http.probe",
            "params": {"targets": [format!("http://localhost:{}/other", server.addr.port())], "mode": "url"},
            "idempotency_key": "flow-http"
        })),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(conflict.body["error"]["code"], "idempotency_conflict");

    let claim = env.db.claim_next_job("test-worker", 30).unwrap().unwrap();
    Worker::new(env.config.clone(), env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_eq!(
        env.db.job_by_id(&job_id).unwrap().unwrap().status,
        JobStatus::Succeeded
    );

    let dashboard = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{project_id}/dashboard"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(dashboard.status, StatusCode::OK);
    assert_eq!(dashboard.body["data_status"], "ready");
    assert!(dashboard.body["metrics"]["observations"].as_u64().unwrap() >= 1);
    assert_eq!(dashboard.body["metrics"]["hosts"], 1);

    let job = call(
        &env.app,
        Method::GET,
        &format!("/api/jobs/{job_id}"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    let artifact_id = job.body["job"]["artifacts"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let evidence = call(
        &env.app,
        Method::GET,
        &format!("/api/evidence/{artifact_id}"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(evidence.status, StatusCode::OK);
    assert!(evidence.text.contains("format_version"));

    let report = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{project_id}/reports/json"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(report.status, StatusCode::OK);
    assert_eq!(report.body["project"]["name"], "api-flow");
    assert!(!report.body["http"].as_array().unwrap().is_empty());
    let csv = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{project_id}/reports/csv"),
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(csv.status, StatusCode::OK);
    assert!(csv.text.starts_with("section,record_type"));

    let pending = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{project_id}/jobs"),
        Some(json!({"task_type": "dns.records", "params": {"targets": ["localhost"]}})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    let pending_id = pending.body["job"]["id"].as_str().unwrap().to_string();
    let cancelled = call(
        &env.app,
        Method::POST,
        &format!("/api/jobs/{pending_id}/cancel"),
        Some(json!({})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(cancelled.body["job"]["status"], "cancelled");
}
