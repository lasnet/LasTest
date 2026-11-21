mod support;

use lastest::db::jobs::CompleteOutcome;
use lastest::domain::{JobCounters, JobStatus};
use lastest::scope::Scope;
use lastest::tasks::providers::censys;
use lastest::tasks::providers::shodan;
use lastest::tasks::{dns_tasks, provider};
use serde_json::json;
use support::{
    make_job, scope_rules, spawn_dns_response_server, spawn_http_server, task_context,
    HttpResponse, TestEnv,
};

#[tokio::test]
async fn absent_ptr_records_are_empty_results_not_task_errors() {
    for response_code in [0, 3] {
        let env = TestEnv::new();
        let mut ctx = task_context(
            &env,
            Scope::new(scope_rules(&[("ip", "203.0.113.88")])).unwrap(),
            &format!("ptr-empty-{response_code}"),
        );
        let dns = spawn_dns_response_server(move |_, _| (response_code, Vec::new())).await;
        ctx.config.dns_server = Some(dns.addr.to_string());
        let outcome = dns_tasks::run_reverse_ip(
            &make_job(
                "reverse.ip",
                json!({"ips":["203.0.113.88"],"sources":["ptr"]}),
            ),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.status, JobStatus::Succeeded);
        assert_eq!(outcome.counters.errors, 0);
        assert_eq!(outcome.counters.processed, 1);
        assert_eq!(outcome.result["partial"], false);
        assert_eq!(outcome.result["providers"][0]["status"], "empty");
        assert_eq!(outcome.result["ips"][0]["status"], "empty");
        assert!(outcome.error.is_none());
        let artifact: serde_json::Value =
            serde_json::from_slice(&outcome.artifacts[0].content).unwrap();
        assert_eq!(artifact["providers"][0]["reason"], "no PTR records");
        assert!(!artifact.to_string().contains("Query {"));
    }
}

#[tokio::test]
async fn ptr_server_failure_remains_a_real_check_error() {
    let env = TestEnv::new();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("ip", "203.0.113.88")])).unwrap(),
        "ptr-servfail",
    );
    let dns = spawn_dns_response_server(|_, _| (2, Vec::new())).await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    ctx.config.http_timeout_seconds = 1;
    let outcome = dns_tasks::run_reverse_ip(
        &make_job(
            "reverse.ip",
            json!({"ips":["203.0.113.88"],"sources":["ptr"]}),
        ),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(outcome.status, JobStatus::Partial);
    assert_eq!(outcome.counters.errors, 1);
    assert_eq!(outcome.result["providers"][0]["status"], "unavailable");
    assert!(!outcome.error.as_deref().unwrap().contains("Query {"));
    assert_ne!(outcome.result["providers"][0]["reason"], "no PTR records");
}

#[tokio::test]
async fn absent_ptr_does_not_mark_passive_provider_results_unavailable() {
    for http_status in [200, 404] {
        let env = TestEnv::new();
        let mut ctx = task_context(
            &env,
            Scope::new(scope_rules(&[("ip", "203.0.113.88")])).unwrap(),
            &format!("ptr-provider-{http_status}"),
        );
        let dns = spawn_dns_response_server(|_, _| (3, Vec::new())).await;
        let provider = spawn_http_server(move |_| {
            HttpResponse::new(http_status, "{\"hostnames\":[],\"ports\":[443]}")
                .header("Content-Type", "application/json")
        })
        .await;
        ctx.config.dns_server = Some(dns.addr.to_string());
        ctx.config.shodan_internetdb_url = format!("http://{}", provider.addr);
        let outcome = dns_tasks::run_reverse_ip(
            &make_job(
                "reverse.ip",
                json!({"ips":["203.0.113.88"],"sources":["ptr","shodan_internetdb"]}),
            ),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.status, JobStatus::Succeeded);
        assert_eq!(outcome.counters.errors, 0);
        assert_eq!(
            outcome.result["ips"][0]["status"],
            if http_status == 200 { "ok" } else { "empty" }
        );
        assert_eq!(
            outcome
                .observations
                .iter()
                .filter(|row| row.kind == "provider")
                .count(),
            usize::from(http_status == 200)
        );
    }
}

#[test]
fn shodan_adapter_uses_only_hostnames_and_normalizes_names() {
    let parsed = shodan::parse(
        &json!({
            "hostnames": ["Example.COM.", "example.com", "*.wild.example", "203.0.113.9", "bad name"],
            "ports": [443, 443, "oops"],
            "cpes": ["cpe:/a:nginx:nginx"],
            "tags": ["cdn"],
            "vulns": {"CVE-2024-0001": {}},
            "issuer": "issuer.evil.example"
        }),
        10,
    );
    assert_eq!(parsed.names, vec!["example.com"]);
    assert!(parsed.partial);
    assert_eq!(parsed.passive["ports"], json!([443]));
    assert!(parsed.passive.get("issuer").is_none());
}

#[test]
fn censys_v3_and_legacy_extract_only_documented_name_fields() {
    let v3 = json!({
        "result": {"resource": {
            "ip": "203.0.113.10",
            "dns": {"names": ["app.example.com", "*.wild.example.com"]},
            "services": [{
                "port": 443,
                "service_name": "HTTPS",
                "tls": {"certificates": [{
                    "leaf_data": {
                        "subject": {"common_name": "www.example.com"},
                        "names": ["api.example.com"],
                        "issuer": {"common_name": "issuer.evil.example"}
                    }
                }], "issuer": {"common_name": "issuer.evil.example"}},
                "banner": "evil.example in a banner",
                "software": [{"product": "nginx", "cpe": "cpe:/a:nginx:nginx"}]
            }],
            "autonomous_system": {"asn": 64500, "name": "Example Hosting", "country": "DE"},
            "location": {"country": "DE"}
        }}
    });
    let parsed = censys::parse(&v3, 20);
    for expected in ["app.example.com", "www.example.com", "api.example.com"] {
        assert!(
            parsed.names.iter().any(|name| name == expected),
            "{expected}"
        );
    }
    assert!(!parsed.names.iter().any(|name| name.contains("evil")));
    assert_eq!(parsed.passive["ports"], json!([443]));
    assert_eq!(parsed.passive["asn"], json!(64500));
    assert_eq!(parsed.passive["organization"], "Example Hosting");
    assert_eq!(
        parsed.passive["certificates"][0]["subject"],
        "www.example.com"
    );

    let legacy = json!({
        "code": 200,
        "result": {
            "ip": "203.0.113.11",
            "hostnames": ["Legacy.Example.COM"],
            "ports": [80],
            "services": [{"port": 80, "tls": {"certificate": {"leaf_data": {"names": ["legacy-api.example.com"]}}}}]
        }
    });
    let parsed = censys::parse(&legacy, 20);
    assert!(parsed.names.contains(&"legacy.example.com".to_string()));
    assert!(parsed.names.contains(&"legacy-api.example.com".to_string()));
    assert_eq!(parsed.passive["api_version"], "legacy_v2");
}

#[test]
fn provider_errors_distinguish_empty_from_access_and_retries() {
    assert!(provider::is_retryable_status(429));
    assert!(provider::is_retryable_status(503));
    assert!(!provider::is_retryable_status(401));
    assert!(!provider::is_retryable_status(404));
}

#[tokio::test]
async fn reverse_ip_publishes_candidate_and_asset_only_after_permitted_dns() {
    let env = TestEnv::new();
    let provider_server = spawn_http_server(|_| {
        HttpResponse::new(
            200,
            "{\"hostnames\":[\"host.allowed.test\",\"outside.other.test\"],\"ports\":[443]}",
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
    let scope = Scope::new(scope_rules(&[
        ("ip", "203.0.113.10"),
        ("tree", "allowed.test"),
    ]))
    .unwrap();
    let mut ctx = task_context(&env, scope.clone(), "reverse-discovery");
    ctx.config = config.clone();
    let job = make_job(
        "reverse.ip",
        json!({"ips": ["203.0.113.10"], "sources": ["shodan_internetdb"]}),
    );
    let outcome = dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["format_version"], "2");
    let verified = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.hostname == "host.allowed.test" && candidate.data_type == "dns_check"
        })
        .expect("verified candidate");
    assert_eq!(verified.dns_status.as_deref(), Some("verified"));
    assert_eq!(verified.ip_match.as_deref(), Some("matched"));
    let denied = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.hostname == "outside.other.test" && candidate.data_type == "dns_check"
        })
        .expect("denied candidate");
    assert_eq!(denied.dns_status.as_deref(), Some("not_permitted"));
    assert!(outcome
        .observations
        .iter()
        .any(|observation| observation.kind == "host" && observation.asset == "host.allowed.test"));
    assert!(!outcome
        .observations
        .iter()
        .any(|observation| observation.asset == "outside.other.test"));

    // Publish atomically through the queue completion path.
    let scope_rev = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    let queued = env
        .db
        .enqueue_job(
            &ctx.project_id,
            "reverse.ip",
            &job.params,
            &scope_rev.id,
            scope_rev.version,
            None,
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("worker-test", 30).unwrap().unwrap();
    assert_eq!(claim.job.id, queued.id);
    assert!(env
        .db
        .complete_attempt(
            &claim.job.id,
            &claim.attempt_id,
            CompleteOutcome {
                status: JobStatus::Succeeded,
                result: json!({"format_version": "2"}),
                counters: JobCounters::default(),
                error: None,
                observations: outcome.observations.clone(),
                findings: Vec::new(),
                artifacts: Vec::new(),
                candidates: outcome.candidates.clone(),
                enrichments: Vec::new(),
                classifications: Vec::new(),
            },
        )
        .unwrap());
    let rows = env.db.recent_candidates(&ctx.project_id, 10).unwrap();
    let allowed = rows
        .iter()
        .find(|row| row["hostname"] == "host.allowed.test")
        .unwrap();
    assert_eq!(allowed["dns_status"], "verified");
    assert!(allowed["asset_id"].as_str().is_some());
    let denied = rows
        .iter()
        .find(|row| row["hostname"] == "outside.other.test")
        .unwrap();
    assert_eq!(denied["dns_status"], "not_permitted");
    assert!(denied["asset_id"].is_null());
    let hosts = env.db.inventory_rows(&ctx.project_id, "").unwrap();
    assert!(hosts
        .iter()
        .any(|row| row.host.as_deref() == Some("host.allowed.test")));
    assert!(!hosts
        .iter()
        .any(|row| row.host.as_deref() == Some("outside.other.test")));
}

#[tokio::test]
async fn candidates_and_asset_detail_are_project_scoped_and_survive_asset_delete() {
    use axum::http::{Method, StatusCode};
    use serde_json::Value as JsonValue;
    use support::{as_pairs, call, cookie_headers};

    let env = TestEnv::new();
    let (project, revision) = env.project_with_scope(
        "discovery-api",
        scope_rules(&[("ip", "203.0.113.10"), ("tree", "allowed.test")]),
        true,
    );
    let job = env
        .db
        .enqueue_job(
            &project.id,
            "reverse.ip",
            &json!({"ips": ["203.0.113.10"], "sources": ["shodan_internetdb"]}),
            &revision.id,
            revision.version,
            None,
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("worker", 30).unwrap().unwrap();
    env.db
        .complete_attempt(
            &job.id,
            &claim.attempt_id,
            CompleteOutcome {
                status: JobStatus::Succeeded,
                result: json!({}),
                counters: JobCounters::default(),
                error: None,
                observations: Vec::new(),
                findings: Vec::new(),
                artifacts: Vec::new(),
                candidates: vec![
                    lastest::domain::NewCandidate::new(
                        "host.allowed.test",
                        "shodan_internetdb",
                        "dns_check",
                    )
                    .with_dns(
                        "verified",
                        vec!["203.0.113.10".to_string()],
                        "matched",
                        "allowed",
                    ),
                    lastest::domain::NewCandidate::new(
                        "outside.other.test",
                        "shodan_internetdb",
                        "dns_check",
                    )
                    .with_dns("not_permitted", Vec::new(), "unknown", "denied")
                    .with_reason("candidate is outside the current DNS scope"),
                ],
                enrichments: Vec::new(),
                classifications: Vec::new(),
            },
        )
        .unwrap();
    let cookie = env.login_web().await;
    let scope = env.db.current_scope(&project.id).unwrap().unwrap();
    env.db
        .list_candidates(
            &project.id,
            &lastest::db::discovery::CandidateFilter::default(),
            &scope.scope,
            10,
            0,
        )
        .unwrap();
    let cookie_headers_value = cookie_headers(&cookie);
    let headers = as_pairs(&cookie_headers_value);
    let list = call(
        &env.app,
        Method::GET,
        &format!(
            "/api/projects/{}/discovery/candidates?scope_status=allowed&dns_status=verified",
            project.id
        ),
        None,
        &headers,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert_eq!(list.body["total"], 1);
    let candidate = &list.body["items"][0];
    assert_eq!(candidate["hostname"], "host.allowed.test");
    assert_eq!(candidate["current_scope_status"], "allowed");
    let candidate_id = candidate["id"].as_str().unwrap().to_string();
    let asset_id = candidate["asset_id"].as_str().unwrap().to_string();

    let scoped = env.db.current_scope(&project.id).unwrap().unwrap();
    let direct = env
        .db
        .candidate_detail(&project.id, &candidate_id, &scoped.scope)
        .unwrap()
        .unwrap();
    assert!(
        !direct["evidence"].as_array().unwrap().is_empty(),
        "direct detail: {direct}"
    );
    let detail = call(
        &env.app,
        Method::GET,
        &format!(
            "/api/projects/{}/discovery/candidates/{}",
            project.id, candidate_id
        ),
        None,
        &headers,
    )
    .await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert!(!detail.body["candidate"]["evidence"]
        .as_array()
        .unwrap()
        .is_empty());

    let asset_detail = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{}/assets/{}", project.id, asset_id),
        None,
        &headers,
    )
    .await;
    assert_eq!(asset_detail.status, StatusCode::OK, "{}", asset_detail.text);

    let discovery_export = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{}/discovery/export/json", project.id),
        None,
        &headers,
    )
    .await;
    assert_eq!(
        discovery_export.status,
        StatusCode::OK,
        "{}",
        discovery_export.text
    );
    assert!(discovery_export.text.contains("host.allowed.test"));
    let report_export = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{}/reports/discovery-csv", project.id),
        None,
        &headers,
    )
    .await;
    assert_eq!(
        report_export.status,
        StatusCode::OK,
        "{}",
        report_export.text
    );
    assert!(report_export.text.contains("host.allowed.test"));

    // Delete the asset: the candidate must remain and its link become null.
    let deleted = call(
        &env.app,
        Method::DELETE,
        &format!("/api/projects/{}/assets/{}", project.id, asset_id),
        None,
        &headers,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text);
    let after = call(
        &env.app,
        Method::GET,
        &format!(
            "/api/projects/{}/discovery/candidates/{}",
            project.id, candidate_id
        ),
        None,
        &headers,
    )
    .await;
    assert_eq!(after.status, StatusCode::OK, "{}", after.text);
    assert!(after.body["candidate"]["asset_id"].is_null());
    assert!(after.body["candidate"]["asset"].is_null());

    // A candidate ID from another project is not visible through this project.
    let (other, _) = env.project_with_scope(
        "other-project",
        scope_rules(&[("ip", "203.0.113.10")]),
        true,
    );
    let foreign: JsonValue = call(
        &env.app,
        Method::GET,
        &format!(
            "/api/projects/{}/discovery/candidates/{}",
            other.id, candidate_id
        ),
        None,
        &headers,
    )
    .await
    .body;
    assert!(foreign["error"].is_object());

    let invalid = call(
        &env.app,
        Method::GET,
        &format!(
            "/api/projects/{}/discovery/candidates?dns_status=nonsense",
            project.id
        ),
        None,
        &headers,
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ptr_only_source_still_runs_permitted_dns_verification() {
    let env = TestEnv::new();
    let dns = spawn_dns_response_server(|name, kind| {
        if kind == 12 && name == "10.113.0.203.in-addr.arpa" {
            (0, vec![support::encode_dns_name("ptr.allowed.test")])
        } else if kind == 1 && name == "ptr.allowed.test" {
            (0, vec![vec![203, 0, 113, 10]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    let mut config = env.config.clone();
    config.dns_server = Some(dns.addr.to_string());
    config.http_timeout_seconds = 1;
    let scope = Scope::new(scope_rules(&[
        ("ip", "203.0.113.10"),
        ("tree", "allowed.test"),
    ]))
    .unwrap();
    let mut ctx = task_context(&env, scope, "ptr-only");
    ctx.config = config;
    let job = make_job(
        "reverse.ip",
        json!({"ips": ["203.0.113.10"], "sources": ["ptr"]}),
    );
    let outcome = dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["sources"], json!(["ptr"]));
    assert!(outcome.result["providers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["provider"] == "ptr"));
    let verified = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.data_type == "dns_check")
        .unwrap();
    assert_eq!(verified.hostname, "ptr.allowed.test");
    assert_eq!(verified.dns_status.as_deref(), Some("verified"));
    assert_eq!(verified.ip_match.as_deref(), Some("matched"));
}

#[test]
fn version_two_database_upgrades_without_losing_assets() {
    use rusqlite::Connection;
    let temp = tempfile::TempDir::new().unwrap();
    let path = temp.path().join("legacy.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002_setup_code.sql"))
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
             INSERT INTO schema_migrations(version, applied_at)
                 VALUES (1, '2026-01-01T00:00:00Z'), (2, '2026-01-01T00:00:00Z');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO projects(id, name, client, description, created_at, updated_at)
             VALUES ('prj_upgrade', 'upgrade', '', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO assets(id, project_id, kind, value, canonical_value, first_seen, last_seen)
             VALUES ('ast_keep', 'prj_upgrade', 'host', 'keep.example.test', 'keep.example.test',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
    }
    let db = lastest::db::Db::new(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 3);
    let assets = db.list_assets("prj_upgrade", 10).unwrap();
    assert!(assets
        .iter()
        .any(|asset| asset["canonical_value"] == "keep.example.test"));
    assert!(db.recent_candidates("prj_upgrade", 10).unwrap().is_empty());
}

#[tokio::test]
async fn classification_uses_label_boundaries_and_stored_data_without_network() {
    use lastest::tasks::tech_catalog;
    assert!(tech_catalog::has_token("api.example.com", "api"));
    assert!(tech_catalog::has_token("api-v2.example.com", "api"));
    assert!(!tech_catalog::has_token("notapi.example.com", "api"));
    assert!(tech_catalog::host_matches_suffix(
        "a.example.com",
        "example.com"
    ));
    assert!(!tech_catalog::host_matches_suffix(
        "notexample.com",
        "example.com"
    ));

    let technologies = vec![
        json!({"name": "jira", "version": null, "evidence": [{"evidence": "x"}]}),
        json!({"name": "nginx", "version": "1.25", "evidence": []}),
    ];
    let groups = tech_catalog::groups_for(&technologies);
    assert_eq!(groups, vec!["jira", "nginx"]);
}
