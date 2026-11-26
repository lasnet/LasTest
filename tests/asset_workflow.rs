mod support;

use axum::http::{Method, StatusCode};
use lastest::db::import::ImportedObservation;
use lastest::scope::Scope;
use lastest::tasks::{self, asset_input};
use lastest::worker::Worker;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use support::{
    as_pairs, call, cookie_headers, make_job, scope_rules, spawn_dns_response_server,
    spawn_http_server, task_context, HttpResponse, TestEnv,
};

fn observe(env: &TestEnv, project: &str, kind: &str, value: &str, data: Value) {
    env.db
        .insert_import_observation(
            project,
            None,
            &ImportedObservation {
                source: "fixture".into(),
                kind: kind.into(),
                asset_kind: kind.into(),
                asset: value.into(),
                canonical: value.into(),
                data,
                scope_status: "allowed".into(),
                observed_at: "2026-11-22T00:00:00Z".into(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn empty_assets_require_dns_enumeration_or_confirmed_scope_import() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let headers = cookie_headers(&cookie);
    let empty = env
        .db
        .create_project("empty-assets", "", "", None, None, "admin")
        .unwrap();
    let get = |project: &str| format!("/api/projects/{project}/assets/targets");
    let response = call(
        &env.app,
        Method::GET,
        &get(&empty.id),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.body["next"], "scope_empty");
    let (dns, revision) = env.project_with_scope(
        "dns-first",
        scope_rules(&[("exact", "example.test"), ("ip", "203.0.113.1")]),
        true,
    );
    let response = call(
        &env.app,
        Method::GET,
        &get(&dns.id),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.body["next"], "enumerate_subdomains");
    let import = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/assets/import-scope", dns.id),
        Some(json!({"scope_version":revision.version})),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(import.status, StatusCode::BAD_REQUEST);
    let (project, revision) = env.project_with_scope(
        "import-network",
        scope_rules(&[("cidr", "203.0.113.0/29"), ("ip", "203.0.113.2")])
            .into_iter()
            .chain([lastest::scope::ScopeRule::new(
                lastest::scope::RuleKind::Ip,
                "203.0.113.3",
                true,
            )
            .unwrap()])
            .collect(),
        true,
    );
    let response = call(
        &env.app,
        Method::GET,
        &get(&project.id),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.body["next"], "import_scope");
    assert_eq!(response.body["import_count"], 5);
    assert!(env.db.inventory_rows(&project.id, "").unwrap().is_empty());
    for (version, status) in [
        (revision.version - 1, StatusCode::BAD_REQUEST),
        (revision.version, StatusCode::OK),
        (revision.version, StatusCode::OK),
    ] {
        let response = call(
            &env.app,
            Method::POST,
            &format!("/api/projects/{}/assets/import-scope", project.id),
            Some(json!({"scope_version":version})),
            &as_pairs(&headers),
        )
        .await;
        assert_eq!(response.status, status, "{}", response.text);
    }
    let rows = env.db.inventory_rows(&project.id, "").unwrap();
    assert_eq!(rows.len(), 5);
    assert!(!rows
        .iter()
        .any(|row| row.ips.contains(&"203.0.113.3".into())));
    assert_eq!(
        env.db.current_scope(&project.id).unwrap().unwrap().version,
        revision.version
    );
    let response = call(
        &env.app,
        Method::GET,
        &get(&project.id),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.body["next"], "ready");
}

#[test]
fn oversized_or_blocked_scope_import_is_atomic() {
    let env = TestEnv::new();
    for (name, rules) in [
        (
            "huge-v4",
            scope_rules(&[("ip", "203.0.113.5"), ("cidr", "203.0.113.0/24")]),
        ),
        ("huge-v6", scope_rules(&[("cidr", "2001:db8::/32")])),
        (
            "blocked",
            scope_rules(&[("ip", "203.0.113.5"), ("ip", "169.254.169.254")]),
        ),
    ] {
        let (project, revision) = env.project_with_scope(name, rules, true);
        assert!(env
            .db
            .import_scope_assets(
                &project.id,
                revision.version,
                &env.config.network_policy(),
                100,
                "admin"
            )
            .is_err());
        assert!(env.db.inventory_rows(&project.id, "").unwrap().is_empty());
    }
}

#[tokio::test]
async fn selection_api_uses_only_project_assets_and_stored_urls() {
    let env = TestEnv::new();
    let (project, _) = env.project_with_scope(
        "selected-inputs",
        scope_rules(&[("exact", "example.test")]),
        true,
    );
    observe(
        &env,
        &project.id,
        "host",
        "web.example.test",
        json!({"addresses":["203.0.113.5"]}),
    );
    for path in ["one", "two"] {
        observe(
            &env,
            &project.id,
            "url",
            &format!("https://web.example.test/{path}"),
            json!({}),
        );
    }
    observe(
        &env,
        &project.id,
        "host",
        "other.example.test",
        json!({"addresses":["203.0.113.6"]}),
    );
    observe(
        &env,
        &project.id,
        "url",
        "https://other.example.test/private",
        json!({}),
    );
    let rows = env.db.asset_input_catalog(&project.id).unwrap();
    let id = rows
        .iter()
        .find(|row| row["host"] == "web.example.test")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let other = rows
        .iter()
        .find(|row| row["host"] == "other.example.test")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let cookie = env.login_web().await;
    let headers = cookie_headers(&cookie);
    let base = format!("/api/projects/{}/jobs", project.id);
    let (other_project, _) = env.project_with_scope("other-urls", vec![], false);
    observe(
        &env,
        &other_project.id,
        "url",
        "https://elsewhere.example.test/other-project",
        json!({}),
    );
    let urls = call(
        &env.app,
        Method::GET,
        &format!("/api/projects/{}/assets/urls", project.id),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(urls.status, StatusCode::OK, "{}", urls.text);
    assert_eq!(
        urls.body["items"],
        json!([
            {"value":"https://other.example.test/private","last_seen":"2026-11-22T00:00:00Z"},
            {"value":"https://web.example.test/one","last_seen":"2026-11-22T00:00:00Z"},
            {"value":"https://web.example.test/two","last_seen":"2026-11-22T00:00:00Z"}
        ])
    );
    let response = call(
        &env.app,
        Method::POST,
        &base,
        Some(json!({"task_type":"http.probe","params":{},"asset_ids":[id]})),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    assert_eq!(
        response.body["job"]["params"]["targets"],
        json!([
            "https://web.example.test/one",
            "https://web.example.test/two"
        ])
    );
    assert_eq!(response.body["job"]["params"]["mode"], "url");
    for body in [
        json!({"task_type":"http.crawl","asset_ids":[],"params":{}}),
        json!({"task_type":"http.crawl","asset_ids":["missing"],"params":{}}),
        json!({"task_type":"http.crawl","asset_ids":[id],"params":{"seeds":["https://other.example.test/"]}}),
        json!({"task_type":"http.crawl","params":{"_asset_input":[{"id":other}]}}),
    ] {
        assert_eq!(
            call(
                &env.app,
                Method::POST,
                &base,
                Some(body),
                &as_pairs(&headers)
            )
            .await
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    let (foreign, _) = env.project_with_scope(
        "foreign-selection",
        scope_rules(&[("exact", "example.test")]),
        true,
    );
    let response = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/jobs", foreign.id),
        Some(json!({"task_type":"http.crawl","asset_ids":[id]})),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    // Legacy explicit-IP authorization is unchanged.
    let raw = call(
        &env.app,
        Method::POST,
        &base,
        Some(json!({"task_type":"tcp.connect","params":{"ips":["203.0.113.5"],"ports":[80]}})),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(raw.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn selected_dns_ips_are_fresh_and_scope_narrowing_revokes_the_grant() {
    let env = TestEnv::new();
    let scope = Scope::new(scope_rules(&[("exact", "example.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "asset-dns-grants");
    observe(
        &env,
        &ctx.project_id,
        "host",
        "chosen.example.test",
        json!({"addresses":["127.0.0.1","203.0.113.9"]}),
    );
    let inputs = env.db.asset_input_catalog(&ctx.project_id).unwrap();
    let metadata = json!([inputs[0].clone()]);
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![127, 0, 0, 1]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    let job = make_job(
        "tcp.connect",
        json!({"ips":["127.0.0.1","203.0.113.9"],"ports":[80]}),
    );
    let granted = asset_input::prepare(&job, &ctx, &metadata).await.unwrap();
    assert!(granted.allows_ip_now("127.0.0.1".parse().unwrap()));
    assert!(!granted.allows_ip_now("203.0.113.9".parse().unwrap()));
    assert!(granted.allows_host_now("chosen.example.test"));
    assert!(!granted.allows_host_now("unselected.example.test"));
    let listener = spawn_http_server(|_| HttpResponse::new(200, "fixture")).await;
    let probe = make_job(
        "tcp.connect",
        json!({"ips":["127.0.0.1","203.0.113.9"],"ports":[listener.addr.port()],"_asset_input":metadata}),
    );
    let outcome = tasks::execute(&probe, &ctx).await.unwrap();
    assert_eq!(outcome.result["confirmed_ports"][0]["ip"], "127.0.0.1");
    assert_eq!(outcome.counters.targets, 1, "stale IP must not be scanned");
    let revision = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    env.db
        .replace_scope(
            &ctx.project_id,
            Some(revision.version),
            &Scope::default(),
            "narrowed",
            "admin",
            true,
        )
        .unwrap();
    assert!(!granted.allows_ip_now("127.0.0.1".parse().unwrap()));
    assert!(!granted.allows_host_now("chosen.example.test"));
    assert!(asset_input::prepare(&job, &ctx, &metadata).await.is_err());
}

#[tokio::test]
async fn scope_import_requires_analyst_and_same_origin() {
    use lastest::domain::Role;
    let env = TestEnv::new();
    let (project, revision) = env.project_with_scope(
        "import-permissions",
        scope_rules(&[("ip", "203.0.113.5")]),
        true,
    );
    let route = format!("/api/projects/{}/assets/import-scope", project.id);
    let body = json!({"scope_version":revision.version});
    assert_eq!(
        call(&env.app, Method::POST, &route, Some(body.clone()), &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let cookie = env.login_web().await;
    assert_eq!(
        call(
            &env.app,
            Method::POST,
            &route,
            Some(body.clone()),
            &[("Host", "localhost"), ("Cookie", &cookie)]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    env.auth
        .create_user(
            "admin",
            "viewer",
            "ViewerPassword!123",
            Role::Viewer,
            false,
            None,
        )
        .unwrap();
    let viewer = env
        .auth
        .login("viewer", "ViewerPassword!123", "cli")
        .unwrap();
    let bearer = format!("Bearer {}", viewer.token);
    assert_eq!(
        call(
            &env.app,
            Method::POST,
            &route,
            Some(body),
            &[("Authorization", &bearer)]
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert!(env.db.inventory_rows(&project.id, "").unwrap().is_empty());
}

#[tokio::test]
async fn ip_only_discovery_enriches_and_classifies_original_assets_without_candidates() {
    let env = TestEnv::new();
    let (project, revision) =
        env.project_with_scope("ip-discovery", scope_rules(&[("ip", "203.0.113.5")]), true);
    env.db
        .import_scope_assets(
            &project.id,
            revision.version,
            &env.config.network_policy(),
            100,
            "admin",
        )
        .unwrap();
    let id = env.db.inventory_rows(&project.id, "").unwrap()[0]
        .id
        .clone();
    let cookie = env.login_web().await;
    let response = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", project.id),
        Some(json!({"preset":"asset_discovery","asset_ids":[id],"sources":["ptr"]})),
        &as_pairs(&cookie_headers(&cookie)),
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let run = response.body["chain"]["id"].as_str().unwrap();
    let dns = spawn_dns_response_server(|_, _| (3, Vec::new())).await;
    let mut config = env.config.clone();
    config.dns_server = Some(dns.addr.to_string());
    let worker = Worker::new(config, env.db.clone());
    for _ in 0..3 {
        let claim = env
            .db
            .claim_next_job(&worker.worker_id, 30)
            .unwrap()
            .unwrap();
        worker
            .run_claimed(
                claim.job,
                claim.attempt_id,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
    }
    let chain = env.db.chain_run_json(run).unwrap().unwrap();
    assert_eq!(
        chain["status"], "succeeded",
        "absent PTR is not an error: {chain}"
    );
    let detail = env.db.asset_detail(&project.id, &id).unwrap().unwrap();
    assert_eq!(
        detail["enrichment"]["data"]["dns"]["status"],
        "not_applicable"
    );
    assert!(detail["classification"].is_object(), "{detail}");
    assert_eq!(env.db.inventory_rows(&project.id, "").unwrap().len(), 1);
}

#[tokio::test]
async fn discovery_starts_from_dns_assets_without_explicit_ip_scope_records() {
    let env = TestEnv::new();
    let (project, revision) = env.project_with_scope(
        "dns-asset-chain",
        scope_rules(&[("exact", "example.test")]),
        true,
    );
    observe(
        &env,
        &project.id,
        "host",
        "www.example.test",
        json!({"addresses":["127.0.0.1"]}),
    );
    let id = env.db.inventory_rows(&project.id, "").unwrap()[0]
        .id
        .clone();
    let cookie = env.login_web().await;
    let response = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", project.id),
        Some(json!({"preset":"asset_discovery","asset_ids":[id],"sources":["ptr"]})),
        &as_pairs(&cookie_headers(&cookie)),
    )
    .await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![127, 0, 0, 1]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    let mut config = env.config.clone();
    config.dns_server = Some(dns.addr.to_string());
    let worker = Worker::new(config, env.db.clone());
    for _ in 0..3 {
        let claim = env
            .db
            .claim_next_job(&worker.worker_id, 30)
            .unwrap()
            .unwrap();
        worker
            .run_claimed(
                claim.job,
                claim.attempt_id,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
    }
    let jobs = env
        .db
        .chain_jobs(response.body["chain"]["id"].as_str().unwrap())
        .unwrap();
    assert!(
        jobs.iter().all(|job| matches!(
            job.status,
            lastest::domain::JobStatus::Succeeded | lastest::domain::JobStatus::Partial
        )),
        "{jobs:?}"
    );
    let detail = env.db.asset_detail(&project.id, &id).unwrap().unwrap();
    assert_eq!(
        detail["enrichment"]["data"]["dns"]["addresses"],
        json!(["127.0.0.1"])
    );
    assert!(detail["classification"].is_object(), "{detail}");
    assert_eq!(env.db.inventory_rows(&project.id, "").unwrap().len(), 1);
    let scope = env.db.current_scope(&project.id).unwrap().unwrap();
    assert_eq!(scope.version, revision.version);
    assert_eq!(
        scope.scope.rules.len(),
        1,
        "derived IP permissions never modify Scope"
    );
}

#[tokio::test]
async fn crawl_selected_ip_stays_on_selected_host() {
    let env = TestEnv::new();
    let target = spawn_http_server(|_| HttpResponse::new(200, "must not crawl this host")).await;
    let redirect = format!("http://localhost:{}/outside", target.addr.port());
    let source = spawn_http_server(move |_| {
        HttpResponse::new(200, format!("<a href='{redirect}'>external</a>"))
            .header("Content-Type", "text/html")
    })
    .await;
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("ip", "127.0.0.1"), ("exact", "localhost")])).unwrap(),
        "crawl-ip",
    );
    observe(&env, &ctx.project_id, "ip", "127.0.0.1", json!({}));
    let metadata = json!(env.db.asset_input_catalog(&ctx.project_id).unwrap());
    ctx.asset_inputs = None;
    let job = make_job(
        "http.crawl",
        json!({"seeds":[format!("http://{}/",source.addr)],"_asset_input":metadata,"max_pages":2}),
    );
    let outcome = tasks::execute(&job, &ctx).await.unwrap();
    assert_eq!(outcome.counters.processed, 1);
    assert_eq!(source.hits.load(Ordering::SeqCst), 1);
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}
