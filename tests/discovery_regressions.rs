mod support;

use lastest::db::jobs::CompleteOutcome;
use lastest::domain::{JobStatus, NewCandidate};
use lastest::scope::Scope;
use lastest::tasks::{
    asset_classify, asset_enrich, dns_tasks, provider, tech_catalog, TaskContext, TaskOutcome,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use support::{
    make_job, scope_rules, spawn_dns_response_server, spawn_http_server, task_context,
    HttpResponse, TestEnv,
};

fn publish(ctx: &TaskContext, outcome: TaskOutcome) -> String {
    let scope = ctx.db.current_scope(&ctx.project_id).unwrap().unwrap();
    let job = ctx
        .db
        .enqueue_job(
            &ctx.project_id,
            "http.probe",
            &json!({}),
            &scope.id,
            scope.version,
            None,
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = ctx.db.claim_next_job("regression", 60).unwrap().unwrap();
    assert!(ctx
        .db
        .complete_attempt(
            &job.id,
            &claim.attempt_id,
            CompleteOutcome {
                status: JobStatus::Succeeded,
                result: outcome.result,
                counters: outcome.counters,
                error: None,
                observations: outcome.observations,
                findings: outcome.findings,
                candidates: outcome.candidates,
                enrichments: outcome.enrichments,
                classifications: outcome.classifications,
                artifacts: Vec::new(),
            }
        )
        .unwrap());
    job.id
}

fn host_and_http(host: &str, url: &str, product: &str) -> TaskOutcome {
    let mut outcome = TaskOutcome::new();
    outcome.observe(
        "http.probe",
        "host",
        "host",
        host,
        json!({"addresses":["127.0.0.1"]}),
        "allowed",
    );
    outcome.observe(
        "http.probe",
        "http",
        "url",
        url,
        json!({"url":url, "status_code":403,
        "technologies":[{"name":product,"version":"1.2","source":"body",
        "evidence":[{"source":"body", "evidence":"product marker", "version":"1.2"}]}]}),
        "allowed",
    );
    outcome
}

#[cfg(unix)]
#[tokio::test]
async fn whatweb_enriches_the_saved_response_and_keeps_native_evidence_on_failure() {
    use std::os::unix::fs::PermissionsExt;

    let env = TestEnv::new();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("exact", "localhost")])).unwrap(),
        "whatweb-http-response",
    );
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![127, 0, 0, 1]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    let server = spawn_http_server(|_| {
        HttpResponse::new(200, "<p>Use jquery-1.2.3.min.js</p><script src='https://cdn.example.test/jquery-3.7.1.min.js?token=secret-fixture'></script>")
            .header("Content-Type", "text/html")
            .header("Server", "nginx/1.26.3")
            .header("X-Jenkins", "2.516.1")
            .header("Set-Cookie", "session=secret-fixture")
    })
    .await;
    let url = format!("http://localhost:{}/fixture", server.addr.port());
    publish(&ctx, host_and_http("localhost", &url, "nginx"));
    let asset = env
        .db
        .host_asset_by_canonical(&ctx.project_id, "localhost")
        .unwrap()
        .unwrap();
    let path = env.temp.path().join("whatweb-fixture");
    std::fs::write(&path, r#"#!/bin/sh
set -eu
test "$1" = '--plugins=jenkins,jquery'
test "$2" = '--aggression=1'
test "$3" = '--follow-redirect=never'
test "$7" = '--log-json=-'
test "$#" -eq 8
case "$8" in /*/response.http) ;; *) exit 12 ;; esac
grep -q 'X-Jenkins: 2.516.1' "$8"
grep -q 'jquery-3.7.1.min.js' "$8"
if grep -Eq 'secret-fixture|http://localhost|cdn.example.test|jquery-1.2.3' "$8"; then exit 13; fi
printf '[{"target":"%s","http_status":200,"plugins":{"Jenkins":{"version":["2.516.1","bad version"]},"JQuery":{"version":["3.7.1"]},"Unexpected":{"version":["1.2"]}}}]\n' "$8"
"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let job = make_job(
        "assets.enrich",
        json!({"asset_ids":[asset["id"]],"http_enrichment":true}),
    );
    ctx.config.whatweb_path = Some(path.clone());
    let outcome = asset_enrich::run(&job, &ctx).await.unwrap();
    let technologies = &outcome.enrichments[0].data["technologies"];
    for (name, version) in [("jenkins", "2.516.1"), ("jquery", "3.7.1")] {
        assert!(
            technologies
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == name
                    && row["versions"] == json!([version])
                    && row["evidence"][0]["source"] == "whatweb"),
            "{technologies}"
        );
    }
    assert!(!technologies.to_string().contains("Unexpected"));
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);

    std::fs::write(path, "#!/bin/sh\nprintf 'not JSON'\n").unwrap();
    let fallback = asset_enrich::run(&job, &ctx).await.unwrap();
    assert!(fallback.error.is_none(), "{:?}", fallback.error);
    assert!(fallback.enrichments[0].data["technologies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["name"] == "nginx"));
    assert!(!fallback.enrichments[0].data["technologies"]
        .to_string()
        .contains("whatweb"));

    publish(&ctx, outcome);
    let details = env
        .db
        .asset_detail(&ctx.project_id, asset["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert!(details["technologies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["name"] == "jquery"
            && row["version"] == "3.7.1"
            && row["sources"] == json!(["whatweb"])));
}

#[tokio::test]
async fn failed_http_enrichment_keeps_attempt_details_in_the_summary_artifact() {
    let env = TestEnv::new();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("exact", "localhost")])).unwrap(),
        "http-failure-details",
    );
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![127, 0, 0, 1]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let url = format!("http://localhost:{port}/unavailable");
    publish(&ctx, host_and_http("localhost", &url, "nginx"));
    let asset = env
        .db
        .host_asset_by_canonical(&ctx.project_id, "localhost")
        .unwrap()
        .unwrap();
    let outcome = asset_enrich::run(
        &make_job(
            "assets.enrich",
            json!({"asset_ids":[asset["id"]],"http_enrichment":true}),
        ),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(outcome.status, JobStatus::Partial);
    assert_eq!(outcome.counters.errors, 1);
    assert_eq!(outcome.result["candidates"][0]["http_enriched"], false);
    assert_eq!(
        outcome.result["candidates"][0]["http_errors"][0]["url"],
        url
    );
    assert!(outcome.result["candidates"][0]["http_errors"][0]["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
    let artifact: serde_json::Value =
        serde_json::from_slice(&outcome.artifacts[0].content).unwrap();
    assert_eq!(
        artifact["candidates"][0]["http_errors"],
        outcome.result["candidates"][0]["http_errors"]
    );
}

#[tokio::test]
async fn existing_host_assets_retain_http_and_explicit_selection_never_falls_back() {
    let env = TestEnv::new();
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "selected-assets");
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![127, 0, 0, 1]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    publish(
        &ctx,
        host_and_http(
            "chosen.allowed.test",
            "https://chosen.allowed.test/app",
            "wordpress",
        ),
    );
    let mut other = TaskOutcome::new();
    other.candidate(NewCandidate::new("other.allowed.test", "ptr", "ptr"));
    publish(&ctx, other);
    let asset = ctx
        .db
        .host_asset_by_canonical(&ctx.project_id, "chosen.allowed.test")
        .unwrap()
        .unwrap();
    let detail = ctx
        .db
        .asset_detail(&ctx.project_id, asset["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(detail["http"].as_array().unwrap().len(), 1);
    assert_eq!(detail["technologies"][0]["name"], "wordpress");
    let params = json!({"asset_ids":[asset["id"]]});
    let outcome = asset_classify::run(&make_job("assets.classify", params.clone()), &ctx)
        .await
        .unwrap();
    assert_eq!(outcome.result["classified"], 1);
    assert_eq!(
        outcome.result["subjects"][0]["groups"],
        json!(["wordpress"])
    );
    assert!(outcome
        .classifications
        .iter()
        .any(|c| c.subject_type == "service"));
    let enriched = asset_enrich::run(&make_job("assets.enrich", params), &ctx)
        .await
        .unwrap();
    assert_eq!(enriched.enrichments.len(), 1);
    assert_eq!(enriched.enrichments[0].host, "chosen.allowed.test");
    assert_eq!(enriched.enrichments[0].data["http"][0]["status_code"], 403);
    for task in ["assets.enrich", "assets.classify"] {
        let job = make_job(task, json!({"candidate_ids":["missing"]}));
        let outcome = if task == "assets.enrich" {
            asset_enrich::run(&job, &ctx).await
        } else {
            asset_classify::run(&job, &ctx).await
        };
        assert!(
            outcome.is_err(),
            "missing selection must not select other project data"
        );
    }
}

#[test]
fn stored_technology_roundtrip_preserves_conflicting_versions_and_unknown_products() {
    let observed = json!({"technologies":[{"name":"custom-product", "version":null,
        "versions":["1.0","2.0"], "source":"body", "evidence":[
            {"source":"header", "evidence":"first marker", "version":"1.0"},
            {"source":"body", "evidence":"second marker", "version":"2.0"}]}]});
    let first = tech_catalog::from_stored(&[observed]);
    let second = tech_catalog::from_stored(&[json!({"technologies":first})]);
    assert_eq!(first, second);
    assert_eq!(second[0]["name"], "custom-product");
    assert_eq!(second[0]["versions"], json!(["1.0", "2.0"]));
    assert_eq!(second[0]["evidence"].as_array().unwrap().len(), 2);
}

#[test]
fn committed_candidate_snapshot_is_not_overwritten_by_a_neighbouring_run() {
    let env = TestEnv::new();
    let ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
        "snapshots",
    );
    let mut first = TaskOutcome::new();
    first.candidate(
        NewCandidate::new("same.allowed.test", "ptr", "ptr").with_ip(Some("203.0.113.1".into())),
    );
    first.candidate(
        NewCandidate::new("same.allowed.test", "reverse.ip", "dns_check").with_dns(
            "verified",
            vec!["203.0.113.1".into()],
            "matched",
            "allowed",
        ),
    );
    let job = publish(&ctx, first);
    let mut second = TaskOutcome::new();
    second.candidate(
        NewCandidate::new("same.allowed.test", "censys", "provider_name")
            .with_ip(Some("203.0.113.2".into())),
    );
    second.candidate(
        NewCandidate::new("same.allowed.test", "reverse.ip", "dns_check").with_dns(
            "no_addresses",
            vec![],
            "unknown",
            "allowed",
        ),
    );
    publish(&ctx, second);
    let snapshot = ctx.db.candidates_for_job(&job).unwrap();
    assert_eq!(snapshot[0]["dns_status"], "verified");
    assert_eq!(snapshot[0]["addresses"], json!(["203.0.113.1"]));
    assert_eq!(snapshot[0]["sources"], json!(["ptr"]));
    assert_eq!(snapshot[0]["source_ips"], json!(["203.0.113.1"]));
}

#[tokio::test]
async fn reverse_dns_discovery_checks_exact_domain_children_and_counts_every_published_name() {
    let env = TestEnv::new();
    let server =
        spawn_http_server(|_| HttpResponse::new(200, "{\"hostnames\":[\"api.allowed.test\"]}"))
            .await;
    let dns = spawn_dns_response_server(|_, kind| {
        if kind == 1 {
            (0, vec![vec![203, 0, 113, 20]])
        } else {
            (3, Vec::new())
        }
    })
    .await;
    let scope = Scope::new(scope_rules(&[
        ("ip", "203.0.113.10"),
        ("exact", "allowed.test"),
    ]))
    .unwrap();
    let mut ctx = task_context(&env, scope, "dns-children");
    ctx.config.shodan_internetdb_url = format!("http://{}", server.addr);
    ctx.config.dns_server = Some(dns.addr.to_string());
    let result = dns_tasks::run_reverse_ip(
        &make_job(
            "reverse.ip",
            json!({
        "ips":["203.0.113.10"],"sources":["shodan_internetdb"]}),
        ),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(result.result["counts"]["published"], 1);
    assert_eq!(result.result["checks"][0]["ip_match"], "not_matched");
    assert_eq!(result.result["checks"][0]["scope_status"], "denied");
    assert!(result
        .observations
        .iter()
        .any(|o| o.asset_kind == "host" && o.kind == "host"));
}

#[tokio::test]
async fn cache_requests_stop_after_scope_narrows_during_backoff() {
    let env = TestEnv::new();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let server = spawn_http_server(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        HttpResponse::new(503, "unavailable")
    })
    .await;
    let scope = Scope::new(scope_rules(&[("ip", "203.0.113.10")])).unwrap();
    let mut ctx = task_context(&env, scope, "scope-backoff");
    ctx.config.provider_min_interval_ms = 0;
    let task_ctx = ctx.clone();
    let url = format!("http://{}/203.0.113.10", server.addr);
    let run = tokio::spawn(async move {
        provider::fetch_json_cached(
            &task_ctx,
            "shodan_internetdb",
            "internetdb",
            "fixture",
            "fixture",
            "public",
            "203.0.113.10",
            &url,
            provider::headers(&[]),
            4096,
        )
        .await
    });
    while hits.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let current = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    env.db
        .replace_scope(
            &ctx.project_id,
            Some(current.version),
            &Scope::new(vec![]).unwrap(),
            "narrowed",
            "admin",
            true,
        )
        .unwrap();
    let result = run.await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_ne!(result.status, provider::FetchStatus::Ok);
}

#[test]
fn shared_limiter_honours_subsecond_intervals_and_reentrant_owners() {
    use lastest::db::provider_cache::ReserveOutcome;
    let env = TestEnv::new();
    let conn = env.db.connect().unwrap();
    let now = chrono::Utc::now();
    let next = (now + chrono::Duration::milliseconds(250))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    conn.execute("INSERT INTO provider_state(provider, namespace, next_allowed_at, updated_at) VALUES ('test','ns',?1,?2)",
        [&next, &now.to_rfc3339()]).unwrap();
    assert!(matches!(
        env.db
            .provider_try_acquire("key", "test", "ns", "owner", 60, 300)
            .unwrap(),
        ReserveOutcome::Wait(_)
    ));
    conn.execute("DELETE FROM provider_state", []).unwrap();
    assert_eq!(
        env.db
            .provider_try_acquire("key", "test", "ns", "owner", 60, 0)
            .unwrap(),
        ReserveOutcome::Acquired
    );
    assert_eq!(
        env.db
            .provider_try_acquire("key", "test", "ns", "owner", 60, 0)
            .unwrap(),
        ReserveOutcome::Acquired
    );
}

#[tokio::test]
async fn rotated_censys_credentials_do_not_reuse_a_previous_credentials_cache() {
    let env = TestEnv::new();
    let server = spawn_http_server(|request| {
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer "));
        assert!(request.starts_with("GET /v3/global/asset/host/203.0.113.10 "));
        HttpResponse::new(
            200,
            "{\"result\":{\"resource\":{\"ip\":\"203.0.113.10\",\"dns\":{\"names\":[]}}}}",
        )
    })
    .await;
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("ip", "203.0.113.10")])).unwrap(),
        "pat-rotation",
    );
    let mut endpoint = url::Url::parse(&ctx.config.censys_platform_url).unwrap();
    assert_eq!(
        endpoint.path(),
        "/v3/global/asset/host",
        "documented Censys Platform v3 host route"
    );
    endpoint.set_scheme("http").unwrap();
    endpoint.set_host(Some("127.0.0.1")).unwrap();
    endpoint.set_port(Some(server.addr.port())).unwrap();
    ctx.config.censys_platform_url = endpoint.to_string();
    ctx.config.provider_min_interval_ms = 0;
    let job = make_job(
        "reverse.ip",
        json!({"ips":["203.0.113.10"],"sources":["censys"]}),
    );
    ctx.config.censys_pat = Some("first-fixture-token".into());
    dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    ctx.config.censys_pat = Some("second-fixture-token".into());
    dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    let requests = server.requests.lock().unwrap();
    assert!(requests[1].contains("second-fixture-token"));
}

#[tokio::test]
async fn chain_defaults_and_idempotency_are_validated_before_replaying() {
    use axum::http::{Method, StatusCode};
    use support::{as_pairs, call, cookie_headers};
    let env = TestEnv::new();
    let (project, _) = env.project_with_scope(
        "default-chain",
        scope_rules(&[("ip", "203.0.113.10")]),
        true,
    );
    let cookie = env.login_web().await;
    let headers = cookie_headers(&cookie);
    let path = format!("/api/projects/{}/chains", project.id);
    let body = json!({"preset":"asset_discovery","idempotency_key":"same"});
    let first = call(
        &env.app,
        Method::POST,
        &path,
        Some(body.clone()),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.text);
    assert_eq!(
        first.body["jobs"][0]["params"]["sources"],
        json!(["ptr", "shodan_internetdb"])
    );
    let again = call(
        &env.app,
        Method::POST,
        &path,
        Some(body),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(again.body["idempotent_replay"], true);
    let changed = call(
        &env.app,
        Method::POST,
        &path,
        Some(json!({"preset":"asset_discovery",
        "idempotency_key":"same","sources":["ptr"]})),
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn candidate_pagination_and_filtered_export_cover_the_full_inventory() {
    use axum::http::{Method, StatusCode};
    use support::{as_pairs, call, cookie_headers};
    let env = TestEnv::new();
    let ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("exact", "first.allowed.test")])).unwrap(),
        "candidate-paging",
    );
    let mut data = TaskOutcome::new();
    data.candidate(NewCandidate::new("first.allowed.test", "ptr", "ptr"));
    data.candidate(NewCandidate::new(
        "other.allowed.test",
        "censys",
        "provider_name",
    ));
    publish(&ctx, data);
    let mut config = env.config.clone();
    config.max_discovery_candidates = 1;
    let app = lastest::api::router(Arc::new(lastest::api::AppState::new(
        config,
        env.db.clone(),
    )));
    let cookie = env.login_web().await;
    let headers = cookie_headers(&cookie);
    let base = format!("/api/projects/{}/discovery", ctx.project_id);
    let second = call(
        &app,
        Method::GET,
        &format!("{base}/candidates?limit=1&offset=1"),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    assert_eq!(second.body["total"], 2);
    assert_eq!(second.body["items"].as_array().unwrap().len(), 1);
    let export = call(
        &app,
        Method::GET,
        &format!("{base}/export/json?scope_status=denied&source=censys"),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(export.status, StatusCode::OK, "{}", export.text);
    assert_eq!(export.body["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(
        export.body["candidates"][0]["hostname"],
        "other.allowed.test"
    );
    let invalid = call(
        &app,
        Method::GET,
        &format!("{base}/export/json?dns_status=bogus"),
        None,
        &as_pairs(&headers),
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cancellation_during_http_response_prevents_following_redirects() {
    use lastest::tasks::http_tasks;
    let env = TestEnv::new();
    let ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("ip", "127.0.0.1")])).unwrap(),
        "cancel-redirect",
    );
    let target = spawn_http_server(|_| HttpResponse::new(200, "must not be contacted")).await;
    let destination = format!("http://{}/", target.addr);
    let cancel = ctx.cancel.clone();
    let source = spawn_http_server(move |_| {
        cancel.store(true, Ordering::SeqCst);
        HttpResponse::new(302, "").header("Location", &destination)
    })
    .await;
    let job = make_job(
        "http.probe",
        json!({"targets":[format!("http://{}/",source.addr)],"mode":"url"}),
    );
    let _ = http_tasks::run_probe(&job, &ctx).await;
    assert_eq!(source.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        target.hits.load(Ordering::SeqCst),
        0,
        "cancelled task must not start a redirected request"
    );
}
