mod support;

use axum::http::{Method, StatusCode};
use lastest::api::{router, AppState};
use lastest::domain::{JobStatus, Role};
use lastest::scope::{RuleKind, Scope, ScopeRule};
use lastest::tasks::{passive, subfinder};
use lastest::worker::Worker;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};
use support::{
    as_pairs, call, cookie_headers, make_job, scope_rules, spawn_dns_server, spawn_http_server,
    task_context, HttpResponse, TestEnv,
};

fn executable(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn saved_keys_are_admin_only_masked_encrypted_and_used_after_rotation() {
    let env = TestEnv::new();
    env.auth
        .create_user(
            "admin",
            "viewer",
            "ViewerFixturePassword",
            Role::Viewer,
            false,
            None,
        )
        .unwrap();
    let viewer = env
        .auth
        .login("viewer", "ViewerFixturePassword", "cli")
        .unwrap();
    let authorization = format!("Bearer {}", viewer.token);
    let viewer_headers = [("Authorization", authorization.as_str())];
    let uri = "/api/settings/providers";
    let denied = call(&env.app, Method::GET, uri, None, &viewer_headers).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let censys_uri = "/api/settings/providers/censys";
    let denied = call(
        &env.app,
        Method::PUT,
        censys_uri,
        Some(json!({"key":"denied-provider-token"})),
        &viewer_headers,
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let denied = call(
        &env.app,
        Method::POST,
        "/api/settings/wordlists",
        Some(json!({"name":"Denied", "contents":"web"})),
        &viewer_headers,
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let cookie = env.login_web().await;
    let cross_site = [
        ("Host", "localhost"),
        ("Origin", "https://untrusted.test"),
        ("Cookie", cookie.as_str()),
    ];
    let denied = call(
        &env.app,
        Method::PUT,
        censys_uri,
        Some(json!({"key":"denied-provider-token"})),
        &cross_site,
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let admin_headers = cookie_headers(&cookie);
    let admin = as_pairs(&admin_headers);
    let bad_key = call(
        &env.app,
        Method::PUT,
        censys_uri,
        Some(json!({"key":"invalid\nprovider-token"})),
        &admin,
    )
    .await;
    assert_eq!(bad_key.status, StatusCode::BAD_REQUEST);
    let certspotter = "certspotter-fixture-1234";
    let old_censys = "censys-initial-fixture-7890";
    let replacement = "censys-replaced-fixture-9876";
    for (uri, key) in [
        ("/api/settings/providers/certspotter", certspotter),
        (censys_uri, old_censys),
        (censys_uri, replacement),
        ("/api/settings/providers/shodan", "shodan-fixture-3000"),
    ] {
        let result = call(&env.app, Method::PUT, uri, Some(json!({"key":key})), &admin).await;
        assert_eq!(result.status, StatusCode::NO_CONTENT, "{}", result.text);
        assert!(result.text.is_empty());
    }

    let status = call(&env.app, Method::GET, uri, None, &admin).await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.headers["cache-control"], "no-store");
    let providers = status.body["providers"].as_array().unwrap();
    let censys = providers
        .iter()
        .find(|item| item["id"] == "censys")
        .unwrap();
    assert_eq!(censys["last_four"], "9876");
    assert_eq!(
        censys["applications"],
        json!(["Subfinder", "Asset Discovery", "Reverse IP"])
    );
    let public = call(
        &env.app,
        Method::GET,
        "/api/providers",
        None,
        &viewer_headers,
    )
    .await;
    assert_eq!(
        public.body["providers"]["censys"]["mode"],
        "platform_v3_pat"
    );
    assert!(public.body["providers"]["censys"]
        .get("last_four")
        .is_none());
    let audit = call(&env.app, Method::GET, "/api/audit", None, &admin).await;
    assert!(audit.text.contains("provider.key.update"));
    for key in [certspotter, old_censys, replacement] {
        assert!(!status.text.contains(key));
        assert!(!public.text.contains(key));
        assert!(!audit.text.contains(key));
    }
    let bytes: Vec<u8> = env
        .db
        .connect()
        .unwrap()
        .query_row(
            "SELECT ciphertext FROM provider_credentials WHERE provider = 'censys'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!bytes
        .windows(replacement.len())
        .any(|window| window == replacement.as_bytes()));
    assert_eq!(
        env.config
            .data_dir
            .join("providers.key")
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let provider = spawn_http_server(|request| {
        if request.starts_with("GET /ct?") {
            HttpResponse::new(200, "[]")
        } else {
            HttpResponse::new(
                200,
                r#"{"result":{"resource":{"hostnames":[],"services":[]}}}"#,
            )
        }
        .header("Content-Type", "application/json")
    })
    .await;
    let dns = spawn_dns_server(|_, _| Vec::new()).await;
    let scope = Scope::new(scope_rules(&[
        ("exact", "approved.test"),
        ("ip", "203.0.113.10"),
    ]))
    .unwrap();
    let mut ctx = task_context(&env, scope, "settings-key-fixture");
    ctx.config.certspotter_url = format!("http://{}/ct", provider.addr);
    ctx.config.censys_platform_url = format!("http://{}/hosts", provider.addr);
    ctx.config.dns_server = Some(dns.addr.to_string());
    ctx.config.censys_pat = Some("server-fallback-fixture".into());
    ctx.config.censys_organization_id = Some("example-organization".into());

    passive::run_subdomains(
        &make_job("subdomains.discover", json!({"domains":["approved.test"]})),
        &ctx,
    )
    .await
    .unwrap();
    let chain = call(
        &env.app,
        Method::POST,
        &format!("/api/projects/{}/chains", ctx.project_id),
        Some(json!({"preset":"asset_discovery", "sources":["ptr"], "use_configured_censys":true})),
        &admin,
    )
    .await;
    assert_eq!(chain.status, StatusCode::ACCEPTED, "{}", chain.text);
    let queued = env
        .db
        .claim_next_job("fixture-worker", 30)
        .unwrap()
        .unwrap();
    assert_eq!(queued.job.task_type, "reverse.ip");
    assert_eq!(queued.job.params["use_configured_censys"], true);
    Worker::new(ctx.config.clone(), env.db.clone())
        .run_claimed(
            queued.job,
            queued.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    {
        let requests = provider.requests.lock().unwrap();
        assert!(requests
            .iter()
            .any(|request| request.contains(&format!("authorization: Bearer {certspotter}"))));
        assert!(requests
            .iter()
            .any(|request| request.contains(&format!("authorization: Bearer {replacement}"))));
        assert!(requests.iter().all(|request| !request.contains(old_censys)));
    }

    ctx.config.subfinder_path = Some(executable(
        env.temp.path(),
        "subfinder",
        r#"#!/bin/sh
set -eu
cp "$SUBFINDER_PROVIDER_CONFIG" "$(dirname "$0")/received.yaml"
cat "$SUBFINDER_PROVIDER_CONFIG" >&2
exit 42
"#,
    ));
    let result = subfinder::run(
        &make_job("subdomains.subfinder", json!({"domains":["approved.test"]})),
        &ctx,
    )
    .await
    .unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        &std::fs::read_to_string(env.temp.path().join("received.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(yaml["certspotter"][0].as_str(), Some(certspotter));
    assert_eq!(
        yaml["censys"][0].as_str(),
        Some("censys-replaced-fixture-9876:example-organization")
    );
    assert_eq!(yaml["shodan"][0].as_str(), Some("shodan-fixture-3000"));
    let diagnostics = result.errors.join("\n");
    assert!(diagnostics.contains("42"));
    assert!(!diagnostics.contains(certspotter));
    assert!(!diagnostics.contains(replacement));
    assert_eq!(ctx.config.tmp_dir().read_dir().unwrap().count(), 0);
}

#[tokio::test]
async fn named_wordlist_is_validated_queued_executed_and_returned_with_evidence() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let admin_headers = cookie_headers(&cookie);
    let admin = as_pairs(&admin_headers);
    let dns = spawn_dns_server(|name, qtype| match (name, qtype) {
        ("web.approved.test", 1) | ("excluded.approved.test", 1) => vec![vec![203, 0, 113, 10]],
        _ => Vec::new(),
    })
    .await;
    let mut config = env.config.clone();
    config.dns_server = Some(dns.addr.to_string());
    config.dnsmap_path = Some(executable(
        env.temp.path(),
        "dnsmap",
        r#"#!/bin/sh
set -eu
while IFS= read -r word; do
  printf '%s.%s\n' "$word" "$1"
done < "$3"
"#,
    ));
    let app = router(Arc::new(AppState::new(config.clone(), env.db.clone())));
    let uri = "/api/settings/wordlists";
    let bad = call(
        &app,
        Method::POST,
        uri,
        Some(json!({"name":"Invalid","contents":"web\nwrong word"})),
        &admin,
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.text.contains("line 2"));
    let created = call(
        &app,
        Method::POST,
        uri,
        Some(
            json!({"name":"Approved services","contents":"\u{feff}WEB\r\nexcluded\r\n\r\nweb\r\n"}),
        ),
        &admin,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let wordlist = &created.body["wordlist"];
    let id = wordlist["id"].as_str().unwrap();
    assert_eq!(wordlist["entries"], 2);
    assert!(wordlist.get("contents").is_none());
    let duplicate = call(
        &app,
        Method::POST,
        uri,
        Some(json!({"name":"approved services","contents":"another"})),
        &admin,
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let catalog = call(&app, Method::GET, "/api/task-types", None, &admin).await;
    assert_eq!(
        catalog.body["dns_wordlists"],
        json!([{"id":"default","name":"default","entries":989},wordlist])
    );
    let tasks = catalog.body["task_types"].as_array().unwrap();
    let dnsmap = tasks
        .iter()
        .find(|task| task["name"] == "dns.wordlist")
        .unwrap();
    assert_eq!(
        dnsmap["params_schema"]["properties"]["wordlist"]["enum"],
        json!(["default", id])
    );
    assert_eq!(
        dnsmap["params_schema"]["properties"]["concurrency"],
        json!({"type":"integer","enum":[10,20,50,100],"default":20})
    );

    let mut rules = scope_rules(&[("exact", "approved.test")]);
    rules.push(ScopeRule::new(RuleKind::ExactDomain, "excluded.approved.test", true).unwrap());
    let (project, _) = env.project_with_scope("wordlist-settings", rules, true);
    let job_uri = format!("/api/projects/{}/jobs", project.id);
    let rejected = call(
        &app,
        Method::POST,
        &job_uri,
        Some(json!({
            "task_type":"dns.wordlist","params":{"domain":"approved.test","wordlist":"wl_missing"}
        })),
        &admin,
    )
    .await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);

    let accepted = call(
        &app,
        Method::POST,
        &job_uri,
        Some(json!({
            "task_type":"dns.wordlist","params":{"domain":"approved.test","wordlist":id}
        })),
        &admin,
    )
    .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{}", accepted.text);
    let claim = env
        .db
        .claim_next_job("fixture-worker", 30)
        .unwrap()
        .unwrap();
    let jid = claim.job.id.clone();
    Worker::new(config, env.db.clone())
        .run_claimed(
            claim.job,
            claim.attempt_id,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let finished = call(&app, Method::GET, &format!("/api/jobs/{jid}"), None, &admin).await;
    assert_eq!(
        finished.body["job"]["status"],
        JobStatus::Succeeded.as_str()
    );
    assert_eq!(finished.body["job"]["result"]["wordlist"], id);
    assert_eq!(
        finished.body["job"]["result"]["found"],
        json!(["web.approved.test"])
    );
    let evidence = finished.body["job"]["artifacts"][0]["href"]
        .as_str()
        .unwrap();
    let evidence = call(&app, Method::GET, evidence, None, &admin).await;
    assert_eq!(evidence.status, StatusCode::OK);
    assert_eq!(evidence.body["wordlist"], id);
    assert_eq!(evidence.body["found"], json!(["web.approved.test"]));
}
