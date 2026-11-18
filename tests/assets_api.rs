mod support;

use axum::http::{Method, StatusCode};
use lastest::db::import::{ImportedFinding, ImportedObservation};
use lastest::domain::Role;
use serde_json::{json, Value};
use support::{call, TestEnv};

const SEEN: &str = "2026-11-18T10:00:00Z";

fn observe(env: &TestEnv, project: &str, kind: &str, asset: &str, data: Value) {
    env.db
        .insert_import_observation(
            project,
            None,
            &ImportedObservation {
                source: "fixture".into(),
                kind: if kind == "url" { "http" } else { kind }.into(),
                asset_kind: kind.into(),
                asset: asset.into(),
                canonical: asset.into(),
                data,
                scope_status: "observed".into(),
                observed_at: SEEN.into(),
            },
        )
        .unwrap();
}

fn project(env: &TestEnv, name: &str) -> String {
    env.db
        .create_project(name, "", "", None, None, "admin")
        .unwrap()
        .id
}

fn finding(env: &TestEnv, project: &str, asset: &str) {
    env.db
        .insert_import_finding(
            project,
            None,
            &ImportedFinding {
                source: "fixture".into(),
                rule_id: "fixture".into(),
                severity: "info".into(),
                title: "Fixture".into(),
                asset: asset.into(),
                evidence: json!({}),
                first_seen: SEEN.into(),
                last_seen: SEEN.into(),
            },
        )
        .unwrap();
}

#[tokio::test]
async fn inventory_search_paging_and_exports_cover_all_rows() {
    let env = TestEnv::new();
    let project = project(&env, "inventory");
    let cookie = env.login_web().await;
    let headers = [("Host", "localhost"), ("Cookie", cookie.as_str())];
    for index in 0..315 {
        let host = format!("host-{index:03}.example.test");
        observe(
            &env,
            &project,
            "host",
            &host,
            json!({"addresses": ["203.0.113.1", "2001:db8::1"]}),
        );
        observe(&env, &project, "ip", "203.0.113.1", json!({"host": host}));
    }
    observe(&env, &project, "ip", "203.0.113.9", json!({}));
    env.db
        .connect()
        .unwrap()
        .execute(
            "UPDATE observations SET observed_at = '2026-11-18T11:00:00Z'
         WHERE project_id = ?1 AND json_extract(data, '$.host') = 'host-314.example.test'",
            [&project],
        )
        .unwrap();
    let base = format!("/api/projects/{project}/assets");
    let first = call(&env.app, Method::GET, &base, None, &headers).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.body["total"], 316);
    assert_eq!(first.body["items"].as_array().unwrap().len(), 10);
    assert_eq!(
        first.body["items"][0]["ips"],
        json!(["2001:db8::1", "203.0.113.1"])
    );
    assert_eq!(first.body["items"][0]["last_seen"], SEEN);
    let tail = call(
        &env.app,
        Method::GET,
        &format!("{base}?offset=99999"),
        None,
        &headers,
    )
    .await;
    assert_eq!(tail.body["offset"], 310);
    assert_eq!(tail.body["items"].as_array().unwrap().len(), 6);
    assert_eq!(tail.body["items"][3]["last_seen"], SEEN);
    assert_eq!(tail.body["items"][4]["last_seen"], "2026-11-18T11:00:00Z");
    assert!(tail.body["items"][5]["host"].is_null());
    for (query, total) in [
        ("HOST-314", 1),
        ("2001%3Adb8%3A%3A1", 315),
        ("203.0.113.9", 1),
        ("absent", 0),
        ("%25", 0),
    ] {
        let result = call(
            &env.app,
            Method::GET,
            &format!("{base}?q={query}&offset=10"),
            None,
            &headers,
        )
        .await;
        assert_eq!(result.body["total"], total, "{}", result.text);
    }
    for format in ["txt", "csv"] {
        let export = call(
            &env.app,
            Method::GET,
            &format!("{base}/export/{format}?offset=310"),
            None,
            &headers,
        )
        .await;
        assert_eq!(export.status, StatusCode::OK);
        assert_eq!(export.text.lines().count(), 317);
        assert!(export.text.contains("host-314.example.test"));
        assert!(!export.text.contains("First seen"));
        let filtered = call(
            &env.app,
            Method::GET,
            &format!("{base}/export/{format}?q=HOST-314"),
            None,
            &headers,
        )
        .await;
        assert_eq!(filtered.text.lines().count(), 2);
        assert!(filtered.text.contains("host-314.example.test"));
        if format == "csv" {
            let mut reader = csv::Reader::from_reader(filtered.text.as_bytes());
            assert_eq!(reader.headers().unwrap().len(), 3);
            let row = reader.records().next().unwrap().unwrap();
            assert_eq!(&row[1], "2001:db8::1, 203.0.113.1");
        }
    }
}

#[test]
fn inventory_links_dns_ptr_and_http_without_assigning_redirect_ips_to_original_hosts() {
    let env = TestEnv::new();
    let project = project(&env, "relationships");
    for host in ["origin.test", "final.test", "dns.test", "ptr.test"] {
        observe(&env, &project, "host", host, json!({}));
    }
    observe(
        &env,
        &project,
        "host",
        "origin.test",
        json!({"url": "https://final.test/", "verified_ip": "203.0.113.2"}),
    );
    observe(
        &env,
        &project,
        "url",
        "https://final.test/",
        json!({"url": "https://final.test/", "verified_ip": "203.0.113.2"}),
    );
    observe(
        &env,
        &project,
        "host",
        "dns.test",
        json!({"record_type": "A", "value": "203.0.113.3"}),
    );
    observe(
        &env,
        &project,
        "host",
        "dns.test",
        json!({"record_type": "AAAA", "value": "2001:db8::3"}),
    );
    env.db
        .insert_import_observation(
            &project,
            None,
            &ImportedObservation {
                source: "fixture".into(),
                kind: "ptr".into(),
                asset_kind: "ip".into(),
                asset: "203.0.113.4".into(),
                canonical: "203.0.113.4".into(),
                data: json!({"name": "PTR.TEST."}),
                scope_status: "observed".into(),
                observed_at: SEEN.into(),
            },
        )
        .unwrap();
    let rows = env.db.inventory_rows(&project, "").unwrap();
    assert_eq!(rows.len(), 4);
    let ips = |host| {
        rows.iter()
            .find(|row| row.host.as_deref() == Some(host))
            .unwrap()
            .ips
            .clone()
    };
    assert!(ips("origin.test").is_empty());
    assert_eq!(ips("final.test"), ["203.0.113.2"]);
    assert_eq!(ips("dns.test"), ["2001:db8::3", "203.0.113.3"]);
    assert_eq!(ips("ptr.test"), ["203.0.113.4"]);
}

#[tokio::test]
async fn deletion_preserves_shared_ips_other_hosts_and_project_boundaries() {
    let env = TestEnv::new();
    let project = project(&env, "deletion");
    let other = self::project(&env, "other-project");
    let cookie = env.login_web().await;
    let headers = [
        ("Host", "localhost"),
        ("Origin", "http://localhost"),
        ("Cookie", cookie.as_str()),
    ];
    for host in [
        "example.test",
        "other.test",
        "child.example.test",
        "example.test.evil.test",
    ] {
        observe(&env, &project, "host", host, json!({}));
        observe(&env, &project, "ip", "203.0.113.1", json!({"host": host}));
        observe(
            &env,
            &project,
            "url",
            &format!("https://{host}/path"),
            json!({"verified_ip": "203.0.113.1"}),
        );
        finding(&env, &project, &format!("https://{host}/path"));
    }
    observe(
        &env,
        &project,
        "ip",
        "203.0.113.8",
        json!({"host": "example.test"}),
    );
    observe(&env, &other, "host", "example.test", json!({}));
    finding(&env, &project, "203.0.113.1");
    let assets = env.db.list_assets(&project, 100).unwrap();
    let host_id = assets
        .iter()
        .find(|a| a["value"] == "example.test")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let ip_id = assets.iter().find(|a| a["value"] == "203.0.113.1").unwrap()["id"]
        .as_str()
        .unwrap();
    let route = format!("/api/projects/{project}/assets/{host_id}");
    let cross = call(
        &env.app,
        Method::DELETE,
        &format!("/api/projects/{other}/assets/{host_id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);
    let linked = call(
        &env.app,
        Method::DELETE,
        &format!("/api/projects/{project}/assets/{ip_id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(linked.status, StatusCode::CONFLICT);
    let deleted = call(&env.app, Method::DELETE, &route, None, &headers).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text);
    let remaining = env.db.list_assets(&project, 100).unwrap();
    assert_eq!(remaining.len(), 8); // Three hosts, their URLs, and two preserved IPs.
    assert!(!remaining
        .iter()
        .any(|a| a["value"] == "example.test" || a["value"] == "https://example.test/path"));
    assert_eq!(env.db.list_assets(&other, 100).unwrap().len(), 1);
    let observations = env.db.all_observations(&project, 100).unwrap();
    assert!(!observations
        .iter()
        .any(|o| o.canonical_asset == "example.test" || o.data["host"] == "example.test"));
    assert!(observations
        .iter()
        .any(|o| o.data["host"] == "other.test" && o.canonical_asset == "203.0.113.1"));
    assert_eq!(env.db.all_findings(&project).unwrap().len(), 4);
    let inventory = env.db.inventory_rows(&project, "").unwrap();
    assert_eq!(inventory.len(), 4);
    let orphan = inventory.iter().find(|row| row.host.is_none()).unwrap();
    assert_eq!(orphan.ips, ["203.0.113.8"]);
    let deleted_ip = call(
        &env.app,
        Method::DELETE,
        &format!("/api/projects/{project}/assets/{}", orphan.id),
        None,
        &headers,
    )
    .await;
    assert_eq!(deleted_ip.status, StatusCode::NO_CONTENT);
    let again = call(&env.app, Method::DELETE, &route, None, &headers).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    let conn = env.db.connect().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM audit_events WHERE action='asset.delete'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
}

#[tokio::test]
async fn asset_permissions_and_csrf_are_enforced() {
    let env = TestEnv::new();
    let project = project(&env, "permissions");
    observe(&env, &project, "host", "example.test", json!({}));
    let row = env.db.inventory_rows(&project, "").unwrap().remove(0);
    let base = format!("/api/projects/{project}/assets");
    let route = format!("{base}/{}", row.id);
    for suffix in ["", "/export/txt", "/export/csv"] {
        assert_eq!(
            call(&env.app, Method::GET, &format!("{base}{suffix}"), None, &[])
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(&env.app, Method::DELETE, &route, None, &[])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let cookie = env.login_web().await;
    for headers in [
        vec![("Host", "localhost"), ("Cookie", cookie.as_str())],
        vec![
            ("Host", "localhost"),
            ("Origin", "http://evil.test"),
            ("Cookie", cookie.as_str()),
        ],
    ] {
        let result = call(&env.app, Method::DELETE, &route, None, &headers).await;
        assert_eq!(result.status, StatusCode::FORBIDDEN);
        assert_eq!(result.body["error"]["code"], "csrf_failed");
    }
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
        .login("viewer", "ViewerPassword!123", "web")
        .unwrap();
    let viewer_cookie = format!("lastest_session={}", viewer.token);
    let viewer_headers = [
        ("Host", "localhost"),
        ("Origin", "http://localhost"),
        ("Cookie", viewer_cookie.as_str()),
    ];
    assert_eq!(
        call(&env.app, Method::DELETE, &route, None, &viewer_headers)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    for suffix in ["", "/export/txt", "/export/csv"] {
        assert_eq!(
            call(
                &env.app,
                Method::GET,
                &format!("{base}{suffix}"),
                None,
                &viewer_headers
            )
            .await
            .status,
            StatusCode::OK
        );
    }
    env.auth
        .create_user(
            "admin",
            "analyst",
            "AnalystPassword!123",
            Role::Analyst,
            false,
            None,
        )
        .unwrap();
    let analyst = env
        .auth
        .login("analyst", "AnalystPassword!123", "cli")
        .unwrap();
    let bearer = format!("Bearer {}", analyst.token);
    let result = call(
        &env.app,
        Method::DELETE,
        &route,
        None,
        &[("Authorization", &bearer)],
    )
    .await;
    assert_eq!(result.status, StatusCode::NO_CONTENT);
    let empty = call(
        &env.app,
        Method::GET,
        &format!("{base}?offset=10"),
        None,
        &viewer_headers,
    )
    .await;
    assert_eq!(empty.body["total"], 0);
    assert_eq!(empty.body["offset"], 0);
}
