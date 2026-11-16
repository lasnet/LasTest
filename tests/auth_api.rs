mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;
use support::{as_pairs, call, cookie_headers, TestEnv};

#[tokio::test]
async fn setup_codes_expire_rotate_and_are_consumed_atomically() {
    let env = TestEnv::empty();
    let route = "/api/auth/setup";
    let headers = [("Host", "localhost"), ("Origin", "http://localhost")];
    let credentials = |code: &str| {
        Some(json!({
            "code": code,
            "username": "admin",
            "password": "CorrectHorseBatteryStaple!"
        }))
    };
    let status = call(&env.app, Method::GET, route, None, &[]).await;
    assert_eq!(status.body["required"], true);

    let (old, _) = env.auth.issue_setup_code().unwrap();
    let (code, _) = env.auth.issue_setup_code().unwrap();
    let response = call(&env.app, Method::POST, route, credentials(&old), &headers).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let response = call(
        &env.app,
        Method::POST,
        route,
        credentials(&code),
        &[("Host", "localhost"), ("Origin", "https://outside.example")],
    )
    .await;
    assert_eq!(response.body["error"]["code"], "csrf_failed");
    env.db
        .connect()
        .unwrap()
        .execute("UPDATE setup_code SET expires_at = 0", [])
        .unwrap();
    let response = call(&env.app, Method::POST, route, credentials(&code), &headers).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(env.db.count_users().unwrap(), 0);

    let (code, _) = env.auth.issue_setup_code().unwrap();
    let first = call(&env.app, Method::POST, route, credentials(&code), &headers);
    let second = call(&env.app, Method::POST, route, credentials(&code), &headers);
    let (first, second) = tokio::join!(first, second);
    let mut codes = [first.status, second.status];
    codes.sort();
    assert_eq!(codes[0], StatusCode::CREATED);
    assert!(matches!(
        codes[1],
        StatusCode::FORBIDDEN | StatusCode::CONFLICT
    ));
    assert_eq!(env.db.count_users().unwrap(), 1);
    assert!(env.auth.issue_setup_code().is_err());
    let status = call(&env.app, Method::GET, route, None, &[]).await;
    assert_eq!(status.body["required"], false);
    assert!(env
        .auth
        .login("admin", "CorrectHorseBatteryStaple!", "web")
        .is_ok());
}

#[test]
fn existing_database_migrates_without_reopening_administrator_setup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lastest.sqlite");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT);
             INSERT INTO schema_migrations VALUES (1, '2026-11-15T00:00:00Z');
             INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
             VALUES ('existing', 'admin', 'existing-hash', 'admin', '', '');",
        )
        .unwrap();
    }
    let db = lastest::db::Db::new(path).unwrap();
    assert_eq!(db.schema_version().unwrap(), lastest::db::SCHEMA_VERSION);
    assert_eq!(
        db.user_by_username("admin").unwrap().unwrap().id,
        "existing"
    );
    assert!(!db.store_setup_code("unavailable", i64::MAX).unwrap());
}

#[tokio::test]
async fn login_cookie_me_logout_and_revocation() {
    let env = TestEnv::new();
    let response = call(
        &env.app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": "CorrectHorseBatteryStaple!"})),
        &[("Host", "localhost"), ("Origin", "http://localhost")],
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let cookie = response
        .headers
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("Secure"));
    let cookie_pair = cookie.split(';').next().unwrap().to_string();

    let me = call(
        &env.app,
        Method::GET,
        "/api/auth/me",
        None,
        &[("Host", "localhost"), ("Cookie", &cookie_pair)],
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["role"], "admin");

    let logout = call(
        &env.app,
        Method::POST,
        "/api/auth/logout",
        Some(json!({})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie_pair),
        ],
    )
    .await;
    assert_eq!(logout.status, StatusCode::OK);
    let after = call(
        &env.app,
        Method::GET,
        "/api/auth/me",
        None,
        &[("Host", "localhost"), ("Cookie", &cookie_pair)],
    )
    .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_session_is_rejected() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let conn = env.db.connect().unwrap();
    conn.execute(
        "UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'",
        [],
    )
    .unwrap();
    drop(conn);
    let response = call(
        &env.app,
        Method::GET,
        "/api/auth/me",
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn csrf_origin_check_for_cookie_requests() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let missing = call(
        &env.app,
        Method::POST,
        "/api/projects",
        Some(json!({"name": "csrf-missing"})),
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    assert_eq!(missing.body["error"]["code"], "csrf_failed");
    let mismatched = call(
        &env.app,
        Method::POST,
        "/api/projects",
        Some(json!({"name": "csrf-mismatch"})),
        &[
            ("Host", "localhost"),
            ("Origin", "https://evil.example"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(mismatched.status, StatusCode::FORBIDDEN);
    let allowed = call(
        &env.app,
        Method::POST,
        "/api/projects",
        Some(json!({"name": "csrf-ok"})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(allowed.status, StatusCode::CREATED);
}

#[tokio::test]
async fn roles_viewer_analyst_admin_and_audit() {
    let env = TestEnv::new();
    env.auth
        .create_user(
            "admin",
            "viewer",
            "ViewerPassword!123",
            lastest::domain::Role::Viewer,
            false,
            None,
        )
        .unwrap();
    let viewer_cookie = {
        let result = env
            .auth
            .login("viewer", "ViewerPassword!123", "web")
            .unwrap();
        format!("lastest_session={}", result.token)
    };
    let read = call(
        &env.app,
        Method::GET,
        "/api/projects",
        None,
        &[("Host", "localhost"), ("Cookie", &viewer_cookie)],
    )
    .await;
    assert_eq!(read.status, StatusCode::OK);
    let write = call(
        &env.app,
        Method::POST,
        "/api/projects",
        Some(json!({"name": "viewer-project"})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &viewer_cookie),
        ],
    )
    .await;
    assert_eq!(write.status, StatusCode::FORBIDDEN);
    let audit_forbidden = call(
        &env.app,
        Method::GET,
        "/api/audit",
        None,
        &[("Host", "localhost"), ("Cookie", &viewer_cookie)],
    )
    .await;
    assert_eq!(audit_forbidden.status, StatusCode::FORBIDDEN);

    let admin_cookie = env.login_web().await;
    let audit = call(
        &env.app,
        Method::GET,
        "/api/audit?limit=200",
        None,
        &[("Host", "localhost"), ("Cookie", &admin_cookie)],
    )
    .await;
    assert_eq!(audit.status, StatusCode::OK);
    let actions: Vec<&str> = audit.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["action"].as_str())
        .collect();
    assert!(actions.contains(&"auth.login"));
    assert!(actions.contains(&"user.create"));
}

#[tokio::test]
async fn last_active_admin_cannot_be_disabled_or_demoted() {
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let me = call(
        &env.app,
        Method::GET,
        "/api/auth/me",
        None,
        &[("Host", "localhost"), ("Cookie", &cookie)],
    )
    .await;
    let admin_id = me.body["user"]["id"].as_str().unwrap().to_string();
    let disable = call(
        &env.app,
        Method::PATCH,
        &format!("/api/users/{admin_id}"),
        Some(json!({"is_active": false})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(disable.status, StatusCode::CONFLICT);
    assert_eq!(disable.body["error"]["code"], "last_admin");
    let demote = call(
        &env.app,
        Method::PATCH,
        &format!("/api/users/{admin_id}"),
        Some(json!({"role": "viewer"})),
        &[
            ("Host", "localhost"),
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
        ],
    )
    .await;
    assert_eq!(demote.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn cli_bearer_login_and_generic_login_failures() {
    let env = TestEnv::new();
    let cli = call(
        &env.app,
        Method::POST,
        "/api/auth/login",
        Some(json!({
            "username": "admin",
            "password": "CorrectHorseBatteryStaple!",
            "client": "cli"
        })),
        &[("Host", "localhost")],
    )
    .await;
    assert_eq!(cli.status, StatusCode::OK);
    let token = cli.body["token"].as_str().unwrap().to_string();
    assert!(cli.headers.get("set-cookie").is_none());
    let me = call(
        &env.app,
        Method::GET,
        "/api/auth/me",
        None,
        &[
            ("Host", "localhost"),
            ("Authorization", &format!("Bearer {token}")),
        ],
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);

    let bad_user = call(
        &env.app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "nobody", "password": "whatever"})),
        &[("Host", "localhost")],
    )
    .await;
    let bad_password = call(
        &env.app,
        Method::POST,
        "/api/auth/login",
        Some(json!({"username": "admin", "password": "wrong-password"})),
        &[("Host", "localhost")],
    )
    .await;
    assert_eq!(bad_user.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad_password.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        bad_user.body["error"]["message"],
        bad_password.body["error"]["message"]
    );
}

#[tokio::test]
async fn task_catalog_and_project_requires_selection_semantics() {
    let env = TestEnv::new();
    let viewer_cookie = env.login_web().await;
    let types = call(
        &env.app,
        Method::GET,
        "/api/task-types",
        None,
        &[("Host", "localhost"), ("Cookie", &viewer_cookie)],
    )
    .await;
    assert_eq!(types.status, StatusCode::OK);
    let names: Vec<&str> = types.body["task_types"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert!(names.contains(&"dns.records"));
    assert!(names.contains(&"web.checks"));
    assert!(types.body["web_check_rules"].as_array().unwrap().len() >= 3);
    let _ = as_pairs(&cookie_headers(&viewer_cookie));
}
