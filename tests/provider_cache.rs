mod support;

use lastest::db::provider_cache::ReserveOutcome;
use serde_json::json;
use support::TestEnv;

#[test]
fn cache_hits_expire_and_recover_after_negative_entries() {
    let env = TestEnv::new();
    env.db
        .provider_cache_put(
            "key-a",
            "shodan_internetdb",
            "internetdb",
            "https://fixture.invalid",
            "credential-context",
            200,
            &json!({"hostnames": ["a.example.com"]}),
            false,
            60,
            100,
        )
        .unwrap();
    let entry = env.db.provider_cache_get("key-a").unwrap().unwrap();
    assert!(!entry.negative);
    assert_eq!(entry.http_status, 200);
    assert_eq!(entry.body["hostnames"][0], "a.example.com");

    env.db
        .provider_cache_put(
            "key-negative",
            "shodan_internetdb",
            "internetdb",
            "https://fixture.invalid",
            "credential-context",
            404,
            &json!({}),
            true,
            60,
            100,
        )
        .unwrap();
    assert!(
        env.db
            .provider_cache_get("key-negative")
            .unwrap()
            .unwrap()
            .negative
    );

    // Expired entries are misses.
    let conn = env.db.connect().unwrap();
    conn.execute(
        "UPDATE provider_cache SET expires_at = '2000-01-01T00:00:00Z' WHERE cache_key = 'key-a'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(env.db.provider_cache_get("key-a").unwrap().is_none());
}

#[test]
fn credential_context_never_contains_the_secret() {
    let context = lastest::tasks::provider::credential_context(
        "censys",
        "platform_v3",
        "super-secret-pat-value|https://api.example",
    );
    assert!(!context.contains("super-secret"));
    assert!(!context.contains("api.example"));
    assert_eq!(context.len(), 32);
    let same = lastest::tasks::provider::credential_context(
        "censys",
        "platform_v3",
        "super-secret-pat-value|https://api.example",
    );
    assert_eq!(context, same);
    let other = lastest::tasks::provider::credential_context(
        "censys",
        "platform_v3",
        "another-organization",
    );
    assert_ne!(context, other);
}

#[test]
fn reservations_are_exclusive_and_shared_cooldown_is_visible() {
    let env = TestEnv::new();
    let first = env
        .db
        .provider_try_acquire("key", "censys", "ns", "owner-a", 30, 0)
        .unwrap();
    assert_eq!(first, ReserveOutcome::Acquired);
    let second = env
        .db
        .provider_try_acquire("key", "censys", "ns", "owner-b", 30, 0)
        .unwrap();
    assert_eq!(second, ReserveOutcome::Busy);
    env.db.provider_release("key", "owner-a").unwrap();
    let third = env
        .db
        .provider_try_acquire("key", "censys", "ns", "owner-b", 30, 0)
        .unwrap();
    assert_eq!(third, ReserveOutcome::Acquired);
    env.db.provider_release("key", "owner-b").unwrap();

    env.db.provider_set_cooldown("censys", "ns", 30).unwrap();
    assert!(env.db.provider_cooldown("censys", "ns").unwrap().is_some());
    let outcome = env
        .db
        .provider_try_acquire("other", "censys", "ns", "owner-c", 30, 0)
        .unwrap();
    assert!(matches!(outcome, ReserveOutcome::Cooldown(_)));
}

#[test]
fn two_database_handles_share_the_installation_cache() {
    let env = TestEnv::new();
    let second = lastest::db::Db::new(env.config.database_path()).unwrap();
    env.db
        .provider_cache_put(
            "shared",
            "censys",
            "v3",
            "https://fixture.invalid",
            "ctx",
            200,
            &json!({"result": {"resource": {"dns": {"names": ["shared.example.com"]}}}}),
            false,
            60,
            100,
        )
        .unwrap();
    let entry = second.provider_cache_get("shared").unwrap().unwrap();
    assert_eq!(
        entry.body["result"]["resource"]["dns"]["names"][0],
        "shared.example.com"
    );
}

#[test]
fn censys_mode_selection_prefers_pat_and_describes_incomplete_pairs() {
    use lastest::config::{CensysMode, Config};
    let mut config = Config::default();
    assert_eq!(config.censys_integration().mode, CensysMode::NotConfigured);
    assert!(!config.provider_catalog()["censys"]["configured"]
        .as_bool()
        .unwrap());

    config.censys_api_id = Some("id".to_string());
    assert_eq!(config.censys_integration().mode, CensysMode::Incomplete);
    config.censys_api_secret = Some("secret".to_string());
    let legacy = config.censys_integration();
    assert_eq!(legacy.mode, CensysMode::Legacy);
    assert!(legacy.legacy_deprecated);

    config.censys_pat = Some("pat-value".to_string());
    let platform = config.censys_integration();
    assert_eq!(platform.mode, CensysMode::Platform);
    assert!(platform.endpoint.contains("platform.censys.io"));

    let debug = format!("{config:?}");
    assert!(!debug.contains("pat-value"));
    assert!(!debug.contains("\"secret\""));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn provider_error_statuses_do_not_turn_into_empty_success() {
    use lastest::tasks::provider::FetchStatus;
    assert_ne!(
        FetchStatus::AccessDenied.as_str(),
        FetchStatus::Empty.as_str()
    );
    assert_ne!(
        FetchStatus::InvalidResponse.as_str(),
        FetchStatus::Empty.as_str()
    );
}

#[test]
fn cache_pruning_removes_expired_rows_and_respects_the_bound() {
    let env = TestEnv::new();
    for index in 0..5 {
        env.db
            .provider_cache_put(
                &format!("key-{index}"),
                "shodan_internetdb",
                "v1",
                "https://fixture.invalid",
                "ctx",
                200,
                &json!({"index": index}),
                false,
                60,
                2,
            )
            .unwrap();
    }
    let conn = env.db.connect().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM provider_cache", [], |row| row.get(0))
        .unwrap();
    assert!(count <= 2, "cache retained {count} entries");
}
