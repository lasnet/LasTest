mod support;

use lastest::scope::{
    canonical_cidr, canonical_ip, canonical_url_key, normalize_domain, EffectiveScope,
    NetworkPolicy, RuleKind, Scope, ScopeError, ScopeRule,
};
use lastest::tasks;
use serde_json::json;
use support::{scope_rules, spawn_http_server, HttpResponse, TestEnv};

fn scope(items: &[(&str, &str, bool)]) -> Scope {
    let rules = items
        .iter()
        .map(|(kind, value, exclusion)| {
            let kind = match *kind {
                "exact" => RuleKind::ExactDomain,
                "tree" => RuleKind::SubdomainTree,
                "ip" => RuleKind::Ip,
                "cidr" => RuleKind::Cidr,
                other => panic!("unknown kind {other}"),
            };
            ScopeRule::new(kind, value, *exclusion).unwrap()
        })
        .collect();
    Scope::new(rules).unwrap()
}

#[test]
fn explicit_and_tree_rules_with_exclusion_priority() {
    let scope = scope(&[
        ("exact", "www.example.com", false),
        ("tree", "example.org", false),
        ("tree", "secret.example.org", true),
    ]);
    assert!(scope.allows_host("www.example.com"));
    assert!(!scope.allows_host("api.example.com"));
    assert!(scope.allows_host("a.b.example.org"));
    assert!(!scope.allows_host("secret.example.org"));
    assert!(!scope.allows_host("x.secret.example.org"));
}

#[test]
fn idna_ipv6_cidr_and_label_boundaries() {
    assert_eq!(
        normalize_domain("BÜCHER.Example.").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(
        canonical_ip("::ffff:203.0.113.9").unwrap(),
        "203.0.113.9".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        canonical_cidr("2001:db8::1/32").unwrap().to_string(),
        "2001:db8::/32"
    );
    assert!(normalize_domain(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(normalize_domain("example..com").is_err());
    assert!(normalize_domain("https://example.com/path").is_err());
    let scope = scope(&[
        ("ip", "2001:db8::1", false),
        ("cidr", "203.0.113.0/24", false),
    ]);
    assert!(scope.allows_ip("2001:db8::1".parse().unwrap()));
    assert!(scope.allows_ip("203.0.113.200".parse().unwrap()));
    assert!(!scope.allows_ip("198.51.100.1".parse().unwrap()));
}

#[test]
fn ambiguous_url_and_deduplication_key() {
    assert!(canonical_url_key("https://example.com/#frag").is_ok());
    assert_eq!(
        canonical_url_key("HTTPS://Example.com:443/a#frag").unwrap(),
        "https://example.com/a"
    );
    assert!(matches!(
        canonical_url_key("ftp://example.com/x"),
        Err(ScopeError::Url(_))
    ));
    assert!(matches!(
        canonical_url_key("http://user:pass@example.com/x"),
        Err(ScopeError::Url(_))
    ));
}

#[test]
fn metadata_and_internal_policy() {
    let empty = NetworkPolicy::default();
    assert!(empty.permits("169.254.169.254".parse().unwrap()).is_err());
    assert!(empty.permits("127.0.0.1".parse().unwrap()).is_err());
    assert!(empty.permits("10.0.0.1".parse().unwrap()).is_err());
    assert!(empty.permits("203.0.113.5".parse().unwrap()).is_ok());
    let configured = NetworkPolicy::new(vec!["127.0.0.0/8".parse().unwrap()]);
    assert!(configured.permits("127.0.0.1".parse().unwrap()).is_ok());
}

#[test]
fn scope_narrowing_applies_to_existing_snapshot() {
    let env = TestEnv::new();
    let (project, snapshot) =
        env.project_with_scope("narrow", scope_rules(&[("tree", "example.com")]), true);
    let current = env
        .db
        .replace_scope(
            &project.id,
            Some(snapshot.version),
            &scope(&[
                ("tree", "example.com", false),
                ("exact", "www.example.com", true),
            ]),
            "narrow",
            "admin",
            true,
        )
        .unwrap();
    let effective = EffectiveScope::new(snapshot.scope.clone(), current.scope.clone());
    assert!(effective.allows_host("api.example.com"));
    assert!(!effective.allows_host("www.example.com"));
    assert!(effective.allows_host("new.example.com"));
    // The old snapshot remains readable and unchanged.
    let stored = env
        .db
        .scope_by_version(&project.id, snapshot.version)
        .unwrap()
        .unwrap();
    assert!(stored.scope.allows_host("www.example.com"));
}

#[test]
fn explicit_parameters_outside_scope_are_rejected_before_queueing() {
    let env = TestEnv::new();
    let scope = scope(&[("tree", "allowed.example", false)]);
    let err = tasks::validate_scope_targets(
        "http.probe",
        &json!({"targets": ["https://outside.example/"]}),
        &scope,
        &env.config,
    )
    .unwrap_err();
    assert!(err.to_string().contains("outside the approved scope"));
    let err = tasks::validate_scope_targets(
        "tcp.connect",
        &json!({"ips": ["203.0.113.10"], "ports": [443]}),
        &scope,
        &env.config,
    )
    .unwrap_err();
    assert!(err.to_string().contains("not explicitly allowed"));
}

#[tokio::test]
async fn redirect_out_of_scope_is_blocked_without_request() {
    let env = TestEnv::new();
    let outside = spawn_http_server(|_| HttpResponse::new(200, "secret")).await;
    let location = format!("http://127.0.0.1:{}/secret", outside.addr.port());
    let inside =
        spawn_http_server(move |_| HttpResponse::new(302, "").header("Location", &location)).await;
    let prober = lastest::net::HttpProber::new(&env.config).unwrap();
    let scope = scope(&[("exact", "localhost", false)]);
    let error = prober
        .get_in_scope(
            &format!("http://localhost:{}/start", inside.addr.port()),
            &scope,
            &env.config.network_policy(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("not allowed by scope")
            || error.to_string().contains("not explicitly allowed")
    );
    assert_eq!(outside.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn in_scope_redirect_is_followed_and_host_is_preserved() {
    let env = TestEnv::new();
    let target = spawn_http_server(|request| {
        let host = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("host:"))
            .unwrap_or("");
        HttpResponse::new(200, format!("ok {host}"))
            .header("Strict-Transport-Security", "max-age=60")
    })
    .await;
    let location = format!("http://localhost:{}/final", target.addr.port());
    let entry =
        spawn_http_server(move |_| HttpResponse::new(302, "").header("Location", &location)).await;
    let prober = lastest::net::HttpProber::new(&env.config).unwrap();
    let scope = scope(&[("exact", "localhost", false)]);
    let result = prober
        .get_in_scope(
            &format!("http://localhost:{}/start", entry.addr.port()),
            &scope,
            &env.config.network_policy(),
        )
        .await
        .unwrap();
    assert_eq!(result.status, 200);
    assert_eq!(result.redirects.len(), 1);
    assert!(result.body.contains("host: localhost"));
    assert_eq!(target.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn blocked_internal_destination_never_opens_a_socket() {
    let mut env_config = TestEnv::new().config;
    env_config.internal_ranges.clear();
    let server = spawn_http_server(|_| HttpResponse::new(200, "should-not-be-hit")).await;
    let prober = lastest::net::HttpProber::new(&env_config).unwrap();
    let scope = scope(&[("exact", "localhost", false)]);
    let error = prober
        .get_in_scope(
            &format!("http://localhost:{}/", server.addr.port()),
            &scope,
            &env_config.network_policy(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("blocked") || error.to_string().contains("internal"));
    assert_eq!(server.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn active_task_uses_current_scope_on_the_next_network_operation() {
    let env = TestEnv::new();
    let snapshot_scope = scope(&[("tree", "example.com", false)]);
    let ctx = support::task_context(&env, snapshot_scope, "narrow-active");
    assert!(ctx.allows_host_now("www.example.com"));
    let current = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    env.db
        .replace_scope(
            &ctx.project_id,
            Some(current.version),
            &scope(&[
                ("tree", "example.com", false),
                ("exact", "www.example.com", true),
            ]),
            "operator narrowed scope",
            "admin",
            true,
        )
        .unwrap();
    assert!(ctx.scope.snapshot.allows_host("www.example.com"));
    assert!(!ctx.allows_host_now("www.example.com"));
    assert!(ctx.allows_host_now("api.example.com"));
}
