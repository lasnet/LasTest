mod v2_support;

use lastest::scope::Scope;
use lastest::tasks::{dns_tasks, http_tasks, network, nmap, passive, web_checks};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use v2_support::{
    encode_dns_name, make_job, scope_rules, spawn_dns_server, spawn_http_server, task_context,
    HttpResponse, TestEnv,
};

#[tokio::test]
async fn local_dns_records_and_wildcard_wordlist() {
    let env = TestEnv::new();
    let dns = spawn_dns_server(|name, qtype| match qtype {
        1 if name.ends_with("allowed.test") => vec![vec![203, 0, 113, 10]],
        28 if name.ends_with("allowed.test") => {
            vec![vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
            ]]
        }
        12 => vec![encode_dns_name("ptr.allowed.test")],
        _ => Vec::new(),
    })
    .await;
    let mut config = env.config.clone();
    config.dns_server = Some(dns.addr.to_string());
    let scope = Scope::new(scope_rules(&[
        ("tree", "allowed.test"),
        ("cidr", "203.0.113.0/24"),
    ]))
    .unwrap();
    let ctx = task_context(&env, scope.clone(), "dns-job");
    let mut ctx = ctx;
    ctx.config = config.clone();
    let job = make_job(
        "dns.records",
        json!({"targets": ["www.allowed.test"], "record_types": ["A", "AAAA"]}),
    );
    let outcome = dns_tasks::run_records(&job, &ctx).await.unwrap();
    assert_eq!(outcome.status, lastest::domain::JobStatus::Succeeded);
    let dns_observations = outcome
        .observations
        .iter()
        .filter(|item| item.kind == "dns")
        .count();
    assert_eq!(dns_observations, 2);
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.asset == "203.0.113.10"));
    assert!(dns
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|(name, qtype)| name == "www.allowed.test" && *qtype == 1));

    let mut ctx = task_context(&env, scope, "wordlist-job");
    ctx.config = config;
    let job = make_job(
        "dns.wordlist",
        json!({"domain": "allowed.test", "words": ["www", "api"]}),
    );
    let outcome = dns_tasks::run_wordlist(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["found"].as_array().unwrap().len(), 0);
    assert!(!outcome.result["wildcard_addresses"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn passive_archive_sources_deduplicate_and_preserve_origin() {
    let env = TestEnv::new();
    let server = spawn_http_server(|request| {
        let path = request.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
        if path.starts_with("/collinfo") {
            let host = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            return HttpResponse::new(
                200,
                format!("[{{\"cdx-api\":\"http://{host}/cc-index\"}}]"),
            );
        }
        if path.starts_with("/cc-index") {
            return HttpResponse::new(
                200,
                "{\"url\":\"https://allowed.test/from-cc\"}\n{\"url\":\"https://allowed.test/from-cc\"}\n",
            );
        }
        if path.starts_with("/cdx") {
            return HttpResponse::new(
                200,
                "[[\"original\"],[\"https://allowed.test/a\"],[\"https://allowed.test/a\"],[\"https://outside.test/b\"]]",
            );
        }
        HttpResponse::new(404, "")
    })
    .await;
    let mut config = env.config.clone();
    config.wayback_url = format!("http://127.0.0.1:{}/cdx", server.addr.port());
    config.commoncrawl_url = format!("http://127.0.0.1:{}/collinfo", server.addr.port());
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "url-job");
    ctx.config = config;
    let job = make_job(
        "urls.passive",
        json!({"domains": ["allowed.test"], "sources": ["wayback"], "limit": 20}),
    );
    let outcome = passive::run_urls_passive(&job, &ctx).await.unwrap();
    let urls: Vec<_> = outcome
        .observations
        .iter()
        .filter(|item| item.kind == "url")
        .collect();
    assert_eq!(urls.len(), 2);
    assert!(urls.iter().any(|item| item.source == "wayback"
        && item.asset == "https://allowed.test/a"
        && item.scope_status == "allowed"));
    assert!(urls
        .iter()
        .any(|item| item.asset == "https://outside.test/b" && item.scope_status == "denied"));

    let job = make_job(
        "urls.passive",
        json!({"domains": ["allowed.test"], "sources": ["commoncrawl"], "limit": 20}),
    );
    let outcome = passive::run_urls_passive(&job, &ctx).await.unwrap();
    let cc: Vec<_> = outcome
        .observations
        .iter()
        .filter(|item| item.source == "commoncrawl")
        .collect();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].asset, "https://allowed.test/from-cc");
}

#[tokio::test]
async fn crawler_handles_relative_links_and_blocks_outside_host() {
    let env = TestEnv::new();
    let server = spawn_http_server(|request| {
        let path = request.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
        if path == "/a" {
            return HttpResponse::new(200, "<html><title>A</title><body>done</body></html>")
                .header("Content-Type", "text/html");
        }
        HttpResponse::new(
            200,
            "<html><title>Root</title><a href=\"/a\">a</a><a href=\"/a#dup\">dup</a><a href=\"http://outside.test/x\">out</a></html>",
        )
        .header("Content-Type", "text/html")
    })
    .await;
    let scope = Scope::new(scope_rules(&[("exact", "localhost")])).unwrap();
    let mut ctx = task_context(&env, scope, "crawl-job");
    ctx.config.max_crawl_pages = 10;
    let job = make_job(
        "http.crawl",
        json!({"seeds": [format!("http://localhost:{}/", server.addr.port())], "max_pages": 10, "max_depth": 2}),
    );
    let outcome = http_tasks::run_crawl(&job, &ctx).await.unwrap();
    assert!(outcome.counters.processed >= 2);
    assert!(outcome.observations.iter().any(|item| item.kind == "url"
        && item.scope_status == "denied"
        && item.asset.contains("outside.test")));
    assert_eq!(
        outcome
            .observations
            .iter()
            .filter(|item| item.kind == "url" && item.asset.ends_with("/a"))
            .count(),
        1
    );
}

#[tokio::test]
async fn path_discovery_suppresses_soft_404() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| HttpResponse::new(200, "generic not found page")).await;
    let scope = Scope::new(scope_rules(&[("exact", "localhost")])).unwrap();
    let ctx = task_context(&env, scope, "paths-job");
    let job = make_job(
        "paths.discover",
        json!({
            "base_urls": [format!("http://localhost:{}/", server.addr.port())],
            "words": ["admin", "login", "api"]
        }),
    );
    let outcome = http_tasks::run_paths(&job, &ctx).await.unwrap();
    assert_eq!(outcome.counters.processed, 0);
    assert_eq!(outcome.result["soft_404"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn reverse_ip_provider_is_labeled_separately() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| {
        HttpResponse::new(200, "{\"ports\":[443],\"hostnames\":[\"x.test\"]}")
            .header("Content-Type", "application/json")
    })
    .await;
    let mut config = env.config.clone();
    config.shodan_internetdb_url = format!("http://127.0.0.1:{}", server.addr.port());
    config.http_timeout_seconds = 1;
    let scope = Scope::new(scope_rules(&[
        ("ip", "203.0.113.10"),
        ("tree", "allowed.test"),
    ]))
    .unwrap();
    let mut ctx = task_context(&env, scope, "reverse-job");
    ctx.config = config;
    let job = make_job(
        "reverse.ip",
        json!({"ips": ["203.0.113.10"], "providers": ["shodan_internetdb"]}),
    );
    let outcome = dns_tasks::run_reverse_ip(&job, &ctx).await.unwrap();
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.source == "shodan_internetdb"
            && item.kind == "provider"
            && item.asset == "203.0.113.10"));
}

#[tokio::test]
async fn socks5_proxy_receives_the_validated_ip_not_a_hostname() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(head[3], 1, "ATYP must be IPv4");
        let mut ip = [0u8; 4];
        stream.read_exact(&mut ip).await.unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        captured_clone
            .lock()
            .unwrap()
            .push((ip, u16::from_be_bytes(port)));
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90])
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    });
    let env = TestEnv::new();
    let mut config = env.config.clone();
    config.socks5_profiles = vec![lastest::config::Socks5Profile {
        name: "test".to_string(),
        host: "127.0.0.1".to_string(),
        port: proxy_addr.port(),
        username: None,
        password: None,
    }];
    let scope = Scope::new(scope_rules(&[("ip", "203.0.113.10")])).unwrap();
    let mut ctx = task_context(&env, scope, "socks-job");
    ctx.config = config;
    let job = make_job(
        "tcp.connect",
        json!({"ips": ["203.0.113.10"], "ports": [8443], "proxy_profile": "test"}),
    );
    let outcome = network::run_tcp(&job, &ctx).await.unwrap();
    assert_eq!(
        outcome.result["confirmed_ports"].as_array().unwrap().len(),
        1
    );
    let (captured_ip, captured_port) = {
        let captured = captured.lock().unwrap();
        (captured[0].0, captured[0].1)
    };
    assert_eq!(captured_ip, [203, 0, 113, 10]);
    assert_eq!(captured_port, 8443);
    handle.await.unwrap();
}

#[tokio::test]
async fn nmap_adapter_uses_fixed_arguments_and_parses_xml() {
    let env = TestEnv::new();
    let temp = tempfile::TempDir::new().unwrap();
    let args_file = temp.path().join("args.txt");
    let script = temp.path().join("nmap");
    let xml = r#"<?xml version="1.0"?><nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"><cpe>cpe:/a:nginx:nginx</cpe></service></port></ports></host></nmaprun>"#;
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat <<'XML'\n{}\nXML\n",
            args_file.display(),
            xml
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = env.config.clone();
    config.nmap_path = Some(script.clone());
    let scope = Scope::new(scope_rules(&[("ip", "203.0.113.10")])).unwrap();
    let mut ctx = task_context(&env, scope, "nmap-job");
    ctx.config = config;
    let job = make_job(
        "nmap.profile",
        json!({"ips": ["203.0.113.10"], "ports": [443]}),
    );
    let outcome = nmap::run(&job, &ctx).await.unwrap();
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.kind == "service"
            && item.data["port"] == 443
            && item.data["service"] == "https"
            && item.data["product"] == "nginx"));
    assert_eq!(outcome.artifacts.len(), 1);
    let args = std::fs::read_to_string(args_file).unwrap();
    assert!(args.contains("-sT"));
    assert!(args.contains("-n"));
    assert!(args.contains("--unprivileged"));
    assert!(args.contains("203.0.113.10"));

    let mut missing = task_context(
        &env,
        Scope::new(scope_rules(&[("ip", "203.0.113.10")])).unwrap(),
        "nmap-missing",
    );
    missing.config.nmap_path = None;
    let error = nmap::run(&job, &missing).await.unwrap_err();
    assert!(error.to_string().contains("unavailable"));
}

#[tokio::test]
async fn web_checks_do_not_create_findings_for_http_or_failed_measurement() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| HttpResponse::new(200, "plain http")).await;
    let scope = Scope::new(scope_rules(&[("exact", "localhost")])).unwrap();
    let ctx = task_context(&env, scope, "web-job");
    let job = make_job(
        "web.checks",
        json!({"targets": [format!("http://localhost:{}/", server.addr.port())]}),
    );
    let outcome = web_checks::run(&job, &ctx).await.unwrap();
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.status, lastest::domain::JobStatus::Succeeded);

    let failed_job = make_job(
        "web.checks",
        json!({"targets": [format!("https://localhost:{}/", server.addr.port())]}),
    );
    let failed = web_checks::run(&failed_job, &ctx).await.unwrap();
    assert!(
        failed.findings.is_empty(),
        "measurement errors never create findings"
    );
    assert!(!failed.errors.is_empty());
}

#[tokio::test]
async fn certificate_transparency_pagination_wildcards_and_quota_errors() {
    let env = TestEnv::new();
    let server = spawn_http_server(|request| {
        let path = request
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("");
        let host = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("host:"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        if path.starts_with("/ct-next") {
            return HttpResponse::new(
                200,
                "[{\"dns_names\":[\"api.allowed.test\",\"www.allowed.test\",\"*.allowed.test\"]}]",
            );
        }
        if path.starts_with("/ct") {
            return HttpResponse::new(
                200,
                "[{\"dns_names\":[\"www.allowed.test\",\"outside.test\"]}]",
            )
            .header("Link", &format!("<http://{host}/ct-next>; rel=\"next\""));
        }
        HttpResponse::new(404, "")
    })
    .await;
    let mut config = env.config.clone();
    config.certspotter_url = format!("http://127.0.0.1:{}/ct", server.addr.port());
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "ct-job");
    ctx.config = config.clone();
    let job = make_job(
        "subdomains.discover",
        json!({"domains": ["allowed.test"], "providers": ["certspotter"]}),
    );
    let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
    let hosts: Vec<_> = outcome
        .observations
        .iter()
        .filter(|item| item.kind == "host")
        .map(|item| item.asset.as_str())
        .collect();
    assert!(hosts.contains(&"www.allowed.test"));
    assert!(hosts.contains(&"api.allowed.test"));
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.kind == "dns_wildcard" && item.asset == "allowed.test"));
    assert_eq!(outcome.result["sources"][0]["pages"], 2);
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.asset == "outside.test" && item.scope_status == "denied"));

    let quota = spawn_http_server(|_| HttpResponse::new(429, "quota")).await;
    let mut config = env.config.clone();
    config.certspotter_url = format!("http://127.0.0.1:{}/ct", quota.addr.port());
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "ct-quota");
    ctx.config = config;
    let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
    assert!(!outcome.errors.is_empty());
    assert_eq!(outcome.result["sources"][0]["status"], "error");
}
