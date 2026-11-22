mod support;

use lastest::scope::Scope;
use lastest::tasks::{dns_tasks, http_tasks, network, nmap, passive, web_checks};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use support::{
    encode_dns_name, make_job, scope_rules, spawn_dns_server, spawn_http_server, task_context,
    HttpResponse, TestEnv,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fake_dnsmap(home: &std::path::Path) -> std::path::PathBuf {
    let path = home.join("dnsmap");
    std::fs::write(
        &path,
        r#"#!/bin/sh
set -eu
domain=$1
[ "$2" = '-w' ]
[ "$4" = '-d' ]
[ "$5" = '1' ]
events="$(dirname "$0")/events"
printf 'start\n' >> "$events"
expected_file="$(dirname "$0")/expected-shards"
if [ -f "$expected_file" ]; then
  read -r expected < "$expected_file"
  while :; do
    count=0
    while IFS= read -r event; do
      if [ "$event" = start ]; then count=$((count + 1)); fi
    done < "$events"
    if [ "$count" -ge "$expected" ]; then break; fi
    sleep 0.02
  done
fi
sleep 0.2
while IFS= read -r word; do
  printf '%s.%s\n' "$word" "$domain"
  printf '%s.%s\n' "$word" "$domain" >> "$(dirname "$0")/candidates"
done < "$3"
printf 'outside.test\nunlisted.allowed.test\n'
printf 'end\n' >> "$events"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

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
    config.dnsmap_path = Some(fake_dnsmap(env.temp.path()));
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
        let url = url::Url::parse(&format!("http://{host}{path}")).unwrap();
        let after = url.query_pairs().find(|(key, _)| key == "after").map(|(_, value)| value.into_owned());
        if url.path() == "/v1/issuances" {
            return match after.as_deref() {
                None => HttpResponse::new(200, r#"[{"id":"1","dns_names":["www.allowed.test","outside.test"]}]"#)
                    .header("Link", &format!("<http://{host}/issuances?after=1>; rel=\"next\"")),
                Some("1") => HttpResponse::new(200, r#"[{"id":"2","dns_names":["api.allowed.test","www.allowed.test","*.allowed.test"]}]"#),
                Some("2") => HttpResponse::new(200, "[]"),
                _ => HttpResponse::new(400, "invalid cursor"),
            };
        }
        HttpResponse::new(404, "")
    })
    .await;
    let mut config = env.config.clone();
    config.certspotter_url = format!("http://127.0.0.1:{}/v1/issuances", server.addr.port());
    let dns = spawn_dns_server(|name, kind| {
        if ["www.allowed.test", "api.allowed.test"].contains(&name) && kind == 1 {
            vec![vec![203, 0, 113, 10]]
        } else {
            vec![]
        }
    })
    .await;
    config.dns_server = Some(dns.addr.to_string());
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
    assert_eq!(outcome.result["wildcards"], json!(["allowed.test"]));
    assert!(!outcome
        .observations
        .iter()
        .any(|item| item.kind == "dns_wildcard"));
    assert_eq!(outcome.result["sources"][0]["pages"], 3);
    assert_eq!(outcome.counters.errors, 0);
    assert_eq!(outcome.result["sources"][0]["status"], "ok");
    assert!(server.requests.lock().unwrap().iter().all(|request| {
        let path = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let url = url::Url::parse(&format!("http://localhost{path}")).unwrap();
        url.path() == "/v1/issuances"
            && url
                .query_pairs()
                .any(|(key, value)| key == "domain" && value == "allowed.test")
            && url
                .query_pairs()
                .any(|(key, value)| key == "expand" && value == "dns_names")
            && url
                .query_pairs()
                .any(|(key, value)| key == "include_subdomains" && value == "true")
    }));
    assert!(outcome.result["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["host"] == "outside.test" && item["reason"] == "scope"));
    assert!(!dns
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|(host, _)| host == "outside.test" || host == "allowed.test"));

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

#[tokio::test]
async fn subfinder_adapter_bounds_output_and_resolves_only_allowed_hosts() {
    let env = TestEnv::new();
    let temp = tempfile::TempDir::new().unwrap();
    let script = temp.path().join("subfinder");
    let args_file = temp.path().join("args");
    std::fs::write(&script, format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' api.allowed.test api.allowed.test denied.allowed.test outside.test invalid/name\n",
        args_file.display()
    )).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dns = spawn_dns_server(|name, qtype| {
        if name == "api.allowed.test" && qtype == 1 {
            vec![vec![203, 0, 113, 10]]
        } else {
            vec![]
        }
    })
    .await;
    let scope = Scope::new(vec![
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::SubdomainTree,
            "allowed.test",
            false,
        )
        .unwrap(),
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "denied.allowed.test",
            true,
        )
        .unwrap(),
    ])
    .unwrap();
    let mut ctx = task_context(&env, scope, "subfinder-test");
    ctx.config.subfinder_path = Some(script.clone());
    ctx.config.dns_server = Some(dns.addr.to_string());
    let job = make_job(
        "subdomains.subfinder",
        json!({"domains":["allowed.test"],"sources":["crtsh"]}),
    );
    let outcome = lastest::tasks::subfinder::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["hosts"].as_array().unwrap().len(), 1);
    assert!(outcome
        .observations
        .iter()
        .any(|item| item.asset == "203.0.113.10"));
    assert_eq!(outcome.result["rejected"][0]["host"], "denied.allowed.test");
    assert_eq!(outcome.result["rejected"][0]["reason"], "scope");
    assert!(!outcome
        .observations
        .iter()
        .any(|item| item.asset == "denied.allowed.test"));
    assert!(!outcome
        .observations
        .iter()
        .any(|item| item.asset == "outside.test"));
    assert!(!dns
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|(name, _)| name == "denied.allowed.test"));
    let args = std::fs::read_to_string(args_file).unwrap();
    assert!(args.contains("-duc"));
    assert!(args.contains("-s\ncrtsh"));
    assert!(!args.contains("-active"));
    assert_eq!(outcome.artifacts.len(), 1);
    assert!(!ctx
        .config
        .tmp_dir()
        .join(format!("subfinder-{}", job.id))
        .exists());

    assert!(
        lastest::tasks::subfinder::validate(&json!({"sources":["-all"]}), &ctx.config).is_err()
    );
    let outside = make_job("subdomains.subfinder", json!({"domains":["outside.test"]}));
    assert!(lastest::tasks::subfinder::run(&outside, &ctx)
        .await
        .is_err());

    ctx.config.max_artifact_bytes = 8;
    let error = lastest::tasks::subfinder::run(&job, &ctx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("limit"));
    ctx.config.subfinder_path = None;
    assert!(lastest::tasks::subfinder::validate(&json!({}), &ctx.config).is_err());
}

#[tokio::test]
async fn subfinder_adapter_stops_on_timeout_and_cancellation() {
    let env = TestEnv::new();
    let temp = tempfile::TempDir::new().unwrap();
    let script = temp.path().join("subfinder");
    std::fs::write(&script, "#!/bin/sh\nexec sleep 10\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let scope = Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap();
    let mut ctx = task_context(&env, scope, "subfinder-timeout");
    ctx.config.subfinder_path = Some(script);
    ctx.config.subfinder_timeout_seconds = 1;
    let job = make_job(
        "subdomains.subfinder",
        json!({"domains":["allowed.test"],"resolve":false}),
    );
    let error = lastest::tasks::subfinder::run(&job, &ctx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timeout"));
    ctx.config.subfinder_timeout_seconds = 30;
    let cancel = ctx.cancel.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        lastest::tasks::subfinder::run(&job, &ctx),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error
        .downcast_ref::<lastest::tasks::TaskCancelled>()
        .is_some());
    cancel_task.await.unwrap();
}

#[tokio::test]
async fn subfinder_validates_exact_seed_children_and_keeps_only_resolving_assets() {
    let env = TestEnv::new();
    let temp = tempfile::TempDir::new().unwrap();
    let script = temp.path().join("subfinder");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' api.allowed.test v6.allowed.test stale.allowed.test blocked.allowed.test outside.test\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dns = spawn_dns_server(|name, qtype| match (name, qtype) {
        ("api.allowed.test", 1) => vec![vec![203, 0, 113, 10]],
        ("v6.allowed.test", 28) => vec!["2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()],
        _ => vec![],
    })
    .await;
    let scope = Scope::new(vec![
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "allowed.test",
            false,
        )
        .unwrap(),
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "blocked.allowed.test",
            true,
        )
        .unwrap(),
    ])
    .unwrap();
    let mut ctx = task_context(&env, scope, "subfinder-exact");
    ctx.config.subfinder_path = Some(script);
    ctx.config.dns_server = Some(dns.addr.to_string());
    let job = make_job(
        "subdomains.subfinder",
        json!({"domains":["allowed.test"], "resolve":true}),
    );
    let outcome = lastest::tasks::subfinder::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.status, lastest::domain::JobStatus::Succeeded);
    assert_eq!(outcome.result["hosts"].as_array().unwrap().len(), 2);
    for ip in ["203.0.113.10", "2001:db8::1"] {
        assert!(outcome
            .observations
            .iter()
            .any(|item| item.asset == ip && item.asset_kind == "ip"));
    }
    assert!(!outcome
        .observations
        .iter()
        .any(|item| item.asset == "stale.allowed.test" || item.asset == "blocked.allowed.test"));
    assert!(outcome.result["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["host"] == "stale.allowed.test" && item["reason"] == "no_addresses"));
    assert!(!ctx.allows_host_now("api.allowed.test"));
    assert!(!ctx.allows_ip_now("203.0.113.10".parse().unwrap()));
    assert!(!dns
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|(name, _)| name == "blocked.allowed.test" || name == "outside.test"));

    // Exercise publication through the worker, which creates Assets for the API.
    let revision = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    let queued = env
        .db
        .enqueue_job(
            &ctx.project_id,
            "subdomains.subfinder",
            &job.params,
            &revision.id,
            revision.version,
            None,
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env
        .db
        .claim_next_job("subfinder-test", 30)
        .unwrap()
        .unwrap();
    lastest::worker::Worker::new(ctx.config.clone(), env.db.clone())
        .run_claimed(claim.job, claim.attempt_id, ctx.cancel.clone())
        .await
        .unwrap();
    assert_eq!(
        env.db.job_by_id(&queued.id).unwrap().unwrap().status,
        lastest::domain::JobStatus::Succeeded
    );
    let assets = env.db.list_assets(&ctx.project_id, 100).unwrap();
    assert_eq!(
        assets
            .iter()
            .filter(|asset| asset["kind"] == "host")
            .count(),
        2
    );
    assert_eq!(
        assets.iter().filter(|asset| asset["kind"] == "ip").count(),
        2
    );
    assert!(!assets
        .iter()
        .any(|asset| asset["value"] == "stale.allowed.test"));

    let passive = make_job(
        "subdomains.subfinder",
        json!({"domains":["allowed.test"], "resolve":false}),
    );
    let outcome = lastest::tasks::subfinder::run(&passive, &ctx)
        .await
        .unwrap();
    assert_eq!(outcome.result["hosts"].as_array().unwrap().len(), 2);
    assert_eq!(outcome.result["resolve"], true);
    assert!(outcome
        .observations
        .iter()
        .filter(|item| item.kind == "host")
        .all(|item| item.data["dns_verified"] == true));
}

#[tokio::test]
async fn dnsmap_named_list_concurrency_scope_and_legacy_parameters() {
    use lastest::tasks::{dnsmap, validate_submission};
    let env = TestEnv::new();
    let path = fake_dnsmap(env.temp.path());
    let dns = spawn_dns_server(|name, qtype| match (name, qtype) {
        ("h0.allowed.test", 1) => vec![vec![203, 0, 113, 10]],
        ("h1.allowed.test", 28) => {
            vec![vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]]
        }
        _ => Vec::new(),
    })
    .await;
    let mut rules = scope_rules(&[("exact", "allowed.test")]);
    rules.push(
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "excluded.allowed.test",
            true,
        )
        .unwrap(),
    );
    let mut ctx = task_context(&env, Scope::new(rules).unwrap(), "dnsmap-test");
    ctx.config.dnsmap_path = Some(path);
    ctx.config.dns_server = Some(dns.addr.to_string());
    ctx.config.max_wordlist_entries = 1;
    let words: Vec<_> = (0..128)
        .map(|i| format!("h{i}"))
        .chain(["excluded".into()])
        .collect();
    for concurrency in [10, 20, 50, 100] {
        std::fs::write(env.temp.path().join("events"), "").unwrap();
        std::fs::write(env.temp.path().join("candidates"), "").unwrap();
        std::fs::write(
            env.temp.path().join("expected-shards"),
            format!("{concurrency}\n"),
        )
        .unwrap();
        let job = make_job(
            "dns.wordlist",
            json!({"domain":"allowed.test", "words":words, "concurrency":concurrency}),
        );
        validate_submission(&job.task_type, &job.params, &ctx.config, &ctx.db).unwrap();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            dns_tasks::run_wordlist(&job, &ctx),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            outcome.result["found"],
            json!(["h0.allowed.test", "h1.allowed.test"])
        );
        assert_eq!(outcome.result["concurrency"], concurrency);
        assert_eq!(outcome.result["engine"], "dnsmap");
        assert_eq!(outcome.result["searched"], 129);
        assert_eq!(outcome.artifacts.len(), 1);
        assert!(outcome
            .observations
            .iter()
            .any(|o| o.asset == "2001:db8::1"));
        let mut active = 0;
        let mut peak = 0;
        let events = std::fs::read_to_string(env.temp.path().join("events")).unwrap();
        for event in events.lines() {
            if event == "start" {
                active += 1;
                peak = peak.max(active);
            } else {
                active -= 1;
            }
        }
        assert_eq!(active, 0);
        assert_eq!(peak, concurrency);
        let candidates = std::fs::read_to_string(env.temp.path().join("candidates")).unwrap();
        assert_eq!(candidates.lines().count(), 128);
        assert!(!candidates.contains("excluded"));
        assert!(!dns
            .queries
            .lock()
            .unwrap()
            .iter()
            .any(|(name, _)| name == "excluded.allowed.test"));
    }
    std::fs::remove_file(env.temp.path().join("expected-shards")).unwrap();
    // New API submissions use the new choices; stored jobs still execute with
    // their original process count after an upgrade.
    for concurrency in [4, 8, 16] {
        let params = json!({"domain":"allowed.test","words":["h0"],"concurrency":concurrency});
        assert!(validate_submission("dns.wordlist", &params, &ctx.config, &ctx.db).is_err());
        let job = make_job("dns.wordlist", params);
        let outcome = dns_tasks::run_wordlist(&job, &ctx).await.unwrap();
        assert_eq!(outcome.result["concurrency"], concurrency);
        assert_eq!(outcome.result["found"], json!(["h0.allowed.test"]));
    }
    for params in [
        json!({"domain":"allowed.test", "concurrency":3}),
        json!({"domain":"allowed.test", "concurrency":0}),
        json!({"domain":"allowed.test", "concurrency":101}),
        json!({"domain":"allowed.test", "concurrency":"20"}),
        json!({"domain":"allowed.test", "wordlist":"../../etc/passwd"}),
        json!({"domain":"allowed.test", "words":["bad\nword"]}),
        json!({"domain":"allowed.test", "words":["-x"]}),
    ] {
        assert!(validate_submission("dns.wordlist", &params, &ctx.config, &ctx.db).is_err());
    }
    let many: Vec<_> = (0..5001).map(|i| format!("h{i}")).collect();
    validate_submission(
        "dns.wordlist",
        &json!({"domain":"allowed.test", "words":many}),
        &ctx.config,
        &ctx.db,
    )
    .unwrap();
    let params: dnsmap::WordlistParams =
        serde_json::from_value(json!({"domain":"allowed.test"})).unwrap();
    assert_eq!(dnsmap::words(&params, &ctx.db).unwrap().len(), 989);
    assert_eq!(params.concurrency, 20);
    let task = lastest::tasks::registry::task_types(&ctx.config)
        .into_iter()
        .find(|t| t.name == "dns.wordlist")
        .unwrap();
    assert!(task.available);
    assert!(task.limits.get("max_words").is_none());
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test", "wordlist":"default"}),
    );
    let outcome = dns_tasks::run_wordlist(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["searched"], 989);
    assert_eq!(outcome.result["wordlist"], "default");
}

#[tokio::test]
async fn dnsmap_large_list_preparation_yields_and_honors_cancel_and_scope_revocation() {
    use lastest::tasks::dnsmap;
    let env = TestEnv::new();
    let path = fake_dnsmap(env.temp.path());
    std::fs::write(&path, "#!/bin/sh\ntouch \"$(dirname \"$0\")/launched\"\n").unwrap();
    let words: Vec<_> = (0..50_000).map(|i| format!("h{i}")).collect();
    let params: dnsmap::WordlistParams =
        serde_json::from_value(json!({"domain":"allowed.test"})).unwrap();
    for revoke_scope in [false, true] {
        let mut ctx = task_context(
            &env,
            Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
            &format!("prep-{revoke_scope}"),
        );
        ctx.config.dnsmap_path = Some(path.clone());
        let trigger = async {
            // The single-thread runtime can run this only if preparation yields.
            if revoke_scope {
                let scope = Scope::new(scope_rules(&[("exact", "allowed.test")])).unwrap();
                ctx.db
                    .replace_scope(&ctx.project_id, None, &scope, "revoke", "admin", true)
                    .unwrap();
            } else {
                ctx.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        };
        let (result, _) = tokio::join!(dnsmap::discover(&params, &words, &ctx), trigger);
        let error = result.unwrap_err();
        if revoke_scope {
            assert!(error
                .to_string()
                .contains("scope changed during preparation"));
        } else {
            assert!(error.is::<lastest::tasks::TaskCancelled>());
        }
        assert!(!env.temp.path().join("launched").exists());
    }
}

#[tokio::test]
async fn dnsmap_stops_children_on_timeout_cancel_scope_change_and_output_overflow() {
    use lastest::tasks::dnsmap;
    let env = TestEnv::new();
    let path = fake_dnsmap(env.temp.path());
    std::fs::write(&path, "#!/bin/sh\nexec sleep 30\n").unwrap();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
        "dnsmap-cancel",
    );
    ctx.config.dnsmap_path = Some(path.clone());
    ctx.config.dnsmap_timeout_seconds = 1;
    let params: dnsmap::WordlistParams =
        serde_json::from_value(json!({"domain":"allowed.test", "words":["www"]})).unwrap();
    let words = dnsmap::words(&params, &ctx.db).unwrap();
    let error = dnsmap::discover(&params, &words, &ctx).await.unwrap_err();
    assert!(error.to_string().contains("timeout"));
    ctx.config.dnsmap_timeout_seconds = 30;
    let cancel = ctx.cancel.clone();
    let work = dnsmap::discover(&params, &words, &ctx);
    let trigger = async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    };
    let (result, _) = tokio::join!(work, trigger);
    assert!(result.unwrap_err().is::<lastest::tasks::TaskCancelled>());
    ctx.cancel
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let work = dnsmap::discover(&params, &words, &ctx);
    let trigger = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut scope = ctx.current_scope().unwrap();
        scope.rules.push(
            lastest::scope::ScopeRule::new(
                lastest::scope::RuleKind::ExactDomain,
                "www.allowed.test",
                true,
            )
            .unwrap(),
        );
        ctx.db
            .replace_scope(&ctx.project_id, None, &scope, "revoke", "admin", true)
            .unwrap();
    };
    let (result, _) = tokio::join!(work, trigger);
    assert!(result.unwrap_err().to_string().contains("scope changed"));
    std::fs::write(&path, "#!/bin/sh\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; done\n").unwrap();
    ctx.config.max_artifact_bytes = 128;
    let params: dnsmap::WordlistParams =
        serde_json::from_value(json!({"domain":"allowed.test", "words":["api"]})).unwrap();
    let error = dnsmap::discover(&params, &dnsmap::words(&params, &ctx.db).unwrap(), &ctx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("artifact limit"));
    assert_eq!(
        std::fs::read_dir(ctx.config.tmp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("dnsmap-"))
            .count(),
        0
    );
}

#[tokio::test]
async fn subdomain_tasks_accept_more_than_fifty_domains() {
    let env = TestEnv::new();
    let server = spawn_http_server(|_| HttpResponse::new(200, "[]")).await;
    let domains: Vec<_> = (0..51).map(|i| format!("d{i}.allowed.test")).collect();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
        "many-domains",
    );
    ctx.config.certspotter_url = format!("http://127.0.0.1:{}/ct", server.addr.port());
    ctx.config.subfinder_path = Some("/usr/bin/true".into());
    let job = make_job("subdomains.discover", json!({"domains":domains}));
    let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
    assert_eq!(outcome.counters.processed, 51);
    let job = make_job(
        "subdomains.subfinder",
        json!({"domains":domains,"resolve":false}),
    );
    let outcome = lastest::tasks::subfinder::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.counters.processed, 51);
    assert!(lastest::tasks::registry::task_types(&ctx.config)
        .iter()
        .all(|t| t.limits.get("max_domains").is_none()));
}

#[tokio::test]
async fn subfinder_treats_dns_absence_as_skipped_and_preserves_operational_errors() {
    let env = TestEnv::new();
    let script = env.temp.path().join("subfinder-dns");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s\\n' stale.allowed.test\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ctx = task_context(
        &env,
        Scope::new(scope_rules(&[("exact", "allowed.test")])).unwrap(),
        "dns-absence",
    );
    ctx.config.subfinder_path = Some(script);
    let job = make_job("subdomains.subfinder", json!({"domains":["allowed.test"]}));
    for code in [0, 3, 2, 5] {
        let dns = support::spawn_dns_response_server(move |_, _| (code, vec![])).await;
        ctx.config.dns_server = Some(dns.addr.to_string());
        let outcome = lastest::tasks::subfinder::run(&job, &ctx).await.unwrap();
        assert!(outcome.result["hosts"].as_array().unwrap().is_empty());
        let rejected = &outcome.result["rejected"][0];
        if code == 0 || code == 3 {
            assert_eq!(outcome.status, lastest::domain::JobStatus::Succeeded);
            assert_eq!(outcome.counters.errors, 0);
            assert_eq!(outcome.counters.skipped, 1);
            assert_eq!(rejected["reason"], "no_addresses");
            assert!(rejected.get("error").is_none());
            let error = ctx
                .dns()
                .unwrap()
                .resolve_ips("stale.allowed.test")
                .await
                .unwrap_err();
            assert!(lastest::net::dns::is_no_records(
                &error.context("address validation")
            ));
        } else {
            assert_eq!(outcome.status, lastest::domain::JobStatus::Partial);
            assert_eq!(outcome.counters.errors, 1);
            assert_eq!(rejected["reason"], "dns_error");
            assert!(outcome.errors[0].contains("DNS server returned"));
            assert!(!outcome.errors[0].contains("no record found for Query"));
            let records = make_job(
                "dns.records",
                json!({"targets":["allowed.test"],"record_types":["A"]}),
            );
            let outcome = dns_tasks::run_records(&records, &ctx).await.unwrap();
            assert_eq!(
                outcome.counters.errors, 1,
                "DNS records must retain server failures"
            );
        }
    }
    // An AAAA-only host remains valid even when A returns NODATA.
    let dns = support::spawn_dns_response_server(|_, kind| {
        (
            0,
            if kind == 28 {
                vec!["2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec()]
            } else {
                vec![]
            },
        )
    })
    .await;
    ctx.config.dns_server = Some(dns.addr.to_string());
    let outcome = lastest::tasks::subfinder::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.counters.errors, 0);
    assert_eq!(outcome.result["hosts"][0]["ips"], json!(["2001:db8::1"]));
}

#[tokio::test]
async fn certificate_transparency_keeps_partial_data_and_real_provider_errors() {
    let env = TestEnv::new();
    let dns = spawn_dns_server(|name, kind| {
        if name.ends_with(".allowed.test") && kind == 1 {
            vec![vec![203, 0, 113, 10]]
        } else {
            vec![]
        }
    })
    .await;
    let job = make_job("subdomains.discover", json!({"domains":["allowed.test"]}));
    for status in [404, 429, 500] {
        let server = spawn_http_server(move |request| {
            if request.contains("after=first") {
                HttpResponse::new(status, "provider failure")
            } else {
                HttpResponse::new(200, r#"[{"id":"first","dns_names":["api.allowed.test"]}]"#)
                    .header("Link", "<http://127.0.0.1:1/wrong-endpoint>; rel=\"next\"")
            }
        })
        .await;
        let mut ctx = task_context(
            &env,
            Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
            &format!("ct-partial-{status}"),
        );
        ctx.config.dns_server = Some(dns.addr.to_string());
        ctx.config.certspotter_url =
            format!("http://127.0.0.1:{}/v1/issuances", server.addr.port());
        let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
        assert_eq!(outcome.status, lastest::domain::JobStatus::Partial);
        assert_eq!(outcome.result["subdomains"], json!(["api.allowed.test"]));
        assert_eq!(outcome.result["sources"][0]["status"], "partial");
        assert_eq!(outcome.counters.errors, 1);
        assert!(outcome
            .observations
            .iter()
            .any(|o| o.asset == "api.allowed.test"));
        assert_eq!(server.hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        let server =
            spawn_http_server(move |_| HttpResponse::new(status, "provider failure")).await;
        ctx.config.dns_server = Some(dns.addr.to_string());
        ctx.config.certspotter_url =
            format!("http://127.0.0.1:{}/v1/issuances", server.addr.port());
        let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
        assert_eq!(outcome.result["sources"][0]["status"], "error");
        assert_eq!(
            outcome.counters.errors, 1,
            "a genuine endpoint/provider failure is not an empty result"
        );
    }
    for repeated_cursor in [true, false] {
        let server = spawn_http_server(move |request| {
            let path = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let url = url::Url::parse(&format!("http://localhost{path}")).unwrap();
            let after: u32 = url
                .query_pairs()
                .find(|(key, _)| key == "after")
                .map(|(_, value)| value.parse().unwrap())
                .unwrap_or(0);
            let id = if repeated_cursor { 1 } else { after + 1 };
            HttpResponse::new(
                200,
                json!([{"id":id.to_string(),"dns_names":[format!("h{id}.allowed.test")]}])
                    .to_string(),
            )
        })
        .await;
        let mut ctx = task_context(
            &env,
            Scope::new(scope_rules(&[("tree", "allowed.test")])).unwrap(),
            &format!("ct-cursor-{repeated_cursor}"),
        );
        ctx.config.dns_server = Some(dns.addr.to_string());
        ctx.config.certspotter_url =
            format!("http://127.0.0.1:{}/v1/issuances", server.addr.port());
        let outcome = passive::run_subdomains(&job, &ctx).await.unwrap();
        assert_eq!(outcome.status, lastest::domain::JobStatus::Partial);
        assert_eq!(outcome.result["sources"][0]["status"], "partial");
        assert_eq!(
            server.hits.load(std::sync::atomic::Ordering::SeqCst),
            if repeated_cursor { 2 } else { 10 }
        );
        assert_eq!(
            outcome.result["subdomains"].as_array().unwrap().len(),
            if repeated_cursor { 1 } else { 10 }
        );
    }
}

#[tokio::test]
async fn enumeration_modules_publish_only_address_verified_hosts_through_assets_api() {
    use axum::http::{Method, StatusCode};
    let env = TestEnv::new();
    let cookie = env.login_web().await;
    let dns = spawn_dns_server(|name, kind| match (name, kind) {
        ("v4.allowed.test", 1) => vec![vec![203, 0, 113, 10]],
        ("v6.allowed.test", 28) => vec!["2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()],
        ("txtonly.allowed.test", 16) => vec![b"\x07fixture".to_vec()],
        _ => vec![],
    })
    .await;
    let ct =
        spawn_http_server(|request| {
            if request.contains("after=first") {
                HttpResponse::new(200, "[]")
            } else {
                HttpResponse::new(200, json!([{"id":"first","dns_names":[
            "v4.allowed.test","v6.allowed.test","dead.allowed.test","txtonly.allowed.test",
            "blocked.allowed.test","outside.test","*.allowed.test","v4.allowed.test"
        ]}]).to_string())
            }
        })
        .await;
    let subfinder = env.temp.path().join("subfinder-asset-gate");
    std::fs::write(&subfinder, "#!/bin/sh\nprintf '%s\\n' v4.allowed.test v6.allowed.test dead.allowed.test txtonly.allowed.test blocked.allowed.test outside.test\n").unwrap();
    std::fs::set_permissions(&subfinder, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dnsmap = fake_dnsmap(env.temp.path());
    let mut rules = scope_rules(&[("tree", "allowed.test")]);
    rules.push(
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "blocked.allowed.test",
            true,
        )
        .unwrap(),
    );
    for (task, params) in [
        (
            "subdomains.subfinder",
            json!({"domains":["allowed.test"],"resolve":false}),
        ),
        ("subdomains.discover", json!({"domains":["allowed.test"]})),
        (
            "dns.records",
            json!({"targets":["v4.allowed.test","v6.allowed.test","dead.allowed.test","txtonly.allowed.test"],"record_types":["TXT"]}),
        ),
        (
            "dns.wordlist",
            json!({"domain":"allowed.test","words":["v4","v6","dead","txtonly","blocked"],"concurrency":10}),
        ),
    ] {
        let mut ctx = task_context(
            &env,
            Scope::new(rules.clone()).unwrap(),
            &format!("asset-gate-{task}"),
        );
        ctx.config.dns_server = Some(dns.addr.to_string());
        ctx.config.certspotter_url = format!("http://127.0.0.1:{}/v1/issuances", ct.addr.port());
        ctx.config.subfinder_path = Some(subfinder.clone());
        ctx.config.dnsmap_path = Some(dnsmap.clone());
        lastest::tasks::validate_submission(task, &params, &ctx.config, &ctx.db).unwrap();
        let revision = ctx.db.current_scope(&ctx.project_id).unwrap().unwrap();
        let queued = ctx
            .db
            .enqueue_job(
                &ctx.project_id,
                task,
                &params,
                &revision.id,
                revision.version,
                None,
                "admin",
                None,
                None,
            )
            .unwrap();
        let claim = ctx.db.claim_next_job("asset-gate", 30).unwrap().unwrap();
        lastest::worker::Worker::new(ctx.config.clone(), ctx.db.clone())
            .run_claimed(claim.job, claim.attempt_id, ctx.cancel.clone())
            .await
            .unwrap();
        let headers = [("Host", "localhost"), ("Cookie", cookie.as_str())];
        let job = support::call(
            &env.app,
            Method::GET,
            &format!("/api/jobs/{}", queued.id),
            None,
            &headers,
        )
        .await;
        assert_eq!(job.status, StatusCode::OK);
        assert_eq!(
            job.body["job"]["status"], "succeeded",
            "{task}: {}",
            job.text
        );
        assert_eq!(job.body["job"]["counters"]["errors"], 0);
        let assets = support::call(
            &env.app,
            Method::GET,
            &format!("/api/projects/{}/assets?limit=100", ctx.project_id),
            None,
            &headers,
        )
        .await;
        assert_eq!(assets.status, StatusCode::OK);
        assert_eq!(assets.body["total"], 2, "{task}: {}", assets.text);
        let rows = assets.body["items"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["host"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["v4.allowed.test", "v6.allowed.test"]
        );
        assert_eq!(rows[0]["ips"], json!(["203.0.113.10"]));
        assert_eq!(rows[1]["ips"], json!(["2001:db8::1"]));
        let artifact_href = job.body["job"]["artifacts"][0]["href"].as_str().unwrap();
        let artifact = support::call(&env.app, Method::GET, artifact_href, None, &headers).await;
        assert_eq!(artifact.status, StatusCode::OK);
        let result: serde_json::Value = serde_json::from_str(&artifact.text).unwrap();
        assert!(result["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |host| host["dns_verified"] == true && !host["ips"].as_array().unwrap().is_empty()
            ));
        let rejected = result["rejected"].as_array().unwrap();
        for host in ["dead.allowed.test", "txtonly.allowed.test"] {
            assert!(
                rejected
                    .iter()
                    .any(|item| item["host"] == host && item["reason"] == "no_addresses"),
                "{task}: {result}"
            );
        }
        if task == "subdomains.discover" {
            assert_eq!(result["wildcards"], json!(["allowed.test"]));
        }
        if task == "subdomains.subfinder" {
            assert_eq!(result["resolve"], true);
        }
        if task == "dns.records" {
            assert_eq!(result["record_types"], json!(["TXT"]));
            assert!(result["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["target"] == "txtonly.allowed.test"
                    && record["type"] == "TXT"
                    && record["value"] == "fixture"));
        }
    }
    assert!(!dns.queries.lock().unwrap().iter().any(|(name, _)| [
        "blocked.allowed.test",
        "outside.test",
        "allowed.test"
    ]
    .contains(&name.as_str())));
}
