mod support;

use hickory_resolver::proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};
use lastest::{
    domain::JobStatus,
    scope::Scope,
    tasks::{dnsx, TaskContext},
    worker::Worker,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant},
};
use support::{make_job, scope_rules, TestEnv};

struct Dns {
    addr: SocketAddr,
    times: Arc<Mutex<Vec<Instant>>>,
    queries: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(loss: bool) -> Dns {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let times = Arc::new(Mutex::new(Vec::new()));
    let queries = Arc::new(Mutex::new(Vec::new()));
    let (recorded, names) = (times.clone(), queries.clone());
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let mut attempts = HashMap::<(String, RecordType), usize>::new();
        let mut pending = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                packet=socket.recv_from(&mut buffer) => {
                    let (len,peer)=packet.unwrap();
                    let request=Message::from_vec(&buffer[..len]).unwrap();
                    let q=request.queries()[0].clone();
                    let name=q.name().to_utf8().trim_end_matches('.').to_string();
                    recorded.lock().unwrap().push(Instant::now());
                    names.lock().unwrap().push(name.clone());
                    let count=attempts.entry((name.clone(),q.query_type())).or_default(); *count+=1;
                    // One timed-out packet, followed by a successful retry.
                    if loss && name=="h0.allowed.test" && q.query_type()==RecordType::A && *count==1 { continue; }
                    let positive=name.split('.').next().unwrap().strip_prefix('h').is_some_and(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit())) || name.starts_with("v6.") || name.starts_with("canary.");
                    let mut reply=Message::new();
                    reply.set_id(request.id()).set_message_type(MessageType::Response)
                        .set_recursion_desired(true).set_recursion_available(true).add_query(q.clone())
                        .set_response_code(if positive {ResponseCode::NoError} else {ResponseCode::NXDomain});
                    if positive {
                        let data=match q.query_type() {
                            RecordType::A if !name.starts_with("v6.") => Some(RData::A(A(Ipv4Addr::new(203,0,113,10)))),
                            RecordType::AAAA if name.starts_with("v6.") => Some(RData::AAAA(AAAA(Ipv6Addr::new(0x2001,0xdb8,0,0,0,0,0,1)))),
                            _ => None,
                        };
                        if let Some(data)=data { reply.add_answer(Record::from_rdata(q.name().clone(),60,data)); }
                    }
                    let socket=socket.clone();
                    pending.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        socket.send_to(&reply.to_vec().unwrap(),peer).await.unwrap();
                    });
                }
                _=pending.join_next(), if !pending.is_empty() => {}
            }
        }
    });
    Dns {
        addr,
        times,
        queries,
        task,
    }
}

fn context(env: &TestEnv, dns: &Dns, key: &str) -> TaskContext {
    let mut rules = scope_rules(&[("tree", "allowed.test")]);
    rules.push(
        lastest::scope::ScopeRule::new(
            lastest::scope::RuleKind::ExactDomain,
            "blocked.allowed.test",
            true,
        )
        .unwrap(),
    );
    let mut ctx = support::task_context(env, Scope::new(rules).unwrap(), key);
    ctx.config.dnsx_path = Some(support::fake_dnsx(env.temp.path()));
    ctx.config.dns_wordlist_resolver = dns.addr.to_string();
    ctx.config.worker_lease_seconds = 3;
    ctx
}

#[tokio::test]
async fn isolated_resolver_rate_gate_preserves_v4_v6_and_negative_answers() {
    let env = TestEnv::new();
    let dns = server(false).await;
    let system = server(false).await;
    let mut ctx = context(&env, &dns, "isolated-rate");
    ctx.config.dns_server = Some(system.addr.to_string());
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":["h0","v6","missing","blocked"],"rate_limit":10}),
    );
    let outcome = dnsx::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.status, JobStatus::Succeeded, "{}", outcome.result);
    assert_eq!(
        outcome.result["found"],
        json!(["h0.allowed.test", "v6.allowed.test"])
    );
    assert_eq!(outcome.result["checked"], 3);
    assert_eq!(outcome.result["unprocessed"], 0);
    assert_eq!(outcome.result["excluded"], 1);
    assert_eq!(outcome.result["dns_errors"], 0);
    assert_eq!(outcome.result["hosts"][1]["ips"], json!(["2001:db8::1"]));
    assert!(
        system.queries.lock().unwrap().is_empty(),
        "wordlist must bypass the ordinary resolver"
    );
    assert!(!dns
        .queries
        .lock()
        .unwrap()
        .iter()
        .any(|name| name == "blocked.allowed.test"));
    let times = dns.times.lock().unwrap();
    assert!(times.len() >= 8);
    for pair in times.windows(2) {
        assert!(
            pair[1].duration_since(pair[0]) >= Duration::from_millis(90),
            "rate limit burst"
        );
    }
}

#[tokio::test]
async fn packet_loss_recovers_without_starving_the_normal_dns_client() {
    let env = TestEnv::new();
    let dns = server(true).await;
    let system = server(false).await;
    let mut ctx = context(&env, &dns, "loss");
    ctx.config.dns_server = Some(system.addr.to_string());
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":(0..12).map(|i|format!("h{i}")).collect::<Vec<_>>(),"rate_limit":50}),
    );
    let canary = async {
        let client = ctx.dns().unwrap();
        for _ in 0..10 {
            assert!(!client
                .resolve_ips("canary.allowed.test")
                .await
                .unwrap()
                .is_empty());
        }
    };
    let (outcome, canary) = tokio::join!(
        dnsx::run(&job, &ctx),
        tokio::time::timeout(Duration::from_secs(2), canary)
    );
    canary.unwrap();
    let outcome = outcome.unwrap();
    assert_eq!(outcome.status, JobStatus::Succeeded, "{}", outcome.result);
    assert_eq!(outcome.result["found"].as_array().unwrap().len(), 12);
    assert_eq!(outcome.result["unprocessed"], 0);
    assert_eq!(outcome.counters.errors, 0);
    assert!(
        dns.queries
            .lock()
            .unwrap()
            .iter()
            .filter(|name| name.as_str() == "h0.allowed.test")
            .count()
            >= 3
    );
}

#[tokio::test]
async fn system_choice_uses_the_normal_las_test_dns_override() {
    let env = TestEnv::new();
    let dedicated = server(false).await;
    let normal = server(false).await;
    let mut ctx = context(&env, &dedicated, "system-override");
    ctx.config.dns_server = Some(normal.addr.to_string());
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":["h0"],"resolver":"system"}),
    );
    let outcome = dnsx::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.status, JobStatus::Succeeded, "{}", outcome.result);
    assert_eq!(outcome.result["found"], json!(["h0.allowed.test"]));
    assert_eq!(outcome.result["resolver"], normal.addr.to_string());
    assert!(dedicated.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deadline_includes_wildcard_checks_and_returns_an_incomplete_artifact() {
    let env = TestEnv::new();
    let dns = server(false).await;
    let mut ctx = context(&env, &dns, "deadline");
    ctx.config.dns_wordlist_timeout_seconds = 1;
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":["h0","h1"],"rate_limit":1}),
    );
    let start = Instant::now();
    let outcome = dnsx::run(&job, &ctx).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(outcome.status, JobStatus::Partial);
    assert_eq!(outcome.result["stop_reason"], "timeout");
    assert_eq!(outcome.result["unprocessed"], 2);
    assert_eq!(outcome.result["complete"], false);
    let artifact: serde_json::Value =
        serde_json::from_slice(&outcome.artifacts[0].content).unwrap();
    assert_eq!(artifact["partial"], true);
}

#[tokio::test]
async fn cancellation_retains_live_checkpoints_assets_and_a_downloadable_artifact() {
    let env = TestEnv::new();
    let dns = server(false).await;
    let mut ctx = context(&env, &dns, "cancel-checkpoint");
    ctx.config.worker_lease_seconds = 60;
    let revision = env.db.current_scope(&ctx.project_id).unwrap().unwrap();
    let params = json!({"domain":"allowed.test","words":(0..100).map(|i|format!("h{i}")).collect::<Vec<_>>(),"rate_limit":20});
    let job = env
        .db
        .enqueue_job(
            &ctx.project_id,
            "dns.wordlist",
            &params,
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
        .claim_next_job("checkpoint-worker", 3)
        .unwrap()
        .unwrap();
    ctx.job_id = claim.job.id.clone();
    ctx.attempt_id = claim.attempt_id.clone();
    let worker = Worker::new(ctx.config.clone(), env.db.clone());
    let work = worker.run_claimed(
        claim.job,
        claim.attempt_id,
        Arc::new(AtomicBool::new(false)),
    );
    let cancel = async {
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let current = env.db.job_by_id(&job.id).unwrap().unwrap();
                if current.result["found"]
                    .as_array()
                    .is_some_and(|names| !names.is_empty())
                {
                    assert_eq!(current.status, JobStatus::Running);
                    assert!(!env
                        .db
                        .inventory_rows(&ctx.project_id, "")
                        .unwrap()
                        .is_empty());
                    env.db.cancel_job(&job.id, "admin").unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .unwrap();
    };
    let (result, _) = tokio::join!(work, cancel);
    result.unwrap();
    let finished = env.db.job_by_id(&job.id).unwrap().unwrap();
    assert_eq!(finished.status, JobStatus::Cancelled, "{}", finished.result);
    assert!(!finished.result["found"].as_array().unwrap().is_empty());
    assert!(finished.result["unprocessed"].as_u64().unwrap() > 0);
    let artifacts = env.db.list_artifacts(&job.id).unwrap();
    assert_eq!(artifacts.len(), 1);
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(ctx.config.evidence_dir().join(&artifacts[0].relative_path)).unwrap(),
    )
    .unwrap();
    assert_eq!(saved["found"], finished.result["found"]);
    assert_eq!(saved["stop_reason"], "cancelled");
}

#[test]
fn wordlists_wait_for_other_ready_jobs_and_are_exclusive_across_workers() {
    let env = TestEnv::new();
    let (project, revision) = env.project_with_scope(
        "wordlist-scheduling",
        scope_rules(&[("tree", "allowed.test")]),
        true,
    );
    let mut queued = Vec::new();
    for task in [
        "dns.wordlist",
        "subdomains.discover",
        "subdomains.subfinder",
        "dns.records",
        "dns.wordlist",
    ] {
        queued.push(
            env.db
                .enqueue_job(
                    &project.id,
                    task,
                    &json!({}),
                    &revision.id,
                    revision.version,
                    None,
                    "admin",
                    None,
                    None,
                )
                .unwrap(),
        );
    }
    let mut active = Vec::new();
    for i in 0..3 {
        let claim = env
            .db
            .claim_next_job(&format!("worker-{i}"), 30)
            .unwrap()
            .unwrap();
        assert_ne!(claim.job.task_type, "dns.wordlist");
        active.push(claim);
    }
    assert!(env.db.claim_next_job("worker-4", 30).unwrap().is_none());
    for claim in active {
        let outcome = lastest::db::jobs::CompleteOutcome {
            status: JobStatus::Succeeded,
            result: json!({}),
            counters: Default::default(),
            error: None,
            observations: vec![],
            findings: vec![],
            artifacts: vec![],
            candidates: vec![],
            enrichments: vec![],
            classifications: vec![],
        };
        env.db
            .complete_attempt(&claim.job.id, &claim.attempt_id, outcome)
            .unwrap();
    }
    let barrier = std::sync::Barrier::new(4);
    let claims = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|i| {
                scope.spawn({
                    let barrier = &barrier;
                    let db = env.db.clone();
                    move || {
                        barrier.wait();
                        db.claim_next_job(&format!("race-{i}"), 30).unwrap()
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].job.id, queued[0].id);
    assert_eq!(
        env.db.job_by_id(&queued[4].id).unwrap().unwrap().status,
        JobStatus::Queued
    );
}

#[tokio::test]
async fn saved_result_survives_lease_expiry_and_rejects_stale_checkpoint_writes() {
    use axum::http::{Method, StatusCode};
    use lastest::db::jobs::CompleteOutcome;
    let env = TestEnv::new();
    let (project, revision) = env.project_with_scope(
        "durable-checkpoint",
        scope_rules(&[("tree", "allowed.test")]),
        true,
    );
    let job = env
        .db
        .enqueue_job(
            &project.id,
            "dns.wordlist",
            &json!({}),
            &revision.id,
            revision.version,
            None,
            "admin",
            None,
            None,
        )
        .unwrap();
    let claim = env.db.claim_next_job("old-worker", 30).unwrap().unwrap();
    let checkpoint = || CompleteOutcome {
        status: JobStatus::Running,
        result: json!({"engine":"dnsx","checkpointed":true,"partial":true,"complete":false,"checked":1,"unprocessed":9,"found":["h0.allowed.test"],"hosts":[{"host":"h0.allowed.test","ips":["203.0.113.10"]}]}),
        counters: Default::default(),
        error: None,
        observations: vec![],
        findings: vec![],
        artifacts: vec![],
        candidates: vec![],
        enrichments: vec![],
        classifications: vec![],
    };
    assert!(env
        .db
        .checkpoint_attempt(&job.id, &claim.attempt_id, checkpoint())
        .unwrap());
    let uri = format!("/api/jobs/{}/result", job.id);
    let anonymous = support::call(&env.app, Method::GET, &uri, None, &[]).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let cookie = env.login_web().await;
    let headers = [("Host", "localhost"), ("Cookie", cookie.as_str())];
    let before = support::call(&env.app, Method::GET, &uri, None, &headers).await;
    assert_eq!(before.status, StatusCode::OK);
    assert_eq!(before.body["unprocessed"], 9);
    env.db
        .connect()
        .unwrap()
        .execute(
            "UPDATE job_attempts SET lease_until='2000-01-01T00:00:00Z' WHERE id=?1",
            [&claim.attempt_id],
        )
        .unwrap();
    assert_eq!(env.db.interrupt_expired_attempts().unwrap(), 1);
    assert!(!env
        .db
        .checkpoint_attempt(&job.id, &claim.attempt_id, checkpoint())
        .unwrap());
    assert!(!env
        .db
        .complete_attempt(&job.id, &claim.attempt_id, checkpoint())
        .unwrap());
    let after = support::call(&env.app, Method::GET, &uri, None, &headers).await;
    assert_eq!(after.body, before.body);
    assert_eq!(
        env.db.job_by_id(&job.id).unwrap().unwrap().status,
        JobStatus::Interrupted
    );
}

#[tokio::test]
async fn scope_revocation_stops_outgoing_packets_and_returns_remaining_names() {
    let env = TestEnv::new();
    let dns = server(false).await;
    let ctx = context(&env, &dns, "revoke");
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":(0..100).map(|i|format!("h{i}")).collect::<Vec<_>>(),"rate_limit":20}),
    );
    let change = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dns
                .queries
                .lock()
                .unwrap()
                .iter()
                .any(|name| name == "h0.allowed.test")
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut scope = ctx.current_scope().unwrap();
        scope.rules.push(
            lastest::scope::ScopeRule::new(
                lastest::scope::RuleKind::ExactDomain,
                "h1.allowed.test",
                true,
            )
            .unwrap(),
        );
        ctx.db
            .replace_scope(&ctx.project_id, None, &scope, "revoke", "admin", true)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let count = dns.queries.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(dns.queries.lock().unwrap().len(), count);
    };
    let (outcome, _) = tokio::join!(dnsx::run(&job, &ctx), change);
    let outcome = outcome.unwrap();
    assert_eq!(outcome.result["stop_reason"], "scope_changed");
    assert!(outcome.result["unprocessed"].as_u64().unwrap() > 0);
    assert!(!outcome
        .observations
        .iter()
        .any(|o| o.asset == "h1.allowed.test"));
}

#[tokio::test]
async fn installation_lock_prevents_a_surviving_old_process_from_sending_dns() {
    use fs2::FileExt;
    let env = TestEnv::new();
    let dns = server(false).await;
    let mut ctx = context(&env, &dns, "file-lock");
    ctx.config.dns_wordlist_timeout_seconds = 1;
    let file = std::fs::File::create(ctx.config.data_dir.join("dns-wordlist.lock")).unwrap();
    file.lock_exclusive().unwrap();
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":["h0"]}),
    );
    let outcome = dnsx::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.result["stop_reason"], "timeout");
    assert_eq!(outcome.result["unprocessed"], 1);
    assert_eq!(outcome.result["domain"], "allowed.test");
    assert_eq!(outcome.result["rate_limit"], 50);
    assert!(dns.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn entirely_excluded_wordlist_finishes_without_dns_traffic() {
    let env = TestEnv::new();
    let dns = server(false).await;
    let ctx = context(&env, &dns, "empty-scope");
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":["blocked"]}),
    );
    let outcome = dnsx::run(&job, &ctx).await.unwrap();
    assert_eq!(outcome.status, JobStatus::Succeeded);
    assert_eq!(outcome.counters.skipped, 1);
    assert_eq!(outcome.result["complete"], true);
    assert_eq!(outcome.result["unprocessed"], 0);
    assert!(dns.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn large_list_preparation_yields_to_cancellation_before_sending_any_dns() {
    use std::sync::atomic::Ordering;
    let env = TestEnv::new();
    let dns = server(false).await;
    let ctx = context(&env, &dns, "large-cancel");
    let job = make_job(
        "dns.wordlist",
        json!({"domain":"allowed.test","words":(0..50000).map(|i|format!("h{i}")).collect::<Vec<_>>()}),
    );
    let cancel = async {
        ctx.cancel.store(true, Ordering::SeqCst);
    };
    let (outcome, _) = tokio::join!(dnsx::run(&job, &ctx), cancel);
    let outcome = outcome.unwrap();
    assert_eq!(outcome.status, JobStatus::Cancelled);
    assert_eq!(outcome.result["unprocessed"], 50000);
    assert_eq!(outcome.result["domain"], "allowed.test");
    assert!(dns.queries.lock().unwrap().is_empty());
}
