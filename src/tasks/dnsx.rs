//! A single dnsx process, an isolated rate-limited DNS transport, and durable
//! verified checkpoints. The deadline covers preparation, probes and collection.
use super::{
    discovery, wordlist,
    wordlist_dns::{Answer, Relay},
    TaskContext, TaskOutcome,
};
use crate::{
    db::jobs::CompleteOutcome,
    domain::{Job, JobStatus},
    net::DnsClient,
    scope::normalize_domain,
};
use anyhow::{Context, Result};
use fs2::FileExt;
use rand::Rng;
use serde_json::json;
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    process::Stdio,
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::Instant,
};

#[derive(Default)]
struct Host {
    done: [bool; 2],
    ips: HashSet<IpAddr>,
    errors: [Option<String>; 2],
    published: HashSet<IpAddr>,
}

impl Host {
    fn answer(&mut self, answer: Answer) {
        if let Some(error) = answer.error {
            if !self.done[answer.family] {
                self.errors[answer.family] = Some(error);
            }
        } else {
            self.done[answer.family] = true;
            self.errors[answer.family] = None;
            self.ips.extend(answer.ips);
        }
    }
}

struct Collection {
    hosts: BTreeMap<String, Host>,
    wildcard: HashSet<IpAddr>,
    outcome: TaskOutcome,
    probes: BTreeMap<String, Host>,
    total: usize,
    excluded: usize,
    domain: String,
    concurrency: usize,
    rate: u32,
    resolver: String,
    wordlist: String,
}

impl Collection {
    fn answer(&mut self, answer: Answer) {
        if let Some(probe) = self.probes.get_mut(&answer.host) {
            self.wildcard.extend(answer.ips.iter().copied());
            probe.answer(answer);
        } else if let Some(host) = self.hosts.get_mut(&answer.host) {
            host.answer(answer);
        }
    }

    fn snapshot(&mut self, ctx: &TaskContext, stop: Option<&str>, requests: u64) -> Result<()> {
        let mut hosts = Vec::new();
        let mut found = Vec::new();
        let mut rejected = Vec::new();
        let mut checked = 0;
        let mut negative = 0;
        let mut errors = 0;
        let mut wildcard_count = 0;
        for (name, host) in &mut self.hosts {
            if host.done.iter().all(|done| *done) {
                checked += 1;
            }
            if host.done.iter().all(|done| *done) && host.ips.is_empty() {
                negative += 1;
                if rejected.len() < 100 {
                    rejected.push(json!({"host":name,"reason":"no_addresses"}));
                }
            }
            if host.errors.iter().any(Option::is_some) {
                errors += 1;
                if rejected.len() < 100 {
                    rejected.push(json!({"host":name,"reason":"dns_error","error":host.errors}));
                }
            }
            if host.ips.is_empty() {
                continue;
            }
            let mut ips: Vec<_> = host.ips.iter().copied().collect();
            ips.sort();
            if !self.wildcard.is_empty() && ips.iter().all(|ip| self.wildcard.contains(ip)) {
                wildcard_count += 1;
                if rejected.len() < 100 {
                    rejected.push(json!({"host":name,"reason":"wildcard","addresses":ips}));
                }
                continue;
            }
            // Scope may have narrowed since a previously verified checkpoint.
            // Never publish a new observation after the permission was revoked.
            if host.published != host.ips && discovery::allows_dns(ctx, &self.domain, name)? {
                let mut active = ctx.clone();
                // Cancellation stops traffic; already received DNS evidence is
                // still valid and can be saved while the worker shuts down.
                active.cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                discovery::observe_host(
                    &mut self.outcome,
                    &active,
                    "dns.wordlist",
                    &self.domain,
                    name,
                    &ips,
                )?;
                host.published.clone_from(&host.ips);
            }
            if !host.published.is_empty() {
                found.push(name.clone());
                hosts.push(json!({"host":name,"ips":ips,"dns_verified":true}));
            }
        }
        self.outcome.counters.targets = self.total as u64;
        self.outcome.counters.processed = checked;
        self.outcome.counters.skipped = self.excluded as u64;
        self.outcome.counters.errors = errors;
        let unprocessed = self.hosts.len().saturating_sub(checked as usize);
        self.outcome.result = json!({
            "format_version":"1", "engine":"dnsx", "domain":self.domain,
            "wordlist":self.wordlist,"concurrency":self.concurrency,"rate_limit":self.rate,"resolver":self.resolver,
            "found":found,"hosts":hosts,"rejected":rejected,"dns_verified":true,
            "wildcard_addresses":self.wildcard,"searched":self.total,"checked":checked,
            "negative":negative,"wildcard_filtered":wildcard_count,"unprocessed":unprocessed,
            "excluded":self.excluded,"dns_errors":errors,"dns_requests":requests,
            "complete":stop.is_none() && unprocessed == 0,"partial":stop.is_some() || unprocessed > 0,
            "stop_reason":stop,"checkpointed":true,
            "errors":if errors > 0 { vec![format!("{errors} names have unresolved DNS failures; see rejected details")] } else { Vec::new() }
        });
        anyhow::ensure!(
            serde_json::to_vec(&self.outcome.result)?.len()
                < ctx.config.max_artifact_bytes as usize,
            "wordlist result exceeds the artifact limit"
        );
        Ok(())
    }

    fn checkpoint(&mut self, ctx: &TaskContext, requests: u64) -> Result<()> {
        self.snapshot(ctx, None, requests)?;
        self.persist(ctx)
    }

    fn persist(&mut self, ctx: &TaskContext) -> Result<()> {
        let outcome = CompleteOutcome {
            status: JobStatus::Running,
            result: self.outcome.result.clone(),
            counters: self.outcome.counters.clone(),
            error: None,
            observations: self.outcome.observations.clone(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            candidates: Vec::new(),
            enrichments: Vec::new(),
            classifications: Vec::new(),
        };
        if ctx
            .db
            .checkpoint_attempt(&ctx.job_id, &ctx.attempt_id, outcome)?
        {
            self.outcome.observations.clear();
        } else if ctx.db.job_by_id(&ctx.job_id)?.is_some() {
            return Err(super::TaskCancelled.into());
        }
        Ok(())
    }
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let deadline = Instant::now() + Duration::from_secs(ctx.config.dns_wordlist_timeout_seconds);
    let (params, words) = wordlist::prepare(&job.params, &ctx.config, &ctx.db)?;
    let domain = normalize_domain(&params.domain)?;
    if ctx.ensure_active().is_err() || Instant::now() >= deadline {
        return empty_result(
            job,
            words.len(),
            if ctx.ensure_active().is_err() {
                "cancelled"
            } else {
                "timeout"
            },
            &params,
        );
    }
    ctx.authorize_host(&domain)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(ctx.config.data_dir.join("dns-wordlist.lock"))?;
    // The DB serializes claims across workers. The OS lock also protects against
    // a paused old worker surviving an expired lease; its transport must stop
    // before another process can send a wordlist query.
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if ctx.ensure_active().is_err() || Instant::now() >= deadline {
            return empty_result(
                job,
                words.len(),
                if ctx.ensure_active().is_err() {
                    "cancelled"
                } else {
                    "timeout"
                },
                &params,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let current = ctx.current_scope()?;
    let mut hosts = BTreeMap::new();
    let mut ordered_hosts = Vec::new();
    for (i, word) in words.iter().enumerate() {
        if i % 256 == 0 {
            if ctx.ensure_active().is_err() || Instant::now() >= deadline {
                return empty_result(
                    job,
                    words.len(),
                    if ctx.ensure_active().is_err() {
                        "cancelled"
                    } else {
                        "timeout"
                    },
                    &params,
                );
            }
            tokio::task::yield_now().await;
        }
        let host = wordlist::candidate(word, &domain)?;
        if discovery::allows_dns_in(&ctx.scope.snapshot, &current, &domain, &host) {
            ordered_hosts.push(host.clone());
            hosts.insert(host, Host::default());
        }
    }
    anyhow::ensure!(
        ctx.current_scope()?.rules == current.rules,
        "wordlist scope changed during preparation"
    );
    if hosts.is_empty() {
        return empty_result(job, words.len(), "no_eligible_names", &params);
    }
    let probes: BTreeMap<_, _> = (0..2)
        .map(|_| {
            let label: String = (0..16)
                .map(|_| char::from_digit(rand::rng().random_range(0..36), 36).unwrap())
                .collect();
            (format!("{label}.{domain}"), Host::default())
        })
        .collect();
    let allowed: HashSet<_> = hosts
        .keys()
        .cloned()
        .chain(probes.keys().cloned())
        .collect();
    let mut transport_ctx = ctx.clone();
    transport_ctx.config.dns_wordlist_rate = params.rate_limit;
    if params.resolver == "system" {
        transport_ctx.config.dns_wordlist_resolver = if let Some(server) = &ctx.config.dns_server {
            server.clone()
        } else {
            let (system, _) = hickory_resolver::system_conf::read_system_conf()?;
            system
                .name_servers()
                .first()
                .context("system DNS has no nameserver")?
                .socket_addr
                .to_string()
        };
    }
    let mut relay = Relay::start(&transport_ctx, &domain, allowed, deadline).await?;
    let concurrency = if wordlist::CONCURRENCY_OPTIONS.contains(&params.concurrency) {
        params.concurrency
    } else {
        wordlist::DEFAULT_CONCURRENCY
    };
    let mut collection = Collection {
        excluded: words.len() - hosts.len(),
        total: words.len(),
        hosts,
        probes,
        wildcard: HashSet::new(),
        outcome: TaskOutcome::new(),
        domain,
        concurrency,
        rate: params.rate_limit,
        resolver: transport_ctx.config.dns_wordlist_resolver.clone(),
        wordlist: if params.words.is_empty() {
            params.wordlist
        } else {
            "custom".into()
        },
    };
    let metrics = relay.metrics.clone();
    let requests = || metrics.requests.load(Ordering::Relaxed);
    collection.checkpoint(ctx, requests())?;
    let directory = tempfile::Builder::new()
        .prefix("dnsx-")
        .tempdir_in(ctx.config.tmp_dir())?;
    let home = directory.path();
    let work = async {
        let mut probe_config = ctx.config.clone();
        probe_config.dns_server = Some(relay.address.to_string());
        probe_config.http_timeout_seconds = 5;
        let dns = DnsClient::new(&probe_config)?;
        for probe in collection.probes.keys().cloned().collect::<Vec<_>>() {
            ctx.ensure_active()?;
            match tokio::time::timeout_at(deadline, dns.resolve_ips(&probe)).await {
                Err(_) => return Ok(Some("timeout".into())),
                Ok(Ok(ips)) => {
                    collection.wildcard.extend(ips);
                    collection.probes.get_mut(&probe).unwrap().done = [true, true];
                }
                Ok(Err(error)) if crate::net::dns::is_no_records(&error) => {
                    // The resolver may answer the second family from its own
                    // cache, without sending another packet through the relay.
                    collection.probes.get_mut(&probe).unwrap().done = [true, true];
                }
                Ok(Err(_)) => return Ok(Some("wildcard_verification_failed".into())),
            }
        }
        while let Ok(answer) = relay.answers.try_recv() {
            collection.answer(answer);
        }
        if collection
            .probes
            .values()
            .any(|probe| !probe.done.iter().all(|done| *done))
        {
            return Ok(Some("wildcard_verification_failed".into()));
        }
        let path = home.join("hosts.txt");
        tokio::fs::write(&path, ordered_hosts.join("\n") + "\n").await?;
        let mut child = tokio::process::Command::new(
            ctx.config.dnsx_path.as_ref().context("missing dnsx path")?,
        )
        .args([
            "-l",
            path.to_str().context("invalid wordlist path")?,
            "-a",
            "-aaaa",
            "-r",
            &relay.address.to_string(),
            "-t",
            &concurrency.to_string(),
            "-rl",
            &params.rate_limit.to_string(),
            "-retry",
            "2",
            "-timeout",
            "5s",
            "-j",
            "-omit-raw",
            "-silent",
            "-nc",
            "-duc",
            "-auth=false",
        ])
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start dnsx")?;
        let stdout = child.stdout.take().context("missing dnsx stdout")?;
        let stderr = child.stderr.take().context("missing dnsx stderr")?;
        let mut output = tokio::task::JoinSet::new();
        let diagnostics = std::sync::Arc::new(tokio::sync::Mutex::new(String::new()));
        output.spawn(drain(stdout, 64 * 1024 * 1024, None));
        output.spawn(drain(stderr, 64 * 1024, Some(diagnostics.clone())));
        let mut checkpoint = tokio::time::interval(Duration::from_secs(1));
        let stop = loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break Some("timeout".to_string()),
                answer = relay.answers.recv() => { if let Some(answer)=answer { collection.answer(answer); } },
                result = output.join_next(), if !output.is_empty() => {
                    result.context("missing dnsx output reader")???;
                },
                status = child.wait() => {
                    let status = status?;
                    break if status.success() { None } else { Some(format!("dnsx exited with {status}: {}", diagnostics.lock().await.trim())) };
                },
                _ = checkpoint.tick() => {
                    if ctx.ensure_active().is_err() { break Some("cancelled".into()); }
                    if ctx.current_scope()?.rules != current.rules { break Some("scope_changed".into()); }
                    if relay.metrics.overloaded.load(Ordering::Relaxed) { break Some("resolver_unavailable".into()); }
                    collection.checkpoint(ctx, requests())?;
                }
            }
        };
        let _ = child.kill().await;
        let _ = child.wait().await;
        output.shutdown().await;
        Ok::<_, anyhow::Error>(stop)
    };
    let result = tokio::time::timeout_at(deadline, async {
        tokio::pin!(work);
        let mut control = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                result = &mut work => break result,
                _ = control.tick() => {
                    let cancelled = ctx.db.attempt_control(&ctx.job_id,&ctx.attempt_id)?
                        .is_some_and(|state| !state.active || state.cancel_requested);
                    if cancelled || ctx.ensure_active().is_err() { break Ok(Some("cancelled".into())); }
                    if ctx.current_scope()?.rules != current.rules { break Ok(Some("scope_changed".into())); }
                }
            }
        }
    }).await;
    relay.stop().await;
    let mut stop = match result {
        Err(_) => Some("timeout".into()),
        Ok(Err(error)) if error.is::<super::TaskCancelled>() => Some("cancelled".into()),
        Ok(Err(error)) => Some(format!("engine_error: {error:#}")),
        Ok(Ok(stop)) => stop,
    };
    if ctx.ensure_active().is_err() {
        stop = Some("cancelled".into());
    }
    while let Ok(answer) = relay.answers.try_recv() {
        collection.answer(answer);
    }
    collection.snapshot(ctx, stop.as_deref(), requests())?;
    collection.outcome.result["dns_transport_failures"] =
        json!(metrics.failures.load(Ordering::Relaxed));
    collection.outcome.result["dns_cache_hits"] = json!(metrics.cache_hits.load(Ordering::Relaxed));
    collection.persist(ctx)?;
    if stop.is_some()
        || collection.outcome.result["unprocessed"]
            .as_u64()
            .unwrap_or(0)
            > 0
        || collection.outcome.counters.errors > 0
    {
        collection.outcome.status = if stop.as_deref() == Some("cancelled") {
            JobStatus::Cancelled
        } else {
            JobStatus::Partial
        };
        collection.outcome.error = Some(
            stop.clone()
                .unwrap_or_else(|| "DNS responses were incomplete".into()),
        );
    }
    collection.outcome.add_artifact(
        "dns_wordlist",
        &format!("{}-dns-wordlist.json", job.id),
        &collection.outcome.result.clone(),
    )?;
    directory.close()?;
    drop(relay);
    drop(lock);
    Ok(collection.outcome)
}

async fn drain(
    mut reader: impl AsyncRead + Unpin,
    limit: u64,
    diagnostics: Option<std::sync::Arc<tokio::sync::Mutex<String>>>,
) -> Result<()> {
    let mut count = 0u64;
    let mut buffer = [0; 8192];
    loop {
        let len = reader.read(&mut buffer).await?;
        if len == 0 {
            return Ok(());
        }
        if let Some(diagnostics) = &diagnostics {
            let mut text = diagnostics.lock().await;
            if text.len() < 8192 {
                let remaining = 8192 - text.len();
                text.push_str(&String::from_utf8_lossy(&buffer[..len.min(remaining)]));
            }
        }
        count += len as u64;
        anyhow::ensure!(count <= limit, "dnsx output exceeded its limit");
    }
}

fn empty_result(
    job: &Job,
    total: usize,
    reason: &str,
    params: &wordlist::WordlistParams,
) -> Result<TaskOutcome> {
    let mut outcome = TaskOutcome::new();
    let incomplete = reason != "no_eligible_names";
    outcome.status = if !incomplete {
        JobStatus::Succeeded
    } else if reason == "cancelled" {
        JobStatus::Cancelled
    } else {
        JobStatus::Partial
    };
    outcome.target(total);
    outcome.error = incomplete.then(|| reason.into());
    outcome.counters.skipped = if incomplete { 0 } else { total as u64 };
    outcome.result = json!({"format_version":"1","engine":"dnsx","checkpointed":true,"partial":incomplete,"complete":!incomplete,
        "domain":normalize_domain(&params.domain)?,"wordlist":if params.words.is_empty() {params.wordlist.as_str()} else {"custom"},
        "concurrency":if wordlist::CONCURRENCY_OPTIONS.contains(&params.concurrency) {params.concurrency} else {wordlist::DEFAULT_CONCURRENCY},
        "rate_limit":params.rate_limit,"resolver":null,"resolver_mode":params.resolver,"dns_requests":0,"dns_errors":0,
        "dns_verified":true,"rejected":[],"wildcard_addresses":[],"negative":0,"excluded":if incomplete {0} else {total},
        "stop_reason":if incomplete {Some(reason)} else {None},"found":[],"hosts":[],"checked":0,"unprocessed":if incomplete {total} else {0},"searched":total,"errors":[]});
    outcome.add_artifact(
        "dns_wordlist",
        &format!("{}-dns-wordlist.json", job.id),
        &outcome.result.clone(),
    )?;
    Ok(outcome)
}
