mod support;

use lastest::db::Db;
use lastest::domain::JobStatus;
use lastest::worker::Worker;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use support::{scope_rules, TestEnv};
use tokio::sync::Notify;

async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not reach the expected state");
}

async fn held_http() -> (
    String,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let entered = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let release = Arc::new(Notify::new());
    let (counter, gate, notify) = (entered.clone(), released.clone(), release.clone());
    let app = axum::Router::new().fallback(axum::routing::get(move || {
        let (counter, gate, notify) = (counter.clone(), gate.clone(), notify.clone());
        async move {
            let ready = notify.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            counter.fetch_add(1, Ordering::SeqCst);
            if !gate.load(Ordering::SeqCst) {
                ready.await;
            }
            "local parallel fixture"
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, entered, released, release, server)
}

fn status(db: &Db, id: &str) -> JobStatus {
    db.job_by_id(id).unwrap().unwrap().status
}

#[tokio::test]
async fn worker_bounds_parallel_slots_refills_and_isolates_failures_and_cancellation() {
    for slots in [1, 4] {
        let env = TestEnv::new();
        let (project, revision) =
            env.project_with_scope("parallel", scope_rules(&[("ip", "127.0.0.1")]), true);
        let (base, entered, released, release, server) = held_http().await;
        let mut jobs = Vec::new();
        for i in 0..5 {
            let job = env
                .db
                .enqueue_job(
                    &project.id,
                    "http.probe",
                    &json!({"targets":[format!("{base}/{i}")],"mode":"url"}),
                    &revision.id,
                    revision.version,
                    None,
                    "admin",
                    None,
                    None,
                )
                .unwrap();
            jobs.push(job.id);
        }
        // Runtime failures must stay failed, without stopping other job slots.
        let invalid = env
            .db
            .enqueue_job(
                &project.id,
                "invalid.fixture",
                &json!({}),
                &revision.id,
                revision.version,
                None,
                "admin",
                None,
                None,
            )
            .unwrap();
        let mut config = env.config.clone();
        config.max_concurrent_jobs = slots;
        config.worker_lease_seconds = 3;
        config.http_timeout_seconds = 10;
        let worker = Worker::new(config, env.db.clone());
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        let handle = tokio::spawn(async move { worker.run_until_shutdown(flag).await });
        wait_for(|| entered.load(Ordering::SeqCst) == slots as usize).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(entered.load(Ordering::SeqCst), slots as usize);
        assert_eq!(
            jobs.iter()
                .filter(|id| status(&env.db, id) == JobStatus::Running)
                .count(),
            slots as usize
        );
        assert_eq!(
            jobs.iter()
                .filter(|id| status(&env.db, id) == JobStatus::Queued)
                .count(),
            5 - slots as usize
        );
        let cancelled = if slots == 4 {
            let id = jobs
                .iter()
                .find(|id| status(&env.db, id) == JobStatus::Running)
                .unwrap()
                .clone();
            env.db.cancel_job(&id, "admin").unwrap();
            // A heartbeat observes cancellation while the local HTTP response is held.
            tokio::time::sleep(Duration::from_millis(1200)).await;
            Some(id)
        } else {
            None
        };
        released.store(true, Ordering::SeqCst);
        release.notify_waiters();
        wait_for(|| {
            jobs.iter().all(|id| status(&env.db, id).is_terminal())
                && status(&env.db, &invalid.id).is_terminal()
        })
        .await;
        assert_eq!(entered.load(Ordering::SeqCst), 5);
        assert_eq!(status(&env.db, &invalid.id), JobStatus::Failed);
        for id in &jobs {
            assert_eq!(
                status(&env.db, id),
                if cancelled.as_ref() == Some(id) {
                    JobStatus::Cancelled
                } else {
                    JobStatus::Succeeded
                }
            );
        }
        shutdown.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.abort();
    }
}

#[tokio::test]
async fn parallel_worker_preserves_chain_order_and_published_inputs() {
    let env = TestEnv::new();
    let (project, revision) =
        env.project_with_scope("parallel-chain", scope_rules(&[("ip", "127.0.0.1")]), true);
    let (base, entered, released, release, server) = held_http().await;
    let run_id = env
        .db
        .create_chain_run(&project.id, "ordered", None, "admin")
        .unwrap();
    let mut jobs = Vec::new();
    for order in [1, 2] {
        env.db
            .add_chain_stage(&run_id, order, "http.probe", None, true)
            .unwrap();
        let job = env
            .db
            .enqueue_job(
                &project.id,
                "http.probe",
                &json!({"targets":[format!("{base}/{order}")],"mode":"url"}),
                &revision.id,
                revision.version,
                None,
                "admin",
                Some(&run_id),
                Some(order),
            )
            .unwrap();
        env.db.set_chain_stage_job(&run_id, order, &job.id).unwrap();
        jobs.push(job.id);
    }
    let mut config = env.config.clone();
    config.max_concurrent_jobs = 4;
    let worker = Worker::new(config, env.db.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let handle = tokio::spawn(async move { worker.run_until_shutdown(flag).await });
    wait_for(|| entered.load(Ordering::SeqCst) == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(status(&env.db, &jobs[0]), JobStatus::Running);
    assert_eq!(status(&env.db, &jobs[1]), JobStatus::Queued);
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "free slots cannot bypass a chain dependency"
    );
    released.store(true, Ordering::SeqCst);
    release.notify_waiters();
    wait_for(|| jobs.iter().all(|id| status(&env.db, id).is_terminal())).await;
    assert!(jobs
        .iter()
        .all(|id| status(&env.db, id) == JobStatus::Succeeded));
    let chain = env.db.chain_run_json(&run_id).unwrap().unwrap();
    assert_eq!(chain["status"], "succeeded");
    shutdown.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn worker_shutdown_cancels_active_processes_and_leaves_unclaimed_jobs_queued() {
    let env = TestEnv::new();
    let script = env.temp.path().join("subfinder");
    std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (project, revision) = env.project_with_scope(
        "parallel-stop",
        scope_rules(&[("exact", "allowed.test")]),
        true,
    );
    let mut jobs = Vec::new();
    for _ in 0..3 {
        let job = env
            .db
            .enqueue_job(
                &project.id,
                "subdomains.subfinder",
                &json!({"domains":["allowed.test"],"resolve":false}),
                &revision.id,
                revision.version,
                None,
                "admin",
                None,
                None,
            )
            .unwrap();
        jobs.push(job.id);
    }
    let mut config = env.config.clone();
    config.max_concurrent_jobs = 2;
    config.subfinder_path = Some(script);
    let worker = Worker::new(config, env.db.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let handle = tokio::spawn(async move { worker.run_until_shutdown(flag).await });
    wait_for(|| {
        jobs.iter()
            .filter(|id| status(&env.db, id) == JobStatus::Running)
            .count()
            == 2
    })
    .await;
    shutdown.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        jobs.iter()
            .filter(|id| status(&env.db, id) == JobStatus::Cancelled)
            .count(),
        2
    );
    assert_eq!(
        jobs.iter()
            .filter(|id| status(&env.db, id) == JobStatus::Queued)
            .count(),
        1
    );
    assert_eq!(env.db.worker_health(30).unwrap()["state"], "stopped");
}
