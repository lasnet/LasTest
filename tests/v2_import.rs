mod v2_support;

use lastest::config::Config;
use lastest::domain::ScopeStatus;
use lastest::import::{run_import, ImportOptions};
use rusqlite::params;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;
use v2_support::TestEnv;

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("v2")
        .join("legacy")
        .join("projects")
}

fn legacy_db(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE users (
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, last_login_at TEXT
         );
         CREATE TABLE jobs (
            id TEXT PRIMARY KEY, project_name TEXT NOT NULL, task_type TEXT NOT NULL,
            status TEXT NOT NULL, params_json TEXT NOT NULL, result_json TEXT,
            log_path TEXT NOT NULL, error TEXT, created_at TEXT NOT NULL,
            started_at TEXT, finished_at TEXT
         );
         CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            actor_username TEXT, actor_role TEXT, action TEXT NOT NULL,
            resource_type TEXT NOT NULL, resource_id TEXT, status TEXT NOT NULL,
            ip_address TEXT, user_agent TEXT, details_json TEXT NOT NULL
         );",
    )
    .unwrap();
    for (id, status, created, error) in [
        (
            "old-succeeded",
            "succeeded",
            "2024-01-05T00:00:00Z",
            None::<String>,
        ),
        ("old-queued", "queued", "2024-01-06T00:00:00Z", None),
        ("old-running", "running", "2024-01-07T00:00:00Z", None),
    ] {
        conn.execute(
            "INSERT INTO jobs(id, project_name, task_type, status, params_json, result_json,
                              log_path, error, created_at, started_at, finished_at)
             VALUES (?1, 'example.com', 'subfinder', ?2, '{}', '{\"found\":1}', '/tmp/abs.log', ?3, ?4, NULL, NULL)",
            params![id, status, error, created],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO users(username, password_hash, role, is_active, created_at, updated_at)
         VALUES ('legacy-viewer', 'pbkdf2_sha256$legacy$hash', 'viewer', 0, '2024-01-01', '2024-01-01')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO audit_events(created_at, actor_username, actor_role, action, resource_type,
                                 resource_id, status, details_json)
         VALUES ('2024-01-05T00:00:00Z', 'legacy-admin', 'admin', 'job.submit',
                 'job', 'old-succeeded', 'ok', '{\"task\":\"subfinder\"}')",
        [],
    )
    .unwrap();
}

fn dry_config(temp: &TempDir) -> Config {
    Config {
        data_dir: temp.path().to_path_buf(),
        internal_ranges: vec!["127.0.0.0/8".to_string()],
        ..Config::default()
    }
}

fn options(database: Option<std::path::PathBuf>, apply: bool) -> ImportOptions {
    ImportOptions {
        projects_dir: fixture(),
        database,
        logs_root: None,
        apply,
        mappings: HashMap::new(),
        import_users: true,
        actor: "test-import".to_string(),
    }
}

#[tokio::test]
async fn dry_run_does_not_create_target_data_and_reports_conflicts() {
    let temp = TempDir::new().unwrap();
    let config = dry_config(&temp);
    let db_path = config.database_path();
    let legacy = temp.path().join("legacy.sqlite");
    legacy_db(&legacy);
    let report = run_import(&config, &options(Some(legacy), false))
        .await
        .unwrap();
    assert_eq!(report.mode, "dry-run");
    assert!(
        !db_path.exists(),
        "dry run must not create the new database"
    );
    assert!(!config.evidence_dir().exists());
    assert_eq!(report.projects.len(), 2);
    let example = report
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert!(example.planned.subdomains >= 2);
    assert!(example.planned.findings >= 2);
    let broken = report
        .projects
        .iter()
        .find(|item| item.source_name == "broken")
        .unwrap();
    assert!(broken
        .warnings
        .iter()
        .any(|warning| warning.contains("invalid JSON")));
}

#[tokio::test]
async fn apply_matches_dry_run_and_is_idempotent() {
    let env = TestEnv::new();
    let legacy = env.temp.path().join("legacy.sqlite");
    legacy_db(&legacy);
    let dry = run_import(&env.config, &options(Some(legacy.clone()), false))
        .await
        .unwrap();
    let applied = run_import(&env.config, &options(Some(legacy.clone()), true))
        .await
        .unwrap();
    assert_eq!(applied.mode, "apply");
    assert_eq!(dry.totals.subdomains, applied.totals.subdomains);
    assert_eq!(dry.totals.dns_records, applied.totals.dns_records);
    assert_eq!(dry.totals.http_hosts, applied.totals.http_hosts);
    assert_eq!(dry.totals.urls, applied.totals.urls);
    assert_eq!(dry.totals.ports, applied.totals.ports);
    assert_eq!(dry.totals.findings, applied.totals.findings);
    assert_eq!(dry.totals.jobs, applied.totals.jobs);
    assert_eq!(dry.totals.artifacts, applied.totals.artifacts);
    assert_eq!(dry.totals.audit, applied.totals.audit);

    let project = env.db.project_by_name("example.com").unwrap().unwrap();
    let scope = env.db.current_scope(&project.id).unwrap().unwrap();
    assert_eq!(scope.status, ScopeStatus::PendingReview);
    assert!(!scope.scope.rules.is_empty());
    assert!(scope.scope.rules.iter().all(|rule| !rule.verified));
    assert!(scope.scope.rules.iter().any(|rule| rule.exclusion));
    assert!(scope.scope.allows_host("www.example.com"));
    assert!(!scope.scope.allows_host("admin.example.com"));

    let subdomains = env
        .db
        .recent_observations(&project.id, Some("host"), 100)
        .unwrap();
    assert!(subdomains.len() >= 2);
    let findings = env.db.all_findings(&project.id).unwrap();
    assert_eq!(findings.len(), 2);
    let jobs = env.db.list_jobs(Some(&project.id), None, 100, 0).unwrap().0;
    assert!(jobs.iter().all(|job| job.archived));
    let archived_queued = jobs
        .iter()
        .find(|job| job.idempotency_key.as_deref() == Some("legacy:old-queued"))
        .unwrap();
    assert_eq!(
        archived_queued.status,
        lastest::domain::JobStatus::Cancelled
    );
    assert!(archived_queued
        .error
        .as_deref()
        .unwrap()
        .contains("never executed"));

    let viewer = env.db.user_by_username("legacy-viewer").unwrap().unwrap();
    assert!(!viewer.is_active);
    let (hash, must_change) = env.db.password_hash(&viewer.id).unwrap().unwrap();
    assert!(must_change);
    assert!(!hash.contains("legacy$hash"));

    let artifacts = env.db.list_artifacts(&jobs[0].id).unwrap_or_default();
    let _ = artifacts;
    let evidence = env.config.evidence_dir().join("imports").join(&project.id);
    assert!(evidence.exists());
    let mut copied_config = None;
    for entry in walk(&evidence) {
        if entry.ends_with("config.yaml") {
            copied_config = Some(entry);
        }
    }
    let copied = copied_config.expect("legacy config must be preserved");
    let content = std::fs::read_to_string(copied).unwrap();
    assert!(content.contains("Synthetic LasTest 1.x project"));

    let before_observations = env.db.all_observations(&project.id, 100_000).unwrap().len();
    let before_jobs = env.db.list_jobs(Some(&project.id), None, 100, 0).unwrap().1;
    let second = run_import(&env.config, &options(Some(legacy), true))
        .await
        .unwrap();
    let second_project = second
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert_eq!(second_project.status, "resumed", "{:#?}", second);
    assert_eq!(
        env.db.all_observations(&project.id, 100_000).unwrap().len(),
        before_observations
    );
    assert_eq!(
        env.db.list_jobs(Some(&project.id), None, 100, 0).unwrap().1,
        before_jobs
    );
}

fn walk(path: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[tokio::test]
async fn name_conflict_requires_explicit_mapping() {
    let env = TestEnv::new();
    env.db
        .create_project("example.com", "", "pre-existing", None, None, "admin")
        .unwrap();
    let legacy = env.temp.path().join("legacy.sqlite");
    legacy_db(&legacy);
    let report = run_import(&env.config, &options(Some(legacy.clone()), true))
        .await
        .unwrap();
    let example = report
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert_eq!(example.status, "conflict", "{:#?}", report);
    assert!(!example.conflicts.is_empty());
    let existing = env.db.project_by_name("example.com").unwrap().unwrap();
    assert_eq!(
        env.db
            .recent_observations(&existing.id, None, 10)
            .unwrap()
            .len(),
        0
    );

    let mut mapped = options(Some(legacy), true);
    mapped
        .mappings
        .insert("example.com".to_string(), "renamed".to_string());
    let report = run_import(&env.config, &mapped).await.unwrap();
    let example = report
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert_eq!(example.status, "new");
    let renamed = env.db.project_by_name("renamed").unwrap().unwrap();
    assert!(!env
        .db
        .recent_observations(&renamed.id, None, 100)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn external_symlink_is_not_imported() {
    let source_temp = TempDir::new().unwrap();
    let project_dir = source_temp.path().join("example.com");
    std::fs::create_dir_all(project_dir.join("recon/subdomains")).unwrap();
    std::fs::write(
        project_dir.join("config.yaml"),
        "project:\n  name: example.com\nscope:\n  domains: [example.com]\n  ips: []\n  exclusions: []\n",
    )
    .unwrap();
    let outside = source_temp.path().join("outside.json");
    std::fs::write(&outside, "{\"all\":[\"secret.example.com\"]}").unwrap();
    std::os::unix::fs::symlink(
        &outside,
        project_dir.join("recon/subdomains/subdomains.json"),
    )
    .unwrap();
    let env = TestEnv::new();
    let mut opts = options(None, true);
    opts.projects_dir = source_temp.path().to_path_buf();
    let report = run_import(&env.config, &opts).await.unwrap();
    let example = report
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert!(example
        .warnings
        .iter()
        .any(|warning| warning.contains("symlink") || warning.contains("regular file")));
    let project = env.db.project_by_name("example.com").unwrap().unwrap();
    let observations = env
        .db
        .recent_observations(&project.id, Some("host"), 10)
        .unwrap();
    assert!(!observations
        .iter()
        .any(|item| item.asset == "secret.example.com"));
}

#[tokio::test]
async fn sqlite_backup_can_be_opened_and_restored_into_a_new_volume() {
    let env = TestEnv::new();
    let project = env
        .db
        .create_project("backup", "", "", None, None, "admin")
        .unwrap();
    let backup_dir = TempDir::new().unwrap();
    let backup_path = backup_dir.path().join("lastest.sqlite");
    env.db.backup_to(&backup_path).unwrap();
    let restored = lastest::db::Db::new(&backup_path).unwrap();
    assert_eq!(
        restored.schema_version().unwrap(),
        lastest::db::SCHEMA_VERSION
    );
    assert!(restored.project_by_id(&project.id).unwrap().is_some());
    let value: Value = serde_json::json!({"restored": true});
    assert_eq!(value["restored"], true);
}

#[tokio::test]
async fn logs_are_imported_only_from_explicit_root_and_symlinks_are_skipped() {
    let env = TestEnv::new();
    let legacy = env.temp.path().join("legacy.sqlite");
    legacy_db(&legacy);
    let logs_root = env.temp.path().join("logs");
    std::fs::create_dir_all(logs_root.join("jobs")).unwrap();
    std::fs::write(
        logs_root.join("jobs/old-succeeded.log"),
        "legacy log line\n",
    )
    .unwrap();
    let outside = env.temp.path().join("outside.log");
    std::fs::write(&outside, "secret\n").unwrap();
    std::os::unix::fs::symlink(&outside, logs_root.join("jobs/old-running.log")).unwrap();
    let mut opts = options(Some(legacy), true);
    opts.logs_root = Some(logs_root);
    let report = run_import(&env.config, &opts).await.unwrap();
    let example = report
        .projects
        .iter()
        .find(|item| item.source_name == "example.com")
        .unwrap();
    assert_eq!(example.planned.logs, 1);
    assert_eq!(example.imported.as_ref().unwrap().logs, 1);
    let project = env.db.project_by_name("example.com").unwrap().unwrap();
    let conn = env.db.connect().unwrap();
    let logs: Vec<String> = conn
        .prepare(
            "SELECT relative_path FROM artifacts WHERE project_id = ?1 AND kind = 'legacy_log'",
        )
        .unwrap()
        .query_map([&project.id], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(logs.len(), 1);
    let content = std::fs::read_to_string(env.config.evidence_dir().join(&logs[0])).unwrap();
    assert_eq!(content, "legacy log line\n");
    assert!(!logs[0].contains("outside"));
}

#[test]
fn newer_schema_is_rejected_before_startup() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("lastest.sqlite");
    let db = lastest::db::Db::new(&path).unwrap();
    drop(db);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (999, '2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    drop(conn);
    let error = lastest::db::Db::new(&path).unwrap_err();
    assert!(error.to_string().contains("newer than this binary"));
}
