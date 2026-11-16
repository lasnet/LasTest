mod support;

use serde_json::Value;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use support::{spawn_http_server, HttpResponse};
use tempfile::TempDir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_lastest")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn cli(data_dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> CliOutput {
    let mut command = Command::new(binary());
    command.arg("--data-dir").arg(data_dir).args(args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn cli_json(data_dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> Value {
    let output = cli(data_dir, args, stdin);
    assert_eq!(
        output.status, 0,
        "CLI failed: args={args:?} stderr={} stdout={}",
        output.stderr, output.stdout
    );
    serde_json::from_str(&output.stdout)
        .unwrap_or_else(|err| panic!("CLI did not return JSON: {err}: {}", output.stdout))
}

fn start_process(data_dir: &std::path::Path, bind: &str, mode: &str) -> ChildGuard {
    let mut command = Command::new(binary());
    command
        .arg("--data-dir")
        .arg(data_dir)
        .arg(mode)
        .env("LASTEST_BIND", bind)
        .env("LASTEST_INTERNAL_RANGES", "127.0.0.0/8")
        .env("LASTEST_LOG_LEVEL", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    ChildGuard(command.spawn().unwrap())
}

async fn wait_ready(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if let Ok(response) = client.get(format!("{base}/api/health/ready")).send().await {
            if response.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("API did not become ready");
}

#[tokio::test]
async fn cli_doctor_bootstrap_workflow_persistence_and_import_smoke() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    let doctor = cli_json(&data_dir, &["doctor"], None);
    assert_eq!(doctor["config"]["valid"], true);
    assert_eq!(
        doctor["storage"]["supported_schema_version"],
        lastest::db::SCHEMA_VERSION
    );
    assert_eq!(doctor["tools"]["go_dependencies"], false);

    let bootstrap = cli_json(
        &data_dir,
        &[
            "admin",
            "bootstrap",
            "--username",
            "admin",
            "--password-stdin",
        ],
        Some("CorrectHorseBatteryStaple!\n"),
    );
    assert_eq!(bootstrap["user"]["role"], "admin");
    let duplicate = cli(
        &data_dir,
        &[
            "admin",
            "bootstrap",
            "--username",
            "admin",
            "--password-stdin",
        ],
        Some("CorrectHorseBatteryStaple!\n"),
    );
    assert_eq!(duplicate.status, 1, "second bootstrap must fail");

    let _serve = start_process(&data_dir, &bind, "serve");
    wait_ready(&base).await;
    let html = reqwest::get(format!("{base}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("login-view"));
    assert!(html.contains("Select a project"));
    let js = reqwest::get(format!("{base}/app.js"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(js.contains("/api/auth/login"));
    assert!(!js.contains("mock data"));

    let login = cli_json(
        &data_dir,
        &[
            "auth",
            "login",
            "--username",
            "admin",
            "--password-stdin",
            "--api-url",
            &base,
        ],
        Some("CorrectHorseBatteryStaple!\n"),
    );
    assert_eq!(login["username"], "admin");

    let project = cli_json(
        &data_dir,
        &[
            "project",
            "create",
            "--name",
            "cli-project",
            "--client",
            "Local Stand",
            "--description",
            "e2e fixture",
        ],
        None,
    );
    let project_id = project["project"]["id"].as_str().unwrap().to_string();
    let rules_path = temp.path().join("rules.json");
    std::fs::write(
        &rules_path,
        r#"[
          {"kind":"exact_domain","value":"localhost"},
          {"kind":"ip","value":"127.0.0.1"}
        ]"#,
    )
    .unwrap();
    let scope = cli_json(
        &data_dir,
        &[
            "scope",
            "update",
            "--project",
            &project_id,
            "--rules-file",
            rules_path.to_str().unwrap(),
            "--expected-version",
            "1",
            "--approve",
        ],
        None,
    );
    assert_eq!(scope["scope"]["status"], "approved");

    let server = spawn_http_server(|_| {
        HttpResponse::new(200, "<html><title>CLI E2E</title><body>ok</body></html>")
            .header("Server", "nginx/1.24.0")
    })
    .await;
    let target = format!("http://localhost:{}/", server.addr.port());
    let params = format!(r#"{{"targets":["{target}"],"mode":"url"}}"#);
    let _worker = start_process(&data_dir, &bind, "worker");
    let submitted = cli_json(
        &data_dir,
        &[
            "job",
            "submit",
            "--project",
            &project_id,
            "--task-type",
            "http.probe",
            "--params",
            &params,
            "--idempotency-key",
            "e2e-http",
        ],
        None,
    );
    let job_id = submitted["job"]["id"].as_str().unwrap().to_string();
    let mut final_job = Value::Null;
    for _ in 0..100 {
        let status = cli_json(&data_dir, &["job", "status", "--id", &job_id], None);
        let state = status["job"]["status"].as_str().unwrap().to_string();
        if matches!(
            state.as_str(),
            "succeeded" | "partial" | "failed" | "cancelled"
        ) {
            final_job = status;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert_eq!(
        final_job["job"]["status"], "succeeded",
        "job did not finish: {final_job}"
    );
    assert!(final_job["job"]["artifacts"].as_array().unwrap().len() == 1);

    let report_path = temp.path().join("report.json");
    let report_cli = cli(
        &data_dir,
        &[
            "report",
            "export",
            "--project",
            &project_id,
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(report_cli.status, 0, "{}", report_cli.stderr);
    let report: Value = serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["project"]["name"], "cli-project");
    assert!(!report["http"].as_array().unwrap().is_empty());
    assert_eq!(report["scope"]["current"]["status"], "approved");

    drop(_serve);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _serve = start_process(&data_dir, &bind, "serve");
    wait_ready(&base).await;
    let persisted = cli_json(&data_dir, &["job", "status", "--id", &job_id], None);
    assert_eq!(persisted["job"]["status"], "succeeded");
    let persisted_report = temp.path().join("report-after-restart.json");
    let after = cli(
        &data_dir,
        &[
            "report",
            "export",
            "--project",
            &project_id,
            "--format",
            "csv",
            "--output",
            persisted_report.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(after.status, 0, "{}", after.stderr);
    let csv = std::fs::read_to_string(&persisted_report).unwrap();
    assert!(csv.contains("http"));
    assert!(csv.contains("CLI E2E") || csv.contains("localhost"));

    let backup_dir = temp.path().join("backup");
    let backup = cli_json(
        &data_dir,
        &["backup", "--output", backup_dir.to_str().unwrap()],
        None,
    );
    assert!(backup["manifest"]["schema_version"].as_i64().unwrap() >= 1);
    assert!(backup_dir.join("lastest.sqlite").is_file());
    assert!(backup_dir.join("evidence").is_dir());
    let restored_data = temp.path().join("restored-data");
    let restore = cli_json(
        &restored_data,
        &["restore", "--from", backup_dir.to_str().unwrap(), "--force"],
        None,
    );
    assert_eq!(restore["schema_version"], lastest::db::SCHEMA_VERSION);
    let restore_port = free_port();
    let restore_bind = format!("127.0.0.1:{restore_port}");
    let restore_base = format!("http://{restore_bind}");
    let _restored_serve = start_process(&restored_data, &restore_bind, "serve");
    wait_ready(&restore_base).await;
    let restore_login = cli_json(
        &restored_data,
        &[
            "auth",
            "login",
            "--username",
            "admin",
            "--password-stdin",
            "--api-url",
            &restore_base,
        ],
        Some("CorrectHorseBatteryStaple!\n"),
    );
    assert_eq!(restore_login["username"], "admin");
    let restored_report_path = temp.path().join("restored-report.json");
    let restored_export = cli(
        &restored_data,
        &[
            "report",
            "export",
            "--project",
            &project_id,
            "--format",
            "json",
            "--output",
            restored_report_path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(restored_export.status, 0, "{}", restored_export.stderr);
    let restored_report: Value =
        serde_json::from_slice(&std::fs::read(restored_report_path).unwrap()).unwrap();
    assert_eq!(restored_report["project"]["name"], "cli-project");
    assert!(!restored_report["http"].as_array().unwrap().is_empty());

    let logout = cli_json(&data_dir, &["auth", "logout"], None);
    assert!(logout["message"].as_str().unwrap().contains("revoked"));
}

#[tokio::test]
async fn cli_import_dry_run_and_apply_smoke() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy/projects");
    let dry = cli_json(
        &data_dir,
        &[
            "import",
            "legacy",
            "--projects-dir",
            fixture.to_str().unwrap(),
            "--dry-run",
        ],
        None,
    );
    assert_eq!(dry["mode"], "dry-run");
    assert!(!data_dir.join("lastest.sqlite").exists());
    let apply = cli_json(
        &data_dir,
        &[
            "import",
            "legacy",
            "--projects-dir",
            fixture.to_str().unwrap(),
            "--apply",
        ],
        None,
    );
    assert_eq!(apply["mode"], "apply");
    assert!(apply["projects"].as_array().unwrap().len() >= 2);
    let second = cli_json(
        &data_dir,
        &[
            "import",
            "legacy",
            "--projects-dir",
            fixture.to_str().unwrap(),
            "--apply",
        ],
        None,
    );
    let resumed = second["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["source_name"] == "example.com")
        .unwrap();
    assert_eq!(resumed["status"], "resumed");
    let doctor = cli_json(&data_dir, &["doctor"], None);
    assert_eq!(doctor["storage"]["compatible"], true);
}
