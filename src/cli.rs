//! Operator CLI. Remote commands call the same `/api/v2` routes as the web UI;
//! bootstrap, doctor, import, backup and restore operate on the local data dir.

use crate::auth::AuthService;
use crate::config::Config;
use crate::db::Db;
use crate::import::{self, ImportOptions};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "lastest",
    version,
    about = "LasTest 2.0 local assessment platform"
)]
pub struct Cli {
    #[arg(long, global = true, env = "LASTEST_CONFIG")]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the HTTP API and embedded UI
    Serve,
    /// Start the queue worker
    Worker,
    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Project commands
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Scope commands
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Job commands
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Report commands
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Administrator commands
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Import a LasTest 1.x data copy
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    /// Read-only deployment diagnosis
    Doctor,
    /// Task catalog
    TaskTypes,
    /// Create a consistent SQLite + evidence backup
    Backup {
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a backup into the configured data directory
    Restore {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    Login(LoginArgs),
    Logout,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub password_stdin: bool,
    #[arg(long)]
    pub password_file: Option<PathBuf>,
    #[arg(long)]
    pub api_url: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        client: String,
        #[arg(long, default_value = "")]
        description: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
    Show {
        #[arg(long)]
        project: String,
    },
    Update {
        #[arg(long)]
        project: String,
        #[arg(long)]
        rules_file: PathBuf,
        #[arg(long)]
        expected_version: Option<i64>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum JobCommand {
    Submit {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task_type: String,
        #[arg(long)]
        params: Option<String>,
        #[arg(long)]
        params_file: Option<PathBuf>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Status {
        #[arg(long)]
        id: String,
    },
    Cancel {
        #[arg(long)]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Export {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    Bootstrap {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Import from a legacy projects directory
    Legacy(ImportArgs),
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[arg(long)]
    pub projects_dir: PathBuf,
    #[arg(long)]
    pub database: Option<PathBuf>,
    #[arg(long)]
    pub logs_root: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    #[arg(long = "map")]
    pub mappings: Vec<String>,
    #[arg(long, default_value_t = false)]
    pub import_users: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSession {
    api_url: String,
    token: String,
    username: String,
    expires_at: String,
}

#[derive(Debug)]
pub struct CliError {
    pub code: u8,
    pub message: String,
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn usage(message: impl Into<String>) -> Self {
        Self::new(2, message)
    }
    fn auth(message: impl Into<String>) -> Self {
        Self::new(3, message)
    }
    fn api(message: impl Into<String>) -> Self {
        Self::new(4, message)
    }
    fn other(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(value: anyhow::Error) -> Self {
        Self::other(format!("{value:#}"))
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::other(value.to_string())
    }
}

type CliResult<T = Value> = std::result::Result<T, CliError>;

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let payload = json!({"error": {"message": err.message, "code": err.code}});
            eprintln!("{payload}");
            ExitCode::from(err.code)
        }
    }
}

async fn dispatch(cli: Cli) -> CliResult<()> {
    let mut config =
        Config::load(cli.config.as_deref()).map_err(|err| CliError::other(format!("{err:#}")))?;
    if let Some(data_dir) = cli.data_dir {
        config.data_dir = data_dir;
        config
            .validate()
            .map_err(|err| CliError::other(format!("{err:#}")))?;
    }
    match cli.command {
        Command::Serve => {
            init_tracing(&config);
            crate::serve(config)
                .await
                .map_err(|err| CliError::other(format!("{err:#}")))
        }
        Command::Worker => {
            init_tracing(&config);
            config.ensure_dirs()?;
            let db = Db::new(config.database_path())?;
            let worker = crate::worker::Worker::new(config, db);
            worker
                .run()
                .await
                .map_err(|err| CliError::other(format!("{err:#}")))
        }
        Command::Auth { command } => match command {
            AuthCommand::Login(args) => login(&config, args).await,
            AuthCommand::Logout => logout(&config).await,
        },
        Command::Project { command } => match command {
            ProjectCommand::List => {
                let client = CliApi::from_session(&config, None)?;
                let value = client.get("/api/v2/projects").await?;
                print_json(&value)
            }
            ProjectCommand::Create {
                name,
                client,
                description,
            } => {
                let api = CliApi::from_session(&config, None)?;
                let value = api
                    .post(
                        "/api/v2/projects",
                        &json!({"name": name, "client": client, "description": description}),
                    )
                    .await?;
                print_json(&value)
            }
        },
        Command::Scope { command } => match command {
            ScopeCommand::Show { project } => {
                let api = CliApi::from_session(&config, None)?;
                let value = api
                    .get(&format!("/api/v2/projects/{}/scope", enc(&project)))
                    .await?;
                print_json(&value)
            }
            ScopeCommand::Update {
                project,
                rules_file,
                expected_version,
                note,
                approve,
            } => {
                let rules: Value =
                    serde_json::from_str(&std::fs::read_to_string(&rules_file).map_err(|err| {
                        CliError::usage(format!("cannot read rules file: {err}"))
                    })?)
                    .map_err(|err| CliError::usage(format!("rules file must be JSON: {err}")))?;
                if !rules.is_array() {
                    return Err(CliError::usage("rules file must contain a JSON array"));
                }
                let api = CliApi::from_session(&config, None)?;
                let value = api
                    .put(
                        &format!("/api/v2/projects/{}/scope", enc(&project)),
                        &json!({
                            "rules": rules,
                            "expected_version": expected_version,
                            "note": note.unwrap_or_default(),
                            "approve": approve
                        }),
                    )
                    .await?;
                print_json(&value)
            }
        },
        Command::Job { command } => match command {
            JobCommand::Submit {
                project,
                task_type,
                params,
                params_file,
                idempotency_key,
            } => {
                let params = match (params, params_file) {
                    (Some(value), _) => serde_json::from_str(&value)
                        .map_err(|err| CliError::usage(format!("params must be JSON: {err}")))?,
                    (None, Some(path)) => serde_json::from_str(
                        &std::fs::read_to_string(path)
                            .map_err(|err| CliError::usage(format!("cannot read params: {err}")))?,
                    )
                    .map_err(|err| CliError::usage(format!("params file must be JSON: {err}")))?,
                    (None, None) => json!({}),
                };
                let api = CliApi::from_session(&config, None)?;
                let value = api
                    .post(
                        &format!("/api/v2/projects/{}/jobs", enc(&project)),
                        &json!({
                            "task_type": task_type,
                            "params": params,
                            "idempotency_key": idempotency_key
                        }),
                    )
                    .await?;
                print_json(&value)
            }
            JobCommand::Status { id } => {
                let api = CliApi::from_session(&config, None)?;
                let value = api.get(&format!("/api/v2/jobs/{}", enc(&id))).await?;
                print_json(&value)
            }
            JobCommand::Cancel { id } => {
                let api = CliApi::from_session(&config, None)?;
                let value = api
                    .post(&format!("/api/v2/jobs/{}/cancel", enc(&id)), &json!({}))
                    .await?;
                print_json(&value)
            }
        },
        Command::Report { command } => match command {
            ReportCommand::Export {
                project,
                format,
                output,
            } => {
                if !matches!(format.as_str(), "json" | "csv") {
                    return Err(CliError::usage("format must be json or csv"));
                }
                let api = CliApi::from_session(&config, None)?;
                let bytes = api
                    .get_bytes(&format!(
                        "/api/v2/projects/{}/reports/{}",
                        enc(&project),
                        format
                    ))
                    .await?;
                if let Some(path) = output {
                    std::fs::write(path, bytes)?;
                } else {
                    std::io::stdout().write_all(&bytes)?;
                }
                Ok(())
            }
        },
        Command::Admin {
            command:
                AdminCommand::Bootstrap {
                    username,
                    password_stdin,
                    password_file,
                },
        } => {
            config.ensure_dirs()?;
            let db = Db::new(config.database_path())?;
            let auth = AuthService::new(db, config);
            let password = read_secret(password_stdin, password_file.as_deref())?;
            let user = auth
                .bootstrap(&username, &password)
                .map_err(|err| CliError::other(format!("{err:#}")))?;
            print_json(&json!({"user": user, "message": "administrator created"}))
        }
        Command::Import {
            command: ImportCommand::Legacy(options),
        } => {
            if options.apply && options.dry_run {
                return Err(CliError::usage(
                    "--apply and --dry-run are mutually exclusive",
                ));
            }
            let mut mappings = std::collections::HashMap::new();
            for mapping in &options.mappings {
                let Some((from, to)) = mapping.split_once('=') else {
                    return Err(CliError::usage("--map requires old=new"));
                };
                mappings.insert(from.to_string(), to.to_string());
            }
            if options.apply {
                config.ensure_dirs()?;
            }
            let import_options = ImportOptions {
                projects_dir: options.projects_dir,
                database: options.database,
                logs_root: options.logs_root,
                apply: options.apply && !options.dry_run,
                mappings,
                import_users: options.import_users,
                actor: "cli-import".to_string(),
            };
            let report = import::run_import(&config, &import_options)
                .await
                .map_err(|err| CliError::other(format!("{err:#}")))?;
            let value =
                serde_json::to_value(&report).map_err(|err| CliError::other(err.to_string()))?;
            print_json(&value)
        }
        Command::Doctor => doctor(&config),
        Command::TaskTypes => {
            let api = CliApi::from_session(&config, None)?;
            let value = api.get("/api/v2/task-types").await?;
            print_json(&value)
        }
        Command::Backup { output } => backup(&config, &output),
        Command::Restore { from, force } => restore(&config, &from, force),
    }
}

fn init_tracing(config: &Config) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn session_path(config: &Config) -> PathBuf {
    config.data_dir.join("cli-session.json")
}

fn default_api_url(config: &Config) -> String {
    let bind = config
        .bind
        .replace("0.0.0.0", "127.0.0.1")
        .replace("[::]", "[::1]");
    let scheme = if config.secure_cookies {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{bind}")
}

async fn login(config: &Config, args: LoginArgs) -> CliResult<()> {
    let password = read_secret(args.password_stdin, args.password_file.as_deref())?;
    let api_url = args.api_url.unwrap_or_else(|| default_api_url(config));
    let client = CliApi {
        base: api_url.clone(),
        token: None,
    };
    let value = client
        .post(
            "/api/v2/auth/login",
            &json!({"username": args.username, "password": password, "client": "cli"}),
        )
        .await?;
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::api("login response did not include a CLI token"))?
        .to_string();
    let session = StoredSession {
        api_url,
        token,
        username: value["user"]["username"]
            .as_str()
            .unwrap_or(&args.username)
            .to_string(),
        expires_at: value["expires_at"].as_str().unwrap_or("").to_string(),
    };
    save_session(config, &session)?;
    print_json(&json!({
        "message": "CLI session stored with mode 0600",
        "username": session.username,
        "expires_at": session.expires_at
    }))
}

async fn logout(config: &Config) -> CliResult<()> {
    let session = load_session(config)?;
    let client = CliApi {
        base: session.api_url.clone(),
        token: Some(session.token.clone()),
    };
    client.post("/api/v2/auth/logout", &json!({})).await?;
    match std::fs::remove_file(session_path(config)) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(CliError::other(err.to_string())),
    }
    print_json(&json!({"message": "logged out and CLI token revoked"}))
}

fn save_session(config: &Config, session: &StoredSession) -> CliResult<()> {
    std::fs::create_dir_all(&config.data_dir)?;
    let path = session_path(config);
    let tmp = path.with_extension("json.tmp");
    let data =
        serde_json::to_vec_pretty(session).map_err(|err| CliError::other(err.to_string()))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&data)?;
    file.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_session(config: &Config) -> CliResult<StoredSession> {
    let path = session_path(config);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .map_err(|_| CliError::auth("not logged in; run 'lastest auth login'"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(CliError::auth(
                "CLI session file permissions are too open; remove it and log in again",
            ));
        }
    }
    let data = std::fs::read(&path)
        .map_err(|_| CliError::auth("not logged in; run 'lastest auth login'"))?;
    serde_json::from_slice(&data).map_err(|_| CliError::auth("invalid CLI session file"))
}

fn read_secret(password_stdin: bool, password_file: Option<&Path>) -> CliResult<String> {
    if let Some(path) = password_file {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map_err(|err| CliError::usage(format!("cannot stat password file: {err}")))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(CliError::usage(
                    "password file must not be readable by group or others (chmod 600)",
                ));
            }
        }
        let value = std::fs::read_to_string(path)
            .map_err(|err| CliError::usage(format!("cannot read password file: {err}")))?;
        let value = value.trim_end_matches(['\n', '\r']).to_string();
        if value.is_empty() {
            return Err(CliError::usage("password file is empty"));
        }
        return Ok(value);
    }
    if password_stdin || !std::io::stdin().is_terminal() {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .map_err(|err| CliError::usage(format!("cannot read password from stdin: {err}")))?;
        let value = value.trim_end_matches(['\n', '\r']).to_string();
        if value.is_empty() {
            return Err(CliError::usage("password from stdin is empty"));
        }
        Ok(value)
    } else {
        rpassword::prompt_password("Password: ")
            .map_err(|err| CliError::usage(format!("cannot read password: {err}")))
    }
}

fn print_json(value: &Value) -> CliResult<()> {
    let mut stdout = std::io::stdout();
    serde_json::to_writer_pretty(&mut stdout, value)
        .map_err(|err| CliError::other(err.to_string()))?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

struct CliApi {
    base: String,
    token: Option<String>,
}

impl CliApi {
    fn from_session(config: &Config, api_url: Option<String>) -> CliResult<Self> {
        let session = load_session(config)?;
        Ok(Self {
            base: api_url.unwrap_or(session.api_url),
            token: Some(session.token),
        })
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("lastest-cli/2.0")
            .build()
            .unwrap_or_default()
    }

    async fn get(&self, path: &str) -> CliResult<Value> {
        self.request(reqwest::Method::GET, path, None).await
    }

    async fn get_bytes(&self, path: &str) -> CliResult<Vec<u8>> {
        let response = self.send(reqwest::Method::GET, path, None).await?;
        Ok(response
            .bytes()
            .await
            .map_err(|err| CliError::api(err.to_string()))?
            .to_vec())
    }

    async fn post(&self, path: &str, body: &Value) -> CliResult<Value> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    async fn put(&self, path: &str, body: &Value) -> CliResult<Value> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> CliResult<Value> {
        let response = self.send(method, path, body).await?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| CliError::api(err.to_string()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)}));
        if !status.is_success() {
            let message = value["error"]["message"]
                .as_str()
                .unwrap_or("API request failed");
            return Err(CliError::api(format!(
                "HTTP {}: {message}",
                status.as_u16()
            )));
        }
        Ok(value)
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> CliResult<reqwest::Response> {
        let url = format!("{}{}", self.base.trim_end_matches('/'), path);
        let mut request = self.client().request(method, &url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|err| CliError::api(format!("cannot reach API at {url}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await.unwrap_or_default();
            let value: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"error": {"message": String::from_utf8_lossy(&bytes)}}));
            let message = value["error"]["message"]
                .as_str()
                .unwrap_or("API request failed");
            let code = if status == reqwest::StatusCode::UNAUTHORIZED {
                3
            } else if status == reqwest::StatusCode::NOT_FOUND {
                5
            } else {
                4
            };
            return Err(CliError::new(
                code,
                format!("HTTP {}: {message}", status.as_u16()),
            ));
        }
        Ok(response)
    }
}

fn doctor(config: &Config) -> CliResult<()> {
    config.ensure_dirs()?;
    let writable = {
        let probe = config.data_dir.join(".doctor-probe");
        let result = std::fs::write(&probe, b"ok").and_then(|_| std::fs::remove_file(&probe));
        result.is_ok()
    };
    let free = fs2::available_space(&config.data_dir).unwrap_or(0);
    let db = Db::new(config.database_path())?;
    let schema = db.schema_version()?;
    let nmap = config
        .nmap_path
        .as_ref()
        .filter(|path| path.is_file())
        .map(|path| path.display().to_string());
    let value = json!({
        "config": {
            "valid": true,
            "bind": config.bind,
            "data_dir": config.data_dir,
            "secure_cookies": config.secure_cookies,
            "internal_ranges": config.internal_ranges,
        },
        "storage": {
            "database": config.database_path(),
            "schema_version": schema,
            "supported_schema_version": crate::db::SCHEMA_VERSION,
            "compatible": schema == crate::db::SCHEMA_VERSION,
            "data_dir_writable": writable,
            "free_bytes": free,
            "evidence_dir": config.evidence_dir(),
        },
        "tools": {
            "nmap": nmap,
            "nmap_available": nmap.is_some(),
            "certspotter_configured": !config.certspotter_url.is_empty(),
            "certspotter_token_configured": config.certspotter_token.is_some(),
            "censys_configured": config.censys_api_id.is_some() && config.censys_api_secret.is_some(),
            "shodan_internetdb_configured": true,
            "go_dependencies": false,
            "python_dependencies": false,
        },
        "worker": {
            "state": "not probed by doctor; compare API readiness and worker logs",
            "lease_seconds": config.worker_lease_seconds
        },
        "retention_days": config.retention_days
    });
    print_json(&value)
}

fn backup(config: &Config, output: &Path) -> CliResult<()> {
    if !config.database_path().is_file() {
        return Err(CliError::usage(
            "database does not exist; start the API once",
        ));
    }
    std::fs::create_dir_all(output)?;
    let db = Db::new(config.database_path())?;
    let schema = db.schema_version()?;
    let target_db = output.join("lastest.sqlite");
    db.backup_to(&target_db)?;
    let evidence_target = output.join("evidence");
    copy_dir(&config.evidence_dir(), &evidence_target)?;
    let manifest = json!({
        "format": "lastest-backup-1",
        "created_at": crate::domain::now_rfc3339(),
        "schema_version": schema,
        "supported_schema_version": crate::db::SCHEMA_VERSION,
        "database": "lastest.sqlite",
        "evidence": "evidence",
        "note": "Stop result-producing workers or accept the point-in-time boundary recorded by the SQLite backup."
    });
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|err| CliError::other(err.to_string()))?,
    )?;
    print_json(&json!({"backup": output, "manifest": manifest}))
}

fn restore(config: &Config, from: &Path, force: bool) -> CliResult<()> {
    let source_db = from.join("lastest.sqlite");
    if !source_db.is_file() {
        return Err(CliError::usage("backup does not contain lastest.sqlite"));
    }
    let conn = rusqlite::Connection::open_with_flags(
        &source_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|err| CliError::other(format!("cannot open backup database: {err}")))?;
    let source_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|err| CliError::other(format!("backup schema is unreadable: {err}")))?;
    if source_version > crate::db::SCHEMA_VERSION {
        return Err(CliError::other(format!(
            "backup schema {} is newer than supported {}",
            source_version,
            crate::db::SCHEMA_VERSION
        )));
    }
    config.ensure_dirs()?;
    if config.database_path().exists() && !force {
        return Err(CliError::usage(
            "refusing to overwrite the current database without --force",
        ));
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    if config.database_path().exists() {
        let previous = config
            .data_dir
            .join(format!("lastest.sqlite.pre-restore-{stamp}"));
        std::fs::copy(config.database_path(), &previous)?;
    }
    let tmp = config.data_dir.join("lastest.sqlite.restore.tmp");
    std::fs::copy(&source_db, &tmp)?;
    std::fs::rename(&tmp, config.database_path())?;
    let source_evidence = from.join("evidence");
    if source_evidence.is_dir() {
        let target_evidence = config.evidence_dir();
        if target_evidence.exists() {
            let previous = config
                .data_dir
                .join(format!("evidence.pre-restore-{stamp}"));
            std::fs::rename(&target_evidence, previous)?;
        }
        copy_dir(&source_evidence, &target_evidence)?;
    }
    let db = Db::new(config.database_path())?;
    let schema = db.schema_version()?;
    print_json(&json!({"message": "restore completed", "schema_version": schema}))
}

fn copy_dir(source: &Path, target: &Path) -> CliResult<()> {
    if !source.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(target)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir(&path, &destination)?;
        } else if file_type.is_file() {
            std::fs::copy(&path, &destination)?;
        }
    }
    Ok(())
}
