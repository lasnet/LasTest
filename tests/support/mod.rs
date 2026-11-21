#![allow(dead_code)]

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use lastest::auth::AuthService;
use lastest::config::Config;
use lastest::db::projects::ScopeRevision;
use lastest::db::Db;
use lastest::domain::{Project, ScopeStatus};
use lastest::scope::{Scope, ScopeRule};
use lastest::tasks::TaskContext;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

pub struct TestEnv {
    pub temp: TempDir,
    pub config: Config,
    pub db: Db,
    pub auth: AuthService,
    pub app: Router,
}

impl TestEnv {
    pub fn new() -> Self {
        let env = Self::empty();
        env.auth
            .bootstrap("admin", "CorrectHorseBatteryStaple!")
            .unwrap();
        env
    }

    pub fn empty() -> Self {
        let temp = TempDir::new().unwrap();
        let mut config = Config {
            data_dir: temp.path().to_path_buf(),
            internal_ranges: vec!["127.0.0.0/8".to_string(), "203.0.113.0/24".to_string()],
            http_timeout_seconds: 3,
            worker_poll_ms: 10,
            worker_lease_seconds: 10,
            max_body_bytes: 1024 * 1024,
            max_artifact_bytes: 4 * 1024 * 1024,
            max_queue_targets: 100,
            max_crawl_pages: 20,
            max_crawl_depth: 2,
            max_wordlist_entries: 100,
            ..Config::default()
        };
        config.secure_cookies = false;
        config.ensure_dirs().unwrap();
        let db = Db::new(config.database_path()).unwrap();
        let auth = AuthService::new(db.clone(), config.clone());
        let state = Arc::new(lastest::api::AppState::new(config.clone(), db.clone()));
        let app = lastest::api::router(state);
        Self {
            temp,
            config,
            db,
            auth,
            app,
        }
    }

    pub fn project_with_scope(
        &self,
        name: &str,
        rules: Vec<ScopeRule>,
        approve: bool,
    ) -> (Project, ScopeRevision) {
        let project = self
            .db
            .create_project(name, "test", "fixture", None, None, "admin")
            .unwrap();
        let scope = Scope::new(rules).unwrap();
        let revision = self
            .db
            .replace_scope(&project.id, Some(1), &scope, "fixture", "admin", approve)
            .unwrap();
        assert_eq!(
            revision.status,
            if approve {
                ScopeStatus::Approved
            } else {
                ScopeStatus::Draft
            }
        );
        (project, revision)
    }

    pub async fn login_web(&self) -> String {
        let response = call(
            &self.app,
            Method::POST,
            "/api/auth/login",
            Some(serde_json::json!({
                "username": "admin",
                "password": "CorrectHorseBatteryStaple!"
            })),
            &[("Host", "localhost"), ("Origin", "http://localhost")],
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        response
            .headers
            .get("set-cookie")
            .expect("login must set a cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }
}

pub struct ApiResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
    pub text: String,
}

pub async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> ApiResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({"raw": text}));
    ApiResponse {
        status,
        headers,
        body,
        text,
    }
}

pub fn cookie_headers(cookie: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Host", "localhost".to_string()),
        ("Origin", "http://localhost".to_string()),
        ("Cookie", cookie.to_string()),
    ]
}

pub fn as_pairs<'a>(values: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    values
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect()
}

pub fn scope_rules(items: &[(&str, &str)]) -> Vec<ScopeRule> {
    items
        .iter()
        .map(|(kind, value)| {
            let kind = match *kind {
                "exact" => lastest::scope::RuleKind::ExactDomain,
                "tree" => lastest::scope::RuleKind::SubdomainTree,
                "ip" => lastest::scope::RuleKind::Ip,
                "cidr" => lastest::scope::RuleKind::Cidr,
                other => panic!("bad scope kind {other}"),
            };
            ScopeRule::new(kind, value, false).unwrap()
        })
        .collect()
}

pub fn task_context(env: &TestEnv, scope: Scope, job_id: &str) -> TaskContext {
    let project = env
        .db
        .create_project(
            &format!("ctx-{}", job_id.replace('_', "-")),
            "test",
            "task context fixture",
            None,
            None,
            "admin",
        )
        .unwrap();
    env.db
        .replace_scope(&project.id, Some(1), &scope, "task fixture", "admin", true)
        .unwrap();
    TaskContext {
        db: env.db.clone(),
        config: env.config.clone(),
        project_id: project.id,
        job_id: job_id.to_string(),
        attempt_id: "att_test".to_string(),
        scope: lastest::scope::EffectiveScope::new(scope.clone(), scope),
        cancel: Arc::new(AtomicBool::new(false)),
        previous_job: None,
        input_jobs: Vec::new(),
    }
}

pub fn make_job(task_type: &str, params: Value) -> lastest::domain::Job {
    lastest::domain::Job {
        id: "job_test".to_string(),
        project_id: "prj_test".to_string(),
        task_type: task_type.to_string(),
        params,
        status: lastest::domain::JobStatus::Running,
        scope_revision_id: "scr_test".to_string(),
        scope_version: 1,
        idempotency_key: None,
        created_by: "admin".to_string(),
        created_at: lastest::domain::now_rfc3339(),
        started_at: None,
        finished_at: None,
        error: None,
        result: serde_json::json!({}),
        counters: Default::default(),
        archived: false,
        chain_run_id: None,
        chain_order: None,
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }
}

pub struct HttpServer {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub requests: Arc<Mutex<Vec<String>>>,
    shutdown: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.handle.abort();
    }
}

pub async fn spawn_http_server<F>(handler: F) -> HttpServer
where
    F: Fn(&str) -> HttpResponse + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let hits_clone = hits.clone();
    let requests_clone = requests.clone();
    let shutdown_clone = shutdown.clone();
    let handler = Arc::new(handler);
    let handle = tokio::spawn(async move {
        loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            }
            let accepted =
                tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await;
            let Ok(Ok((mut stream, _))) = accepted else {
                continue;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut buffer = vec![0u8; 64 * 1024];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buffer))
                    .await;
            let Ok(Ok(count)) = read else {
                continue;
            };
            let request = String::from_utf8_lossy(&buffer[..count]).to_string();
            requests_clone.lock().unwrap().push(request.clone());
            let response = handler(&request);
            let reason = match response.status {
                200 => "OK",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "OK",
            };
            let mut head = format!(
                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                response.status,
                reason,
                response.body.len()
            );
            for (key, value) in &response.headers {
                head.push_str(&format!("{key}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(response.body.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    HttpServer {
        addr,
        hits,
        requests,
        shutdown,
        handle,
    }
}

pub struct DnsServer {
    pub addr: SocketAddr,
    pub queries: Arc<Mutex<Vec<(String, u16)>>>,
    shutdown: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.handle.abort();
    }
}

/// Minimal UDP DNS responder. The closure returns RDATA values for the query.
pub async fn spawn_dns_server<F>(answers: F) -> DnsServer
where
    F: Fn(&str, u16) -> Vec<Vec<u8>> + Send + Sync + 'static,
{
    spawn_dns_response_server(move |name, kind| (0, answers(name, kind))).await
}

/// DNS fixture with explicit response codes, including NXDOMAIN/SERVFAIL.
pub async fn spawn_dns_response_server<F>(answers: F) -> DnsServer
where
    F: Fn(&str, u16) -> (u8, Vec<Vec<u8>>) + Send + Sync + 'static,
{
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let queries = Arc::new(Mutex::new(Vec::new()));
    let queries_clone = queries.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let answers = Arc::new(answers);
    let handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            if shutdown_clone.load(Ordering::SeqCst) {
                break;
            }
            let received = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                socket.recv_from(&mut buffer),
            )
            .await;
            let Ok(Ok((count, peer))) = received else {
                continue;
            };
            let packet = &buffer[..count];
            if packet.len() < 12 {
                continue;
            }
            let mut offset = 12;
            let mut labels = Vec::new();
            while offset < packet.len() {
                let len = packet[offset] as usize;
                offset += 1;
                if len == 0 || offset + len > packet.len() {
                    break;
                }
                labels.push(String::from_utf8_lossy(&packet[offset..offset + len]).to_string());
                offset += len;
            }
            if offset + 4 > packet.len() {
                continue;
            }
            let query_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 4;
            let question_end = offset;
            let name = labels.join(".").to_ascii_lowercase();
            queries_clone
                .lock()
                .unwrap()
                .push((name.clone(), query_type));
            let (rcode, rdatas) = answers(&name, query_type);
            let mut response = Vec::new();
            response.extend_from_slice(&packet[0..2]);
            response.extend_from_slice(&[0x81, 0x80 | (rcode & 0x0f)]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&(rdatas.len() as u16).to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..question_end]);
            for rdata in rdatas {
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&query_type.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&60u32.to_be_bytes());
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(&rdata);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    DnsServer {
        addr,
        queries,
        shutdown,
        handle,
    }
}

pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}
