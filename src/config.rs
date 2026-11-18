//! Runtime configuration. A TOML file is optional; environment variables
//! override the most important deployment settings.

use crate::scope::NetworkPolicy;
use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Profile {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: String,
    pub dns_server: Option<String>,
    pub secure_cookies: bool,
    pub session_ttl_hours: i64,
    pub cli_token_ttl_hours: i64,
    pub login_max_attempts: u32,
    pub login_lock_minutes: i64,
    pub internal_ranges: Vec<String>,
    pub worker_poll_ms: u64,
    pub worker_lease_seconds: i64,
    pub max_concurrent_jobs: u32,
    pub http_timeout_seconds: u64,
    pub max_body_bytes: u64,
    pub max_redirects: u32,
    pub max_queue_targets: usize,
    pub max_artifact_bytes: u64,
    pub max_crawl_pages: usize,
    pub max_crawl_depth: usize,
    pub max_wordlist_entries: usize,
    pub retention_days: i64,
    pub certspotter_url: String,
    pub certspotter_token: Option<String>,
    pub wayback_url: String,
    pub commoncrawl_url: String,
    pub shodan_internetdb_url: String,
    pub censys_url: String,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
    pub session_cookie_names: Vec<String>,
    pub tls_expiry_warning_days: i64,
    pub nmap_path: Option<PathBuf>,
    pub subfinder_path: Option<PathBuf>,
    pub dnsmap_path: Option<PathBuf>,
    pub dnsmap_timeout_seconds: u64,
    pub subfinder_timeout_seconds: u64,
    pub nmap_timeout_seconds: u64,
    pub nmap_max_output_bytes: u64,
    pub socks5_profiles: Vec<Socks5Profile>,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = PathBuf::from("lastest-data");
        Self {
            data_dir,
            bind: "127.0.0.1:8080".to_string(),
            dns_server: None,
            secure_cookies: false,
            session_ttl_hours: 12,
            cli_token_ttl_hours: 24,
            login_max_attempts: 5,
            login_lock_minutes: 15,
            internal_ranges: Vec::new(),
            worker_poll_ms: 500,
            worker_lease_seconds: 60,
            max_concurrent_jobs: 1,
            http_timeout_seconds: 10,
            max_body_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
            max_queue_targets: 5_000,
            max_artifact_bytes: 8 * 1024 * 1024,
            max_crawl_pages: 200,
            max_crawl_depth: 3,
            max_wordlist_entries: 5_000,
            retention_days: 90,
            certspotter_url: "https://api.certspotter.com/v1/issuances".to_string(),
            certspotter_token: None,
            wayback_url: "https://web.archive.org/cdx/search/cdx".to_string(),
            commoncrawl_url: "https://index.commoncrawl.org/collinfo.json".to_string(),
            shodan_internetdb_url: "https://internetdb.shodan.io".to_string(),
            censys_url: "https://search.censys.io/api/v2/hosts".to_string(),
            censys_api_id: None,
            censys_api_secret: None,
            session_cookie_names: vec!["session".to_string(), "sessionid".to_string()],
            tls_expiry_warning_days: 30,
            nmap_path: None,
            subfinder_path: None,
            dnsmap_path: None,
            dnsmap_timeout_seconds: 600,
            subfinder_timeout_seconds: 150,
            nmap_timeout_seconds: 120,
            nmap_max_output_bytes: 4 * 1024 * 1024,
            socks5_profiles: Vec::new(),
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut config = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read config {}", path.display()))?;
                toml::from_str(&text)
                    .with_context(|| format!("invalid config {}", path.display()))?
            }
            None => match std::env::var("LASTEST_CONFIG") {
                Ok(value) if !value.trim().is_empty() => {
                    let path = PathBuf::from(value);
                    let text = std::fs::read_to_string(&path)
                        .with_context(|| format!("cannot read config {}", path.display()))?;
                    toml::from_str(&text)
                        .with_context(|| format!("invalid config {}", path.display()))?
                }
                _ => Self::default(),
            },
        };
        config.apply_env()?;
        config.certspotter_token = config
            .certspotter_token
            .filter(|value| !value.trim().is_empty());
        config.censys_api_id = config
            .censys_api_id
            .filter(|value| !value.trim().is_empty());
        config.censys_api_secret = config
            .censys_api_secret
            .filter(|value| !value.trim().is_empty());
        config
            .socks5_profiles
            .retain(|profile| !profile.name.trim().is_empty());
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) -> Result<()> {
        if let Ok(value) = std::env::var("LASTEST_DNSMAP_PATH") {
            self.dnsmap_path = (!value.trim().is_empty()).then(|| PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("LASTEST_SUBFINDER_PATH") {
            self.subfinder_path = (!value.trim().is_empty()).then(|| PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("LASTEST_DATA_DIR") {
            if !value.trim().is_empty() {
                self.data_dir = PathBuf::from(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_BIND") {
            if !value.trim().is_empty() {
                self.bind = value;
            }
        }
        if let Ok(value) = std::env::var("LASTEST_DNS_SERVER") {
            if !value.trim().is_empty() {
                self.dns_server = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_SECURE_COOKIES") {
            self.secure_cookies = parse_bool(&value)?;
        }
        if let Ok(value) = std::env::var("LASTEST_INTERNAL_RANGES") {
            self.internal_ranges = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(value) = std::env::var("LASTEST_LOG_LEVEL") {
            self.log_level = value;
        }
        if let Ok(value) = std::env::var("LASTEST_CERTSPOTTER_TOKEN") {
            if !value.trim().is_empty() {
                self.certspotter_token = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_CENSYS_API_ID") {
            if !value.trim().is_empty() {
                self.censys_api_id = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_CENSYS_API_SECRET") {
            if !value.trim().is_empty() {
                self.censys_api_secret = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_NMAP_PATH") {
            if !value.trim().is_empty() {
                self.nmap_path = Some(PathBuf::from(value));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.dnsmap_timeout_seconds == 0 {
            anyhow::bail!("dnsmap_timeout_seconds must be positive");
        }
        if self.subfinder_timeout_seconds == 0 {
            anyhow::bail!("subfinder_timeout_seconds must be positive");
        }
        self.bind.parse::<std::net::SocketAddr>().with_context(|| {
            format!("invalid bind address in LASTEST_BIND / bind: {}", self.bind)
        })?;
        if self.session_ttl_hours <= 0 {
            anyhow::bail!("session_ttl_hours must be positive");
        }
        if self.cli_token_ttl_hours <= 0 {
            anyhow::bail!("cli_token_ttl_hours must be positive");
        }
        if self.max_concurrent_jobs == 0 {
            anyhow::bail!("max_concurrent_jobs must be at least 1");
        }
        if self.http_timeout_seconds == 0 {
            anyhow::bail!("http_timeout_seconds must be positive");
        }
        if self.max_queue_targets == 0 {
            anyhow::bail!("max_queue_targets must be positive");
        }
        if self.certspotter_url.trim().is_empty() {
            anyhow::bail!("certspotter_url must not be empty");
        }
        for range in &self.internal_ranges {
            range
                .parse::<IpNet>()
                .with_context(|| format!("invalid internal range: {range}"))?;
        }
        if let Some(server) = &self.dns_server {
            server
                .parse::<std::net::SocketAddr>()
                .with_context(|| format!("invalid dns_server address: {server}"))?;
        }
        let mut proxy_names = std::collections::HashSet::new();
        for profile in &self.socks5_profiles {
            if profile.name.trim().is_empty() || profile.host.trim().is_empty() || profile.port == 0
            {
                anyhow::bail!("SOCKS5 profiles require a name, host and non-zero port");
            }
            if !proxy_names.insert(profile.name.as_str()) {
                anyhow::bail!("duplicate SOCKS5 profile name: {}", profile.name);
            }
            if profile
                .username
                .as_deref()
                .is_some_and(|value| value.len() > 255)
                || profile
                    .password
                    .as_deref()
                    .is_some_and(|value| value.len() > 255)
            {
                anyhow::bail!("SOCKS5 credentials must not exceed 255 bytes");
            }
        }
        if self.secure_cookies
            && !self.bind.starts_with("127.0.0.1")
            && !self.bind.starts_with("localhost")
            && !self.bind.starts_with("[::1]")
        {
            tracing::warn!(
                "secure_cookies is enabled; terminate TLS at a trusted reverse proxy and keep the API on a loopback/private interface"
            );
        }
        Ok(())
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("lastest.sqlite")
    }

    pub fn evidence_dir(&self) -> PathBuf {
        self.data_dir.join("evidence")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }

    pub fn network_policy(&self) -> NetworkPolicy {
        NetworkPolicy::new(
            self.internal_ranges
                .iter()
                .filter_map(|item| item.parse::<IpNet>().ok())
                .collect(),
        )
    }

    pub fn http_timeout(&self) -> Duration {
        Duration::from_secs(self.http_timeout_seconds)
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("cannot create data directory {}", self.data_dir.display()))?;
        std::fs::create_dir_all(self.evidence_dir())?;
        std::fs::create_dir_all(self.tmp_dir())?;
        Ok(())
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => anyhow::bail!("invalid boolean value: {other}"),
    }
}
