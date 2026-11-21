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

#[derive(Clone, Serialize, Deserialize)]
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
    pub censys_pat: Option<String>,
    pub censys_organization_id: Option<String>,
    pub censys_platform_url: String,
    pub provider_cache_ttl_seconds: i64,
    pub provider_negative_cache_ttl_seconds: i64,
    pub provider_cache_max_entries: usize,
    pub provider_min_interval_ms: u64,
    pub provider_cooldown_seconds: i64,
    pub provider_reservation_seconds: i64,
    pub provider_max_retries: u32,
    pub provider_max_candidates: usize,
    pub discovery_refresh_seconds: i64,
    pub max_discovery_candidates: usize,
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

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print credentials in diagnostics.
        f.debug_struct("Config")
            .field("data_dir", &self.data_dir)
            .field("bind", &self.bind)
            .field("dns_server", &self.dns_server)
            .field("secure_cookies", &self.secure_cookies)
            .field("retention_days", &self.retention_days)
            .field("certspotter_url", &self.certspotter_url)
            .field("wayback_url", &self.wayback_url)
            .field("commoncrawl_url", &self.commoncrawl_url)
            .field("shodan_internetdb_url", &self.shodan_internetdb_url)
            .field("censys_url", &self.censys_url)
            .field("censys_platform_url", &self.censys_platform_url)
            .field(
                "censys_api_id",
                &self.censys_api_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "censys_api_secret",
                &self.censys_api_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "censys_pat",
                &self.censys_pat.as_ref().map(|_| "<redacted>"),
            )
            .field("censys_organization_id", &self.censys_organization_id)
            .field("log_level", &self.log_level)
            .finish_non_exhaustive()
    }
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
            max_concurrent_jobs: 4,
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
            censys_pat: None,
            censys_organization_id: None,
            censys_platform_url: "https://api.platform.censys.io/v3/global/asset/host".to_string(),
            provider_cache_ttl_seconds: 86_400,
            provider_negative_cache_ttl_seconds: 300,
            provider_cache_max_entries: 10_000,
            provider_min_interval_ms: 250,
            provider_cooldown_seconds: 60,
            provider_reservation_seconds: 120,
            provider_max_retries: 3,
            provider_max_candidates: 1_000,
            discovery_refresh_seconds: 3_600,
            max_discovery_candidates: 1_000,
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
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        config.censys_api_id = config
            .censys_api_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        config.censys_api_secret = config
            .censys_api_secret
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        config.censys_pat = config
            .censys_pat
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        config.censys_organization_id = config
            .censys_organization_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        config
            .socks5_profiles
            .retain(|profile| !profile.name.trim().is_empty());
        config.validate()?;
        Ok(config)
    }

    fn apply_env(&mut self) -> Result<()> {
        if let Ok(value) = std::env::var("LASTEST_MAX_CONCURRENT_JOBS") {
            self.max_concurrent_jobs = value
                .parse()
                .context("LASTEST_MAX_CONCURRENT_JOBS must be a positive integer")?;
        }
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
        if let Ok(value) = std::env::var("LASTEST_CENSYS_PAT") {
            if !value.trim().is_empty() {
                self.censys_pat = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_CENSYS_ORGANIZATION_ID") {
            if !value.trim().is_empty() {
                self.censys_organization_id = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LASTEST_CENSYS_PLATFORM_URL") {
            if !value.trim().is_empty() {
                self.censys_platform_url = value;
            }
        }
        if let Ok(value) = std::env::var("LASTEST_PROVIDER_CACHE_TTL_SECONDS") {
            self.provider_cache_ttl_seconds = value
                .parse()
                .context("LASTEST_PROVIDER_CACHE_TTL_SECONDS must be an integer")?;
        }
        if let Ok(value) = std::env::var("LASTEST_PROVIDER_NEGATIVE_CACHE_TTL_SECONDS") {
            self.provider_negative_cache_ttl_seconds = value
                .parse()
                .context("LASTEST_PROVIDER_NEGATIVE_CACHE_TTL_SECONDS must be an integer")?;
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
        if self.censys_platform_url.trim().is_empty() {
            anyhow::bail!("censys_platform_url must not be empty");
        }
        for (name, endpoint) in [
            ("shodan_internetdb_url", &self.shodan_internetdb_url),
            ("censys_url", &self.censys_url),
            ("censys_platform_url", &self.censys_platform_url),
        ] {
            let parsed =
                url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid {name}"))?;
            let loopback = parsed.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            anyhow::ensure!(
                parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback),
                "{name} must use HTTPS (HTTP is only supported for loopback fixtures)"
            );
            anyhow::ensure!(
                parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.query().is_none()
                    && parsed.fragment().is_none(),
                "{name} must be an endpoint without embedded credentials, query or fragment"
            );
        }
        anyhow::ensure!(
            (1..=5).contains(&self.provider_max_retries),
            "provider_max_retries must be between 1 and 5"
        );
        anyhow::ensure!(
            self.provider_reservation_seconds > 0 && self.provider_cooldown_seconds > 0,
            "provider reservation and cooldown durations must be positive"
        );
        if self.provider_cache_ttl_seconds <= 0 {
            anyhow::bail!("provider_cache_ttl_seconds must be positive");
        }
        if self.provider_negative_cache_ttl_seconds <= 0 {
            anyhow::bail!("provider_negative_cache_ttl_seconds must be positive");
        }
        if self.provider_cache_max_entries == 0 {
            anyhow::bail!("provider_cache_max_entries must be positive");
        }
        if self.provider_max_candidates == 0 {
            anyhow::bail!("provider_max_candidates must be positive");
        }
        if self.max_discovery_candidates == 0 {
            anyhow::bail!("max_discovery_candidates must be positive");
        }
        if self.discovery_refresh_seconds < 0 {
            anyhow::bail!("discovery_refresh_seconds must not be negative");
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

/// Effective Censys transport selected from installation configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensysMode {
    Platform,
    Legacy,
    NotConfigured,
    Incomplete,
}

impl CensysMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform_v3_pat",
            Self::Legacy => "legacy_v2_basic",
            Self::NotConfigured => "not_configured",
            Self::Incomplete => "incomplete_configuration",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CensysIntegration {
    pub mode: CensysMode,
    pub configured: bool,
    pub requires_key: bool,
    pub reason: Option<String>,
    pub endpoint: String,
    pub legacy_deprecated: bool,
}

impl Config {
    /// Single small interface that task code uses to obtain provider
    /// configuration. A future Settings UI can replace the source without
    /// changing task implementations.
    pub fn censys_integration(&self) -> CensysIntegration {
        let has_pat = self.censys_pat.is_some();
        let has_id = self.censys_api_id.is_some();
        let has_secret = self.censys_api_secret.is_some();
        if has_pat {
            return CensysIntegration {
                mode: CensysMode::Platform,
                configured: true,
                requires_key: true,
                reason: None,
                endpoint: self.censys_platform_url.clone(),
                legacy_deprecated: false,
            };
        }
        if has_id && has_secret {
            return CensysIntegration {
                mode: CensysMode::Legacy,
                configured: true,
                requires_key: true,
                reason: Some(
                    "legacy Censys v2 Basic credentials are deprecated; migrate to a Platform PAT"
                        .to_string(),
                ),
                endpoint: self.censys_url.clone(),
                legacy_deprecated: true,
            };
        }
        if has_id || has_secret {
            return CensysIntegration {
                mode: CensysMode::Incomplete,
                configured: false,
                requires_key: true,
                reason: Some(
                    "Censys legacy credentials require both api_id and api_secret".to_string(),
                ),
                endpoint: self.censys_url.clone(),
                legacy_deprecated: true,
            };
        }
        CensysIntegration {
            mode: CensysMode::NotConfigured,
            configured: false,
            requires_key: true,
            reason: Some(
                "Censys is not configured; PTR and Shodan InternetDB remain available".to_string(),
            ),
            endpoint: String::new(),
            legacy_deprecated: false,
        }
    }

    pub fn provider_catalog(&self) -> serde_json::Value {
        let censys = self.censys_integration();
        serde_json::json!({
            "ptr": {
                "configured": true,
                "requires_key": false,
                "mode": "dns_ptr",
                "available": true,
                "reason": null
            },
            "shodan_internetdb": {
                "configured": true,
                "requires_key": false,
                "mode": "internetdb",
                "available": true,
                "reason": null
            },
            "censys": {
                "configured": censys.configured,
                "requires_key": censys.requires_key,
                "mode": censys.mode.as_str(),
                "available": censys.configured,
                "reason": censys.reason,
                "legacy_deprecated": censys.legacy_deprecated
            }
        })
    }
}
