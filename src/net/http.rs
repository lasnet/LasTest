use crate::config::Config;
use crate::net::dns::DnsClient;
use crate::scope::{canonical_ip, parse_target_url, NetworkPolicy, Scope, ScopeError};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION, SET_COOKIE};
use reqwest::redirect::Policy;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub status: u16,
    pub final_url: String,
    pub remote_ip: IpAddr,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub truncated: bool,
    pub redirects: Vec<String>,
    pub tls_cert_not_after: Option<DateTime<Utc>>,
}

impl FetchResult {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn content_type(&self) -> &str {
        self.header("content-type").unwrap_or("")
    }
}

#[derive(Clone)]
pub struct HttpProber {
    config: Config,
    dns: DnsClient,
}

impl HttpProber {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            dns: DnsClient::new(config)?,
        })
    }

    pub async fn get_in_scope(
        &self,
        url: &str,
        scope: &Scope,
        policy: &NetworkPolicy,
    ) -> Result<FetchResult> {
        self.get_with_authorizer(url, policy, |candidate| {
            self.authorize_url(candidate, scope).is_ok()
        })
        .await
    }

    /// Like `get_in_scope`, but re-evaluates authorization for every redirect
    /// hop. Callers can therefore apply a scope narrowed while a job is active
    /// before the next network operation.
    pub async fn get_with_authorizer<F>(
        &self,
        url: &str,
        policy: &NetworkPolicy,
        authorize: F,
    ) -> Result<FetchResult>
    where
        F: Fn(&Url) -> bool,
    {
        let mut current = parse_target_url(url)?;
        let mut redirects = Vec::new();
        let mut cert_not_after = None;
        for hop in 0..=self.config.max_redirects {
            if !authorize(&current) {
                anyhow::bail!("URL {} is not allowed by scope", current);
            }
            let (response, remote_ip) = self.request_pinned(&current, policy).await?;
            let status = response.status().as_u16();
            let final_url = current.to_string();
            if current.scheme() == "https" {
                cert_not_after = tls_cert_not_after(&current, remote_ip).await.ok().flatten();
            }
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if hop == self.config.max_redirects {
                    anyhow::bail!("redirect limit exceeded");
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .context("redirect without a valid Location header")?;
                let next = current
                    .join(location)
                    .with_context(|| format!("invalid redirect target: {location}"))?;
                if !matches!(next.scheme(), "http" | "https") {
                    anyhow::bail!("redirect target uses an unsupported scheme");
                }
                if !authorize(&next) {
                    anyhow::bail!("URL {} is not allowed by scope", next);
                }
                redirects.push(next.to_string());
                current = next;
                continue;
            }
            let (headers, body, truncated) = read_response(response, &self.config).await?;
            return Ok(FetchResult {
                status,
                final_url,
                remote_ip,
                headers,
                body,
                truncated,
                redirects,
                tls_cert_not_after: cert_not_after,
            });
        }
        anyhow::bail!("redirect limit exceeded")
    }

    pub fn authorize_url(&self, url: &Url, scope: &Scope) -> Result<()> {
        let host = url
            .host_str()
            .context("URL does not contain a host")?
            .trim_end_matches('.')
            .to_string();
        if let Ok(ip) = canonical_ip(&host) {
            if !scope.allows_ip(ip) {
                return Err(ScopeError::Url(format!(
                    "IP target {ip} is not explicitly allowed by scope"
                ))
                .into());
            }
        } else if !scope.allows_host(&host) {
            return Err(ScopeError::Url(format!("host {host} is not allowed by scope")).into());
        }
        Ok(())
    }

    async fn request_pinned(
        &self,
        url: &Url,
        policy: &NetworkPolicy,
    ) -> Result<(reqwest::Response, IpAddr)> {
        let host = url
            .host_str()
            .context("URL does not contain a host")?
            .to_string();
        let port = url
            .port_or_known_default()
            .context("URL does not contain a port")?;
        let ips = if let Ok(ip) = canonical_ip(&host) {
            vec![ip]
        } else {
            self.dns.resolve_ips(&host).await?
        };
        if ips.is_empty() {
            anyhow::bail!("no addresses resolved for {host}");
        }
        let mut last_error = None;
        for ip in ips {
            if let Err(err) = policy.permits(ip) {
                last_error = Some(anyhow::Error::from(err));
                continue;
            }
            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .timeout(self.config.http_timeout())
                .connect_timeout(self.config.http_timeout())
                .user_agent("LasTest authorized-assessment")
                .no_proxy()
                .resolve(&host, SocketAddr::new(ip, port))
                .build()
                .context("cannot build HTTP client")?;
            match client.get(url.clone()).send().await {
                Ok(response) => return Ok((response, ip)),
                Err(err) => last_error = Some(err.into()),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all resolved addresses were blocked")))
    }
}

async fn read_response(
    response: reqwest::Response,
    config: &Config,
) -> Result<(Vec<(String, String)>, String, bool)> {
    let status = response.status();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect();
    // Keep Set-Cookie observable for cookie checks without joining values.
    for cookie in response.headers().get_all(SET_COOKIE).iter() {
        if let Ok(value) = cookie.to_str() {
            if !headers.iter().any(|(k, v)| k == "set-cookie" && v == value) {
                headers.push(("set-cookie".to_string(), value.to_string()));
            }
        }
    }
    let mut body = Vec::new();
    let mut truncated = false;
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        let remaining = (config.max_body_bytes as usize).saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
        if body.len() >= config.max_body_bytes as usize {
            truncated = true;
            break;
        }
    }
    let _ = status;
    let text = String::from_utf8_lossy(&body).to_string();
    headers.sort();
    headers.dedup();
    Ok((headers, text, truncated))
}

pub async fn tls_cert_not_after(url: &Url, ip: IpAddr) -> Result<Option<DateTime<Utc>>> {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let host = url.host_str().context("URL has no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host).map_err(|_| anyhow::anyhow!("invalid TLS server name"))?;
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS connection timed out"))??;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
    let certs = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|items| items.to_vec());
    let Some(certs) = certs else {
        return Ok(None);
    };
    for cert in certs {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
            let ts = parsed.validity().not_after.timestamp();
            return Ok(DateTime::<Utc>::from_timestamp(ts, 0));
        }
    }
    Ok(None)
}

pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(4096)
        .collect()
}

pub fn headers_from_pairs(pairs: &[(String, String)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in pairs {
        if let (Ok(key), Ok(value)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&sanitize_header_value(value)),
        ) {
            headers.append(key, value);
        }
    }
    headers
}
