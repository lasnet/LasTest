use crate::config::Config;
use crate::scope::{canonical_ip, ScopeError};
use anyhow::Result;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;

#[derive(Clone)]
pub struct DnsClient {
    resolver: TokioAsyncResolver,
    timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub record_type: String,
    pub value: String,
}

impl DnsClient {
    pub fn new(config: &Config) -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(config.http_timeout_seconds);
        opts.attempts = 2;
        let resolver = if let Some(server) = &config.dns_server {
            let address = server.parse::<std::net::SocketAddr>()?;
            let group =
                NameServerConfigGroup::from_ips_clear(&[address.ip()], address.port(), true);
            TokioAsyncResolver::tokio(ResolverConfig::from_parts(None, vec![], group), opts)
        } else {
            match hickory_resolver::system_conf::read_system_conf() {
                Ok((cfg, mut system_opts)) => {
                    system_opts.timeout = opts.timeout;
                    system_opts.attempts = opts.attempts;
                    TokioAsyncResolver::tokio(cfg, system_opts)
                }
                Err(_) => TokioAsyncResolver::tokio(ResolverConfig::default(), opts),
            }
        };
        Ok(Self {
            resolver,
            timeout_seconds: config.http_timeout_seconds,
        })
    }

    pub async fn lookup(&self, name: &str, record_type: RecordType) -> Result<Vec<DnsAnswer>> {
        let lookup = tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_seconds),
            self.resolver.lookup(name, record_type),
        )
        .await
        .map_err(|_| anyhow::anyhow!("DNS query timed out"))??;
        let mut out = Vec::new();
        for data in lookup.iter() {
            let value = match data {
                RData::A(a) => a.0.to_string(),
                RData::AAAA(a) => a.0.to_string(),
                other => other.to_string(),
            };
            out.push(DnsAnswer {
                record_type: record_type.to_string(),
                value: value.trim_matches('"').to_string(),
            });
        }
        out.sort_by(|a, b| a.value.cmp(&b.value));
        out.dedup_by(|a, b| a.value == b.value);
        Ok(out)
    }

    pub async fn resolve_ips(&self, name: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        for (record_type, label) in [(RecordType::A, "A"), (RecordType::AAAA, "AAAA")] {
            match self.lookup(name, record_type).await {
                Ok(answers) => {
                    for answer in answers {
                        if let Ok(ip) = canonical_ip(&answer.value) {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
                Err(err) => {
                    if label == "A" {
                        return Err(err);
                    }
                }
            }
        }
        if ips.is_empty() {
            anyhow::bail!("DNS name did not resolve: {name}");
        }
        Ok(ips)
    }

    pub async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>> {
        let lookup = tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_seconds),
            self.resolver.reverse_lookup(ip),
        )
        .await
        .map_err(|_| anyhow::anyhow!("PTR query timed out"))??;
        let mut names = Vec::new();
        for ptr in lookup.iter() {
            names.push(ptr.0.to_utf8().trim_end_matches('.').to_string());
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

pub fn record_type(value: &str) -> Result<RecordType> {
    match value.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "CNAME" => Ok(RecordType::CNAME),
        "MX" => Ok(RecordType::MX),
        "NS" => Ok(RecordType::NS),
        "TXT" => Ok(RecordType::TXT),
        "PTR" => Ok(RecordType::PTR),
        other => Err(ScopeError::Domain(format!("unsupported DNS record type: {other}")).into()),
    }
}
