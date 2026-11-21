//! Scope normalization and the single authorization layer used by explicit
//! task parameters, discovered artifacts and network clients.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    ExactDomain,
    SubdomainTree,
    Ip,
    Cidr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub kind: RuleKind,
    pub value: String,
    #[serde(default)]
    pub exclusion: bool,
    #[serde(default = "default_true")]
    pub verified: bool,
}

fn default_true() -> bool {
    true
}

impl ScopeRule {
    pub fn new(kind: RuleKind, value: &str, exclusion: bool) -> Result<Self, ScopeError> {
        if kind == RuleKind::ExactDomain && value.trim().starts_with("*.") {
            return Err(ScopeError::Domain(
                "exact_domain cannot contain a wildcard; use subdomain_tree".into(),
            ));
        }
        let value = match kind {
            RuleKind::ExactDomain => normalize_domain(value)?,
            RuleKind::SubdomainTree => normalize_domain(value)?,
            RuleKind::Ip => canonical_ip(value)?.to_string(),
            RuleKind::Cidr => canonical_cidr(value)?.to_string(),
        };
        Ok(Self {
            kind,
            value,
            exclusion,
            verified: true,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("invalid domain: {0}")]
    Domain(String),
    #[error("invalid IP address: {0}")]
    Ip(String),
    #[error("invalid CIDR: {0}")]
    Cidr(String),
    #[error("unsupported scope rule kind")]
    Kind,
    #[error("URL is not allowed by scope: {0}")]
    Url(String),
    #[error("destination is blocked by network policy: {0}")]
    Blocked(String),
}

/// Normalize a DNS name with IDNA, validate label boundaries and lowercase it.
pub fn normalize_domain(input: &str) -> Result<String, ScopeError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(ScopeError::Domain("empty domain".into()));
    }
    if raw.contains("://") || raw.contains('/') || raw.contains('?') || raw.contains('@') {
        return Err(ScopeError::Domain(format!(
            "ambiguous value is not a bare DNS name: {raw}"
        )));
    }
    let trimmed = raw.strip_prefix("*.").unwrap_or(raw);
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(ScopeError::Domain("empty domain".into()));
    }
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|_| ScopeError::Domain(format!("IDNA conversion failed: {raw}")))?;
    let domain = ascii.to_ascii_lowercase();
    if domain != "localhost"
        && (!domain.contains('.')
            || domain
                .rsplit('.')
                .next()
                .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit())))
    {
        return Err(ScopeError::Domain(
            "use a complete DNS name such as example.com".into(),
        ));
    }
    if domain.len() > 253 {
        return Err(ScopeError::Domain("domain exceeds 253 octets".into()));
    }
    if domain.parse::<IpAddr>().is_ok() {
        return Err(ScopeError::Domain(
            "IP addresses must use the ip/cidr rule kind".into(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(ScopeError::Domain("empty DNS label".into()));
        }
        if label.len() > 63 {
            return Err(ScopeError::Domain("DNS label exceeds 63 octets".into()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ScopeError::Domain(
                "DNS label starts or ends with '-'".into(),
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ScopeError::Domain(format!(
                "invalid character in DNS label: {label}"
            )));
        }
    }
    Ok(domain)
}

/// Canonicalize an address. IPv4-mapped IPv6 is represented as IPv4.
pub fn canonical_ip(input: &str) -> Result<IpAddr, ScopeError> {
    let value = input.trim().trim_matches(['[', ']']);
    let ip = value
        .parse::<IpAddr>()
        .map_err(|_| ScopeError::Ip(value.to_string()))?;
    Ok(match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        other => other,
    })
}

pub fn canonical_cidr(input: &str) -> Result<IpNet, ScopeError> {
    let value = input.trim();
    let net = value
        .parse::<IpNet>()
        .map_err(|_| ScopeError::Cidr(value.to_string()))?;
    let net = match net {
        IpNet::V6(v6) => {
            let prefix = v6.prefix_len();
            let addr = v6.addr();
            if let Some(v4) = addr.to_ipv4_mapped() {
                if prefix >= 96 {
                    return Ok(IpNet::V4(
                        ipnet::Ipv4Net::new(v4, prefix - 96)
                            .map_err(|_| ScopeError::Cidr(value.to_string()))?,
                    ));
                }
            }
            IpNet::V6(v6)
        }
        other => other,
    };
    Ok(net.trunc())
}

/// A validated, immutable view of one scope revision.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
}

impl Scope {
    pub fn new(rules: Vec<ScopeRule>) -> Result<Self, ScopeError> {
        let mut scope = Self { rules };
        scope.dedup_and_validate()?;
        Ok(scope)
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, ScopeError> {
        let rules: Vec<ScopeRule> =
            serde_json::from_value(value.clone()).map_err(|_| ScopeError::Kind)?;
        Self::new(rules)
    }

    fn dedup_and_validate(&mut self) -> Result<(), ScopeError> {
        let mut out: Vec<ScopeRule> = Vec::new();
        for rule in &self.rules {
            let normalized = ScopeRule {
                kind: rule.kind,
                value: match rule.kind {
                    RuleKind::ExactDomain | RuleKind::SubdomainTree => {
                        normalize_domain(&rule.value)?
                    }
                    RuleKind::Ip => canonical_ip(&rule.value)?.to_string(),
                    RuleKind::Cidr => canonical_cidr(&rule.value)?.to_string(),
                },
                exclusion: rule.exclusion,
                verified: rule.verified,
            };
            if !out.iter().any(|existing| {
                existing.kind == normalized.kind
                    && existing.value == normalized.value
                    && existing.exclusion == normalized.exclusion
            }) {
                out.push(normalized);
            }
        }
        self.rules = out;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn allows_host(&self, host: &str) -> bool {
        let Ok(host) = normalize_domain(host) else {
            return false;
        };
        if self
            .rules
            .iter()
            .any(|rule| rule.exclusion && host_matches(rule, &host))
        {
            return false;
        }
        self.rules
            .iter()
            .any(|rule| !rule.exclusion && host_matches(rule, &host))
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(&ip.to_string()).unwrap_or(ip);
        if self
            .rules
            .iter()
            .any(|rule| rule.exclusion && ip_matches(rule, ip))
        {
            return false;
        }
        self.rules
            .iter()
            .any(|rule| !rule.exclusion && ip_matches(rule, ip))
    }

    pub fn exclusion_matches_ip(&self, ip: IpAddr) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.exclusion && ip_matches(rule, ip))
    }

    /// Resolution of a permitted DNS name is not itself permission to connect
    /// to arbitrary ports on the resulting address. Hostname HTTP authorization
    /// is separate from explicit IP/CIDR authorization.
    pub fn allows_hostname_target(&self, host: &str) -> bool {
        self.allows_host(host)
    }

    pub fn exclusion_matches_host(&self, host: &str) -> bool {
        let Ok(host) = normalize_domain(host) else {
            return false;
        };
        self.rules
            .iter()
            .any(|rule| rule.exclusion && host_matches(rule, &host))
    }
}

/// The job snapshot and the current scope must both allow an operation. A
/// scope narrowing therefore applies to the next network request of an active
/// job; widening only affects newly submitted jobs.
#[derive(Debug, Clone)]
pub struct EffectiveScope {
    pub snapshot: Scope,
    pub current: Scope,
}

impl EffectiveScope {
    pub fn new(snapshot: Scope, current: Scope) -> Self {
        Self { snapshot, current }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.snapshot.allows_host(host) && self.current.allows_host(host)
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.snapshot.allows_ip(ip) && self.current.allows_ip(ip)
    }

    /// Best-effort intersection used by clients that take a single `Scope`.
    /// IP checks still use `allows_ip` on both scopes before TCP connections.
    pub fn combined_scope(&self) -> Scope {
        let mut rules = Vec::new();
        for rule in &self.snapshot.rules {
            if rule.exclusion {
                rules.push(rule.clone());
                continue;
            }
            let keep = match rule.kind {
                RuleKind::ExactDomain | RuleKind::SubdomainTree => {
                    self.current.allows_host(&rule.value)
                }
                RuleKind::Ip => rule
                    .value
                    .parse::<IpAddr>()
                    .map(|ip| self.current.allows_ip(ip))
                    .unwrap_or(false),
                RuleKind::Cidr => rule
                    .value
                    .parse::<IpNet>()
                    .map(|net| {
                        self.current.allows_ip(net.network())
                            && self.current.allows_ip(net.broadcast())
                    })
                    .unwrap_or(false),
            };
            if keep {
                rules.push(rule.clone());
            }
        }
        for rule in &self.current.rules {
            if rule.exclusion && !rules.contains(rule) {
                rules.push(rule.clone());
            }
        }
        Scope { rules }
    }
}

fn host_matches(rule: &ScopeRule, host: &str) -> bool {
    match rule.kind {
        RuleKind::ExactDomain => rule.value == host,
        RuleKind::SubdomainTree => {
            host == rule.value || host.ends_with(&format!(".{}", rule.value))
        }
        _ => false,
    }
}

fn ip_matches(rule: &ScopeRule, ip: IpAddr) -> bool {
    match rule.kind {
        RuleKind::Ip => rule
            .value
            .parse::<IpAddr>()
            .map(|v| v == ip)
            .unwrap_or(false),
        RuleKind::Cidr => rule
            .value
            .parse::<IpNet>()
            .map(|net| net.contains(&ip))
            .unwrap_or(false),
        _ => false,
    }
}

/// Explicitly configured internal ranges and absolute metadata exclusions.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    pub internal_ranges: Vec<IpNet>,
}

impl NetworkPolicy {
    pub fn new(internal_ranges: Vec<IpNet>) -> Self {
        Self { internal_ranges }
    }

    pub fn permits(&self, ip: IpAddr) -> Result<(), ScopeError> {
        let ip = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other => other,
        };
        if is_metadata_or_infrastructure(ip) {
            return Err(ScopeError::Blocked(format!(
                "metadata/infrastructure address {ip}"
            )));
        }
        if matches!(ip, IpAddr::V4(v4) if v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified())
            || matches!(ip, IpAddr::V6(v6) if v6.is_multicast() || v6.is_unspecified())
        {
            return Err(ScopeError::Blocked(format!("non-unicast address {ip}")));
        }
        if is_internal(ip) && !self.internal_ranges.iter().any(|net| net.contains(&ip)) {
            return Err(ScopeError::Blocked(format!(
                "internal address {ip} is not in an administrator-approved range"
            )));
        }
        Ok(())
    }
}

fn is_metadata_or_infrastructure(ip: IpAddr) -> bool {
    const METADATA_V4: [Ipv4Addr; 3] = [
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(100, 100, 100, 200),
        Ipv4Addr::new(192, 0, 0, 192),
    ];
    const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);
    match ip {
        IpAddr::V4(v4) => METADATA_V4.contains(&v4) || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6 == METADATA_V6 || (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_unspecified()
        }
    }
}

fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Parse a URL, requiring an unambiguous absolute http(s) URL.
pub fn parse_target_url(input: &str) -> Result<Url, ScopeError> {
    let url = Url::parse(input.trim()).map_err(|_| ScopeError::Url(input.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScopeError::Url(format!(
            "only http/https URLs are supported: {input}"
        )));
    }
    if url.host_str().is_none() || url.username() != "" || url.password().is_some() {
        return Err(ScopeError::Url(format!("ambiguous URL: {input}")));
    }
    Ok(url)
}

/// Deduplication key for a URL. The raw URL is stored separately.
pub fn canonical_url_key(input: &str) -> Result<String, ScopeError> {
    let mut url = parse_target_url(input)?;
    url.set_fragment(None);
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(items: &[(RuleKind, &str, bool)]) -> Scope {
        Scope::new(
            items
                .iter()
                .map(|(kind, value, exclusion)| ScopeRule::new(*kind, value, *exclusion).unwrap())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn exact_and_subdomain_boundaries() {
        let scope = rules(&[
            (RuleKind::ExactDomain, "www.example.com", false),
            (RuleKind::SubdomainTree, "example.org", false),
        ]);
        assert!(scope.allows_host("WWW.Example.com."));
        assert!(!scope.allows_host("api.example.com"));
        assert!(scope.allows_host("example.org"));
        assert!(scope.allows_host("a.b.example.org"));
        assert!(!scope.allows_host("badexample.org"));
    }

    #[test]
    fn exclusions_win() {
        let scope = rules(&[
            (RuleKind::SubdomainTree, "example.com", false),
            (RuleKind::SubdomainTree, "admin.example.com", true),
        ]);
        assert!(scope.allows_host("www.example.com"));
        assert!(!scope.allows_host("admin.example.com"));
        assert!(!scope.allows_host("x.admin.example.com"));
    }

    #[test]
    fn idna_and_label_limits() {
        assert_eq!(
            normalize_domain("BÜCHER.example").unwrap(),
            "xn--bcher-kva.example"
        );
        let too_long = "a".repeat(64);
        assert!(normalize_domain(&format!("{too_long}.example")).is_err());
        assert!(normalize_domain("example..com").is_err());
        assert!(normalize_domain("https://example.com/x").is_err());
        for invalid in ["543535", "мвамум", "example.123", "bad name.example"] {
            assert!(normalize_domain(invalid).is_err(), "{invalid}");
            assert!(Scope::from_json(&serde_json::json!([
                {"kind": "exact_domain", "value": invalid}
            ]))
            .is_err());
        }
        assert_eq!(normalize_domain("localhost").unwrap(), "localhost");
        assert_eq!(
            normalize_domain("пример.рф").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );
    }

    #[test]
    fn cidr_and_mapped_ipv6() {
        assert_eq!(
            canonical_ip("::ffff:192.0.2.5").unwrap(),
            "192.0.2.5".parse::<IpAddr>().unwrap()
        );
        let scope = rules(&[
            (RuleKind::Cidr, "192.0.2.7/24", false),
            (RuleKind::Ip, "2001:db8::1", false),
        ]);
        assert!(scope.allows_ip("192.0.2.99".parse().unwrap()));
        assert!(!scope.allows_ip("192.0.3.1".parse().unwrap()));
        assert!(scope.allows_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn metadata_is_always_blocked() {
        let policy = NetworkPolicy::new(vec!["169.254.0.0/16".parse().unwrap()]);
        assert!(policy.permits("169.254.169.254".parse().unwrap()).is_err());
        assert!(policy.permits("127.0.0.1".parse().unwrap()).is_err());
        let local = NetworkPolicy::new(vec!["127.0.0.0/8".parse().unwrap()]);
        assert!(local.permits("127.0.0.1".parse().unwrap()).is_ok());
    }
}
