//! Shared authorization and cancellable A/AAAA verification for DNS discovery.
use crate::net::DnsClient;
use crate::tasks::{TaskContext, TaskOutcome};
use anyhow::Result;
use serde_json::json;
use std::net::IpAddr;

pub(crate) fn allows_dns(ctx: &TaskContext, domain: &str, host: &str) -> Result<bool> {
    let current = ctx.current_scope()?;
    Ok((host == domain || host.ends_with(&format!(".{domain}")))
        && ctx.scope.snapshot.allows_host(domain)
        && current.allows_host(domain)
        && !ctx.scope.snapshot.exclusion_matches_host(host)
        && !current.exclusion_matches_host(host))
}

/// DNS verification permission for an already discovered candidate.
///
/// A candidate is permitted when it is itself an allowed DNS name, or when it
/// is a child of an allowed ExactDomain/SubdomainTree through the existing DNS
/// discovery helper. This never grants HTTP/TCP permission.
/// Returns the allowed DNS domain that permits verification of `host`.
pub(crate) fn candidate_dns_domain(ctx: &TaskContext, host: &str) -> Result<Option<String>> {
    if ctx.allows_host_now(host) && !ctx.scope.snapshot.exclusion_matches_host(host) {
        return Ok(Some(host.to_string()));
    }
    for rule in &ctx.scope.snapshot.rules {
        if rule.exclusion
            || !matches!(
                rule.kind,
                crate::scope::RuleKind::ExactDomain | crate::scope::RuleKind::SubdomainTree
            )
        {
            continue;
        }
        if allows_dns(ctx, &rule.value, host)? {
            return Ok(Some(rule.value.clone()));
        }
    }
    Ok(None)
}

pub(crate) async fn resolve_ips(
    dns: &DnsClient,
    ctx: &TaskContext,
    domain: &str,
    host: &str,
) -> Result<Vec<IpAddr>> {
    ctx.ensure_active()?;
    anyhow::ensure!(
        allows_dns(ctx, domain, host)?,
        "DNS discovery host is excluded by scope"
    );
    let lookup = dns.resolve_ips(host);
    tokio::pin!(lookup);
    let ips = loop {
        tokio::select! {
            result = &mut lookup => break result?,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                ctx.ensure_active()?;
                anyhow::ensure!(allows_dns(ctx, domain, host)?, "DNS discovery scope changed");
            }
        }
    };
    ctx.ensure_active()?;
    anyhow::ensure!(
        allows_dns(ctx, domain, host)?,
        "DNS discovery scope changed"
    );
    anyhow::ensure!(!ips.is_empty(), "DNS verification returned no addresses");
    Ok(ips)
}

pub(crate) async fn lookup_records(
    dns: &DnsClient,
    ctx: &TaskContext,
    domain: &str,
    host: &str,
    record_type: hickory_resolver::proto::rr::RecordType,
) -> Result<Vec<crate::net::dns::DnsAnswer>> {
    ctx.ensure_active()?;
    anyhow::ensure!(
        allows_dns(ctx, domain, host)?,
        "DNS discovery scope changed"
    );
    let lookup = dns.lookup(host, record_type);
    tokio::pin!(lookup);
    loop {
        tokio::select! {
            result = &mut lookup => {
                ctx.ensure_active()?;
                anyhow::ensure!(allows_dns(ctx, domain, host)?, "DNS discovery scope changed");
                return result;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                ctx.ensure_active()?;
                anyhow::ensure!(allows_dns(ctx, domain, host)?, "DNS discovery scope changed");
            }
        }
    }
}

/// Publish a name only together with its verified address observations.
pub(crate) fn observe_host(
    outcome: &mut TaskOutcome,
    ctx: &TaskContext,
    source: &str,
    domain: &str,
    host: &str,
    ips: &[IpAddr],
) -> Result<()> {
    anyhow::ensure!(
        !ips.is_empty(),
        "cannot publish a DNS name without verified addresses"
    );
    ctx.ensure_active()?;
    anyhow::ensure!(
        allows_dns(ctx, domain, host)?,
        "DNS discovery scope changed"
    );
    let scope_status = if ctx.allows_host_now(host) {
        "allowed"
    } else {
        "denied"
    };
    outcome.observe(
        source,
        "host",
        "host",
        host,
        json!({"domain":domain,"addresses":ips,"dns_verified":true}),
        scope_status,
    );
    for ip in ips {
        let record_type = if ip.is_ipv4() { "A" } else { "AAAA" };
        outcome.observe(
            source,
            "dns",
            "host",
            host,
            json!({"record_type":record_type,"value":ip.to_string(),"dns_verified":true}),
            scope_status,
        );
        outcome.observe(
            source,
            "ip",
            "ip",
            &ip.to_string(),
            json!({"host":host,"record_type":record_type}),
            if ctx.allows_ip_now(*ip) {
                "allowed"
            } else {
                "observed"
            },
        );
    }
    Ok(())
}
