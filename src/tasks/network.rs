use crate::domain::Job;
use crate::net::socks::connect_via_socks5;
use crate::net::tcp::{probe_tcp, ProbeState};
use crate::scope::canonical_ip;
use crate::tasks::{dedup_strings, parse_params, TaskContext, TaskOutcome};
use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpParams {
    ips: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    proxy_profile: Option<String>,
}

pub async fn run_tcp(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    let params: TcpParams = parse_params(&job.params)?;
    let ips = dedup_strings(&params.ips);
    if ips.is_empty() {
        anyhow::bail!("tcp.connect requires at least one explicit IP");
    }
    if ips.len() > 256 {
        anyhow::bail!("tcp.connect accepts at most 256 explicit addresses");
    }
    let mut ports = params.ports;
    if ports.is_empty() {
        ports = vec![80, 443, 22, 445, 3389, 8080, 8443];
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > 1024 {
        anyhow::bail!("tcp.connect accepts at most 1024 ports");
    }
    if ips.len().saturating_mul(ports.len()) > ctx.config.max_queue_targets {
        anyhow::bail!("TCP probe budget exceeds configured target limit");
    }
    let profile = match &params.proxy_profile {
        Some(name) => Some(
            ctx.config
                .socks5_profiles
                .iter()
                .find(|profile| &profile.name == name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown SOCKS5 profile: {name}"))?,
        ),
        None => None,
    };
    let mut outcome = TaskOutcome::new();
    outcome.target(ips.len() * ports.len());
    let mut confirmed = Vec::new();
    let mut candidates = Vec::new();
    let mut closed = Vec::new();
    for raw_ip in ips {
        ctx.ensure_active()?;
        let ip = match canonical_ip(&raw_ip) {
            Ok(ip) => ip,
            Err(err) => {
                outcome.error(format!("{raw_ip}: {err}"));
                outcome.skipped();
                continue;
            }
        };
        if let Err(err) = ctx.authorize_ip(ip) {
            outcome.error(err.to_string());
            outcome.skipped();
            continue;
        }
        for port in &ports {
            ctx.ensure_active()?;
            let probe = if let Some(proxy) = &profile {
                run_proxy_probe(proxy, ip, *port, ctx.config.http_timeout_seconds).await
            } else {
                probe_tcp(
                    ip,
                    *port,
                    Duration::from_secs(ctx.config.http_timeout_seconds),
                    &ctx.config.network_policy(),
                )
                .await
            };
            match probe {
                Ok(probe) => {
                    let mut data = json!({
                        "port": probe.port,
                        "state": probe.state.as_str(),
                        "duration_ms": probe.duration_ms,
                        "via_proxy": profile.as_ref().map(|value| value.name.clone()),
                    });
                    if let Some(error) = &probe.error {
                        data["error"] = json!(error);
                    }
                    outcome.observe(
                        "tcp.connect",
                        "port",
                        "ip",
                        &ip.to_string(),
                        data,
                        "allowed",
                    );
                    match probe.state {
                        ProbeState::Open => {
                            confirmed.push(json!({
                                "ip": ip.to_string(), "port": port,
                                "proxy": profile.as_ref().map(|value| value.name.clone())
                            }));
                        }
                        ProbeState::Timeout | ProbeState::Error => {
                            candidates.push(json!({
                                "ip": ip.to_string(), "port": port,
                                "state": probe.state.as_str(),
                                "reason": probe.error
                            }));
                            outcome.error(format!(
                                "{}:{} probe ended with {}",
                                ip,
                                port,
                                probe.state.as_str()
                            ));
                        }
                        ProbeState::Closed => {
                            closed.push(json!({"ip": ip.to_string(), "port": port}))
                        }
                    }
                    outcome.processed();
                }
                Err(err) => {
                    outcome.error(format!("{ip}:{port}: {err}"));
                    outcome.skipped();
                }
            }
        }
    }
    outcome.result = json!({
        "format_version": "1",
        "confirmed_ports": confirmed,
        "candidate_ports": candidates,
        "closed_ports": closed,
        "proxy_profile": profile.as_ref().map(|value| value.name.clone()),
        "socks5_confirmation": if profile.is_some() {
            json!("SOCKS5 confirmation uses one fresh authenticated TCP connect per port; re-run the task to confirm an unknown or timeout result")
        } else {
            json!(null)
        },
    });
    let result = outcome.result.clone();
    outcome.add_artifact("tcp", &format!("{}-tcp.json", job.id), &result)?;
    Ok(outcome.finalize())
}

async fn run_proxy_probe(
    profile: &crate::config::Socks5Profile,
    ip: IpAddr,
    port: u16,
    timeout_seconds: u64,
) -> Result<crate::net::TcpProbe> {
    let started = std::time::Instant::now();
    let result = connect_via_socks5(profile, ip, port, Duration::from_secs(timeout_seconds)).await;
    let duration_ms = started.elapsed().as_millis();
    match result {
        Ok(_) => Ok(crate::net::TcpProbe {
            ip,
            port,
            state: ProbeState::Open,
            duration_ms,
            error: None,
        }),
        Err(err) => {
            let state = if err.to_string().to_ascii_lowercase().contains("timed out") {
                ProbeState::Timeout
            } else {
                ProbeState::Error
            };
            Ok(crate::net::TcpProbe {
                ip,
                port,
                state,
                duration_ms,
                error: Some(err.to_string()),
            })
        }
    }
}
