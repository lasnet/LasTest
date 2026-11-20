//! Optional passive subfinder process with bounded output and native DNS resolution.
use crate::domain::Job;
use crate::scope::{normalize_domain, RuleKind};
use crate::tasks::{dedup_strings, discovery, parse_params, TaskContext, TaskOutcome};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::process::Stdio;
use tokio::io::AsyncReadExt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubfinderParams {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default = "resolve_default")]
    // Legacy API field: accepted, but DNS verification is mandatory.
    pub resolve: bool,
}

fn resolve_default() -> bool {
    true
}

pub fn available(config: &crate::config::Config) -> bool {
    config
        .subfinder_path
        .as_ref()
        .is_some_and(|path| path.is_file())
}

pub fn validate(params: &serde_json::Value, config: &crate::config::Config) -> Result<()> {
    if !available(config) {
        anyhow::bail!("subfinder is unavailable: configure LASTEST_SUBFINDER_PATH");
    }
    let params: SubfinderParams = parse_params(params)?;
    if params.sources.len() > 32 {
        anyhow::bail!("subfinder accepts at most 32 sources");
    }
    for domain in &params.domains {
        normalize_domain(domain)?;
    }
    for source in &params.sources {
        if source.is_empty()
            || !source
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            anyhow::bail!("invalid subfinder source name");
        }
    }
    Ok(())
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    validate(&job.params, &ctx.config)?;
    let params: SubfinderParams = parse_params(&job.params)?;
    let domains = if params.domains.is_empty() {
        ctx.scope
            .snapshot
            .rules
            .iter()
            .filter(|rule| {
                !rule.exclusion
                    && matches!(rule.kind, RuleKind::ExactDomain | RuleKind::SubdomainTree)
            })
            .map(|rule| rule.value.clone())
            .collect()
    } else {
        params.domains
    };
    let domains = dedup_strings(&domains);
    if domains.is_empty() {
        anyhow::bail!("subfinder requires at least one allowed DNS name");
    }
    let path = ctx
        .config
        .subfinder_path
        .as_ref()
        .context("subfinder path is missing")?;
    let home = ctx.config.tmp_dir().join(format!("subfinder-{}", job.id));
    tokio::fs::create_dir_all(&home).await?;
    let result = run_domains(path, &home, domains, &params.sources, ctx).await;
    let _ = tokio::fs::remove_dir_all(&home).await;
    result
}

async fn run_domains(
    path: &std::path::Path,
    home: &std::path::Path,
    domains: Vec<String>,
    sources: &[String],
    ctx: &TaskContext,
) -> Result<TaskOutcome> {
    let mut outcome = TaskOutcome::new();
    outcome.target(domains.len());
    let mut seen = HashSet::new();
    let mut hosts = Vec::new();
    let mut rejected = Vec::new();
    let dns = ctx.dns()?;
    for raw in domains {
        ctx.ensure_active()?;
        let domain = normalize_domain(&raw)?;
        ctx.authorize_host(&domain)?;
        let timeout = ctx.config.http_timeout_seconds.to_string();
        let mut command = tokio::process::Command::new(path);
        command
            .args([
                "-d",
                &domain,
                "-silent",
                "-duc",
                "-nc",
                "-timeout",
                &timeout,
                "-max-time",
                "2",
                "-rl",
                "5",
            ])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home)
            .env("SUBFINDER_CONFIG", home.join("config.yaml"))
            .env(
                "SUBFINDER_PROVIDER_CONFIG",
                home.join("provider-config.yaml"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if !sources.is_empty() {
            command.args(["-s", &sources.join(",")]);
        }
        let mut child = command.spawn().context("cannot start subfinder")?;
        let mut stdout = child
            .stdout
            .take()
            .context("missing subfinder stdout")?
            .take(ctx.config.max_artifact_bytes + 1);
        let mut stderr = child
            .stderr
            .take()
            .context("missing subfinder stderr")?
            .take(64 * 1024);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let status = {
            let run = async {
                let (out, err, status) = tokio::join!(
                    stdout.read_to_end(&mut output),
                    stderr.read_to_end(&mut diagnostics),
                    child.wait()
                );
                out?;
                err?;
                Ok::<_, anyhow::Error>(status?)
            };
            tokio::pin!(run);
            let deadline = tokio::time::sleep(std::time::Duration::from_secs(
                ctx.config.subfinder_timeout_seconds,
            ));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    result = &mut run => break result?,
                    _ = &mut deadline => anyhow::bail!("subfinder exceeded its timeout"),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                        ctx.ensure_active()?;
                        if !ctx.allows_host_now(&domain) {
                            anyhow::bail!("subfinder domain is no longer allowed by scope");
                        }
                    }
                }
            }
        };
        if output.len() as u64 > ctx.config.max_artifact_bytes {
            anyhow::bail!("subfinder output exceeded the artifact limit");
        }
        if !status.success() {
            outcome.error(format!(
                "subfinder {domain} exited with {status}: {}",
                String::from_utf8_lossy(&diagnostics)
            ));
            continue;
        }
        for line in String::from_utf8_lossy(&output).lines() {
            ctx.ensure_active()?;
            let Ok(host) = normalize_domain(line) else {
                continue;
            };
            if host != domain && !host.ends_with(&format!(".{domain}")) {
                continue;
            }
            if !seen.insert(host.clone()) {
                continue;
            }
            if seen.len() > ctx.config.max_queue_targets {
                outcome.error("subfinder results reached the target limit");
                break;
            }
            if !discovery::allows_dns(ctx, &domain, &host)? {
                outcome.skipped();
                rejected.push(json!({"host":host,"reason":"scope"}));
                continue;
            }
            let ips = match discovery::resolve_ips(&dns, ctx, &domain, &host).await {
                Ok(ips) => ips,
                Err(error) => {
                    ctx.ensure_active()?;
                    outcome.skipped();
                    if !discovery::allows_dns(ctx, &domain, &host)? {
                        rejected.push(json!({"host":host,"reason":"scope"}));
                    } else if crate::net::dns::is_no_records(&error) {
                        rejected.push(json!({"host":host,"reason":"no_addresses"}));
                    } else {
                        let message = crate::net::dns::error_message(&error);
                        outcome.error(format!("DNS {host}: {message}"));
                        rejected.push(json!({"host":host,"reason":"dns_error","error":message}));
                    }
                    continue;
                }
            };
            discovery::observe_host(&mut outcome, ctx, "subfinder", &domain, &host, &ips)?;
            let allowed = ctx.allows_host_now(&host);
            let scope_status = if allowed { "allowed" } else { "denied" };
            hosts.push(
                json!({"host":host,"ips":ips,"scope_status":scope_status,"dns_verified":true}),
            );
        }
        outcome.processed();
    }
    outcome.result = json!({"format_version":"1","hosts":hosts,"resolve":true,"rejected":rejected});
    let result = outcome.result.clone();
    outcome.add_artifact("subdomains", "subfinder.json", &result)?;
    Ok(outcome.finalize())
}
