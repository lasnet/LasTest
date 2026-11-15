use crate::domain::Job;
use crate::scope::canonical_ip;
use crate::tasks::{dedup_strings, parse_params, registry, TaskContext, TaskOutcome};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::process::Stdio;
use tokio::io::AsyncReadExt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NmapParams {
    ips: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
}

pub async fn run(job: &Job, ctx: &TaskContext) -> Result<TaskOutcome> {
    if !registry::nmap_available(&ctx.config) {
        anyhow::bail!(
            "nmap.profile is unavailable: Nmap is not installed or nmap_path is not configured"
        );
    }
    let params: NmapParams = parse_params(&job.params)?;
    let ips = dedup_strings(&params.ips);
    if ips.is_empty() {
        anyhow::bail!("nmap.profile requires at least one explicit IP");
    }
    if ips.len() > 128 {
        anyhow::bail!("nmap.profile accepts at most 128 addresses");
    }
    let mut ports = params.ports;
    if ports.is_empty() {
        ports = vec![22, 80, 443, 445, 3389, 8080, 8443];
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > 1024 || ports.contains(&0) {
        anyhow::bail!("nmap.profile accepts 1-1024 non-zero TCP ports");
    }
    let mut validated = Vec::new();
    for raw in ips {
        let ip = canonical_ip(&raw)?;
        ctx.authorize_ip(ip)?;
        validated.push(ip.to_string());
    }
    let path = ctx
        .config
        .nmap_path
        .as_ref()
        .context("nmap path is missing")?;
    let port_list = ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut command = tokio::process::Command::new(path);
    command
        .args([
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-n",
            "--unprivileged",
            "-oX",
            "-",
            "-p",
            &port_list,
        ])
        .args(&validated)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot start Nmap at {}", path.display()))?;
    let stdout = child.stdout.take().context("nmap stdout is unavailable")?;
    let stderr = child.stderr.take().context("nmap stderr is unavailable")?;
    let max_output = ctx.config.nmap_max_output_bytes as usize;
    let mut output = Vec::new();
    let mut limited = stdout.take(max_output as u64 + 1);
    let read_stdout = async {
        limited.read_to_end(&mut output).await?;
        Ok::<_, std::io::Error>(())
    };
    let mut err_buf = Vec::new();
    let read_stderr = async {
        let mut limited = stderr.take(64 * 1024);
        limited.read_to_end(&mut err_buf).await?;
        Ok::<_, std::io::Error>(())
    };
    let timeout = std::time::Duration::from_secs(ctx.config.nmap_timeout_seconds);
    let result = tokio::time::timeout(timeout, async {
        let (out, err, status) = tokio::join!(read_stdout, read_stderr, child.wait());
        out?;
        err?;
        status
    })
    .await;
    let status = match result {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => anyhow::bail!("cannot read Nmap output: {err}"),
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!(
                "Nmap exceeded the configured {} second timeout",
                ctx.config.nmap_timeout_seconds
            );
        }
    };
    if output.len() > max_output {
        anyhow::bail!("Nmap output exceeded the configured limit");
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(&err_buf);
        anyhow::bail!("Nmap exited with {status}: {}", stderr.trim());
    }
    let xml = String::from_utf8_lossy(&output).to_string();
    let doc = roxmltree::Document::parse(&xml).context("Nmap produced invalid XML")?;
    let mut outcome = TaskOutcome::new();
    let mut ports_found = 0usize;
    for host in doc.descendants().filter(|node| node.has_tag_name("host")) {
        let address = host
            .children()
            .find(|node| node.has_tag_name("address"))
            .and_then(|node| node.attribute("addr"))
            .unwrap_or_default()
            .to_string();
        let ip = canonical_ip(&address)?;
        ctx.authorize_ip(ip)?;
        for port in host.descendants().filter(|node| node.has_tag_name("port")) {
            ctx.ensure_active()?;
            let port_number = port.attribute("portid").unwrap_or("0");
            let protocol = port.attribute("protocol").unwrap_or("tcp");
            let state = port
                .children()
                .find(|node| node.has_tag_name("state"))
                .and_then(|node| node.attribute("state"))
                .unwrap_or("unknown");
            let service = port.children().find(|node| node.has_tag_name("service"));
            let name = service
                .and_then(|node| node.attribute("name"))
                .unwrap_or("");
            let product = service
                .and_then(|node| node.attribute("product"))
                .unwrap_or("");
            let version = service
                .and_then(|node| node.attribute("version"))
                .unwrap_or("");
            let extra = service
                .and_then(|node| node.attribute("extrainfo"))
                .unwrap_or("");
            let cpes: Vec<String> = service
                .map(|node| {
                    node.children()
                        .filter(|child| child.has_tag_name("cpe"))
                        .filter_map(|child| child.text().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if state == "open" {
                ports_found += 1;
            }
            outcome.observe(
                "nmap.profile",
                "service",
                "ip",
                &ip.to_string(),
                json!({
                    "port": port_number.parse::<u16>().unwrap_or(0),
                    "protocol": protocol,
                    "state": state,
                    "service": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extra,
                    "cpe": cpes,
                    "profile": "tcp-service-connect-v1"
                }),
                "allowed",
            );
        }
        outcome.processed();
    }
    outcome.target(validated.len());
    outcome.result = json!({
        "format_version": "1",
        "open_ports": ports_found,
        "profile": "tcp-service-connect-v1",
        "nmap_args": ["-sT", "-sV", "--version-light", "-Pn", "-n", "--unprivileged", "-oX", "-"],
    });
    outcome.add_raw_artifact("nmap_xml", &format!("{}-nmap.xml", job.id), output);
    Ok(outcome.finalize())
}
