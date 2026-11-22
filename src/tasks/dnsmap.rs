//! dnsmap 0.36 adapter. Partition wordlists rather than assuming a thread flag.
use crate::config::Config;
use crate::db::Db;
use crate::scope::normalize_domain;
use crate::tasks::{discovery::allows_dns_in, parse_params, TaskContext};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinSet;

pub const DEFAULT_WORDLIST: &str = include_str!("wordlists/default.txt");
pub const MAX_WORDLIST_BYTES: usize = 1024 * 1024;
pub const CONCURRENCY_OPTIONS: [usize; 4] = [10, 20, 50, 100];
pub const DEFAULT_CONCURRENCY: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordlistParams {
    pub domain: String,
    #[serde(default = "default_wordlist")]
    pub wordlist: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    // Retained for API clients and queued jobs created before named lists.
    #[serde(default)]
    pub words: Vec<String>,
}

fn default_wordlist() -> String {
    "default".into()
}

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

pub fn available(config: &Config) -> bool {
    config
        .dnsmap_path
        .as_ref()
        .is_some_and(|path| path.is_file())
}

pub fn prepare(
    value: &serde_json::Value,
    config: &Config,
    db: &Db,
) -> Result<(WordlistParams, Vec<String>)> {
    let params: WordlistParams = parse_params(value)?;
    let domain = normalize_domain(&params.domain)?;
    // Existing queued jobs retain their original process count. New submissions
    // are restricted to CONCURRENCY_OPTIONS by validate_submission.
    if !CONCURRENCY_OPTIONS.contains(&params.concurrency)
        && !matches!(params.concurrency, 4 | 8 | 16)
    {
        anyhow::bail!("dns.wordlist concurrency must be 10, 20, 50 or 100");
    }
    if domain.len() > 197 {
        anyhow::bail!("dnsmap domain exceeds its 197-byte input capacity");
    }
    if domain.len() < 4
        || !domain.contains('.')
        || !(2..=13).contains(&domain.rsplit('.').next().unwrap_or_default().len())
    {
        anyhow::bail!("dnsmap requires a DNS name with a 2-13 byte top-level label");
    }
    if !available(config) {
        anyhow::bail!("dnsmap is unavailable: configure LASTEST_DNSMAP_PATH");
    }
    let words = words(&params, db)?;
    // Validate the exact combination since dnsmap also limits the full name.
    let validation_words = if params.words.is_empty() {
        &words
    } else {
        &params.words
    };
    for word in validation_words {
        candidate(word, &domain)?;
    }
    Ok((params, words))
}

fn candidate(word: &str, domain: &str) -> Result<String> {
    let word = word.trim();
    if word.is_empty() || word.len() > 100 || word.len() + domain.len() + 1 >= 200 {
        anyhow::bail!("DNS wordlist label exceeds dnsmap input capacity or is empty");
    }
    // Reject whitespace, options and punctuation before passing a file to dnsmap.
    let host = normalize_domain(&format!("{word}.{domain}"))?;
    if !word
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        anyhow::bail!("invalid DNS wordlist label: {word}");
    }
    Ok(host)
}

pub fn words(params: &WordlistParams, db: &Db) -> Result<Vec<String>> {
    let stored;
    let named = if params.wordlist == "default" {
        DEFAULT_WORDLIST
    } else {
        stored = db
            .dns_wordlist_contents(&params.wordlist)?
            .with_context(|| format!("unknown DNS wordlist: {}", params.wordlist))?;
        &stored
    };
    let words = if params.words.is_empty() {
        normalize_words(named.lines())
    } else {
        normalize_words(params.words.iter().map(String::as_str))
    };
    Ok(words)
}

pub fn parse_wordlist(contents: &str) -> Result<Vec<String>> {
    anyhow::ensure!(
        contents.len() <= MAX_WORDLIST_BYTES,
        "TXT file must be at most 1 MiB"
    );
    let contents = contents.trim_start_matches('\u{feff}');
    for (index, line) in contents.lines().enumerate() {
        if !line.trim().is_empty() {
            candidate(line, "upload.test").map_err(|_| {
                anyhow::anyhow!(
                    "line {} must contain one valid DNS label or prefix",
                    index + 1
                )
            })?;
        }
    }
    let words = normalize_words(contents.lines());
    anyhow::ensure!(!words.is_empty(), "TXT file must contain at least one word");
    Ok(words)
}

fn normalize_words<'a>(input: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    input
        .map(|word| word.trim().to_ascii_lowercase())
        .filter(|word| !word.is_empty() && seen.insert(word.clone()))
        .collect()
}

/// Only approved candidates reach dnsmap. Stop every shard on cancellation,
/// timeout, output overflow or a change to the current scope revision.
pub async fn discover(
    params: &WordlistParams,
    words: &[String],
    ctx: &TaskContext,
) -> Result<Vec<String>> {
    ctx.ensure_active()?;
    let domain = normalize_domain(&params.domain)?;
    ctx.authorize_host(&domain)?;
    let current = ctx.current_scope()?;
    let mut allowed = HashSet::new();
    let mut labels = Vec::new();
    let mut scope_checked_at = std::time::Instant::now();
    for (index, word) in words.iter().enumerate() {
        if index % 256 == 0 {
            ctx.ensure_active()?;
            // Large uploaded lists must not block heartbeats or other job slots.
            tokio::task::yield_now().await;
            if scope_checked_at.elapsed() >= std::time::Duration::from_millis(100) {
                anyhow::ensure!(
                    ctx.current_scope()?.rules == current.rules,
                    "dnsmap scope changed during preparation"
                );
                scope_checked_at = std::time::Instant::now();
            }
        }
        let host = candidate(word, &domain)?;
        if allows_dns_in(&ctx.scope.snapshot, &current, &domain, &host) {
            allowed.insert(host);
            labels.push(word.clone());
        }
    }
    ctx.ensure_active()?;
    anyhow::ensure!(
        ctx.current_scope()?.rules == current.rules,
        "dnsmap scope changed during preparation"
    );
    if labels.is_empty() {
        return Ok(Vec::new());
    }
    let path = ctx
        .config
        .dnsmap_path
        .as_ref()
        .context("dnsmap path is missing")?;
    let path = tokio::fs::canonicalize(path)
        .await
        .context("cannot locate dnsmap")?;
    // Attempt-specific directories cannot collide when a lease is retried.
    let home = ctx
        .config
        .tmp_dir()
        .join(format!("dnsmap-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&home).await?;
    let result = async {
        let count = params.concurrency.min(labels.len());
        let mut shards = vec![Vec::new(); count];
        for (i, label) in labels.into_iter().enumerate() {
            shards[i % count].push(label);
        }
        let mut runs = JoinSet::new();
        for (i, shard) in shards.into_iter().enumerate() {
            let file = format!("words-{i}.txt");
            tokio::fs::write(home.join(&file), shard.join("\n") + "\n").await?;
            let (path, home, domain) = (path.clone(), home.clone(), domain.clone());
            let limit = ctx.config.max_artifact_bytes;
            runs.spawn(async move { run_shard(&path, &home, &domain, &file, limit).await });
        }
        let deadline = tokio::time::sleep(std::time::Duration::from_secs(
            ctx.config.dnsmap_timeout_seconds,
        ));
        tokio::pin!(deadline);
        let mut found = HashSet::new();
        let mut bytes = 0u64;
        let result = loop {
            tokio::select! {
                result = runs.join_next() => {
                    let Some(result) = result else { break Ok(()); };
                    let output = match result {
                        Ok(Ok(output)) => output,
                        Ok(Err(err)) => break Err(err),
                        Err(err) => break Err(err.into()),
                    };
                    bytes += output.len() as u64;
                    if bytes > ctx.config.max_artifact_bytes {
                        break Err(anyhow::anyhow!("dnsmap output exceeded the artifact limit"));
                    }
                    // dnsmap prints each discovered name on a line of its own.
                    // Accept only names from the exact wordlist submitted to it.
                    for line in String::from_utf8_lossy(&output).lines() {
                        if let Ok(host) = normalize_domain(line) {
                            if allowed.contains(&host) { found.insert(host); }
                        }
                    }
                },
                _ = &mut deadline => break Err(anyhow::anyhow!("dnsmap exceeded its timeout")),
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    if let Err(err) = ctx.ensure_active() { break Err(err); }
                    match ctx.current_scope() {
                        Ok(scope) if scope.rules == current.rules => {},
                        _ => break Err(anyhow::anyhow!("dnsmap scope changed during execution")),
                    }
                }
            }
        };
        // Drain aborted tasks before deleting files; kill_on_drop stops children.
        runs.shutdown().await;
        result?;
        ctx.ensure_active()?;
        ctx.authorize_host(&domain)?;
        let mut found: Vec<_> = found.into_iter().collect();
        found.sort();
        Ok(found)
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&home).await;
    result
}

async fn read_bounded(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take(limit + 1).read_to_end(&mut output).await?;
    if output.len() as u64 > limit {
        anyhow::bail!("dnsmap output exceeded the artifact limit");
    }
    Ok(output)
}

async fn run_shard(
    path: &Path,
    home: &Path,
    domain: &str,
    file: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let mut child = tokio::process::Command::new(path)
        .current_dir(home)
        .args([domain, "-w", file, "-d", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start dnsmap")?;
    let stdout = child.stdout.take().context("missing dnsmap stdout")?;
    let stderr = child.stderr.take().context("missing dnsmap stderr")?;
    let (output, diagnostics, status) = tokio::try_join!(
        read_bounded(stdout, limit),
        read_bounded(stderr, 64 * 1024),
        async { Ok::<_, anyhow::Error>(child.wait().await?) }
    )?;
    if !status.success() {
        anyhow::bail!(
            "dnsmap exited with {status}: {} {}",
            String::from_utf8_lossy(&output),
            String::from_utf8_lossy(&diagnostics)
        );
    }
    Ok(output)
}
