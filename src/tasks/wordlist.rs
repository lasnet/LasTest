//! Named DNS wordlists and compatible parameters for dns.wordlist.
use crate::config::Config;
use crate::db::Db;
use crate::scope::normalize_domain;
use crate::tasks::parse_params;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;

pub const DEFAULT_WORDLIST: &str = include_str!("wordlists/default.txt");
pub const MAX_WORDLIST_BYTES: usize = 1024 * 1024;
pub const CONCURRENCY_OPTIONS: [usize; 3] = [4, 8, 16];
pub const DEFAULT_CONCURRENCY: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordlistParams {
    pub domain: String,
    #[serde(default = "default_wordlist")]
    pub wordlist: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_rate")]
    pub rate_limit: u32,
    #[serde(default = "default_resolver")]
    pub resolver: String,
    // Retained for API clients and queued jobs created before named lists.
    #[serde(default)]
    pub words: Vec<String>,
}

fn default_rate() -> u32 {
    50
}
fn default_resolver() -> String {
    "dedicated".into()
}

fn default_wordlist() -> String {
    "default".into()
}

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

pub fn available(config: &Config) -> bool {
    config.dnsx_path.as_ref().is_some_and(|path| path.is_file())
}

pub fn prepare(
    value: &serde_json::Value,
    config: &Config,
    db: &Db,
) -> Result<(WordlistParams, Vec<String>)> {
    let mut params: WordlistParams = parse_params(value)?;
    if value.get("rate_limit").is_none() {
        params.rate_limit = params.rate_limit.min(config.dns_wordlist_rate);
    }
    let domain = normalize_domain(&params.domain)?;
    // Existing queued jobs retain their original process count. New submissions
    // are restricted to CONCURRENCY_OPTIONS by validate_submission.
    if !CONCURRENCY_OPTIONS.contains(&params.concurrency)
        && !matches!(params.concurrency, 2 | 10 | 20 | 50 | 100)
    {
        anyhow::bail!("dns.wordlist concurrency must be 4, 8 or 16");
    }
    if !available(config) {
        anyhow::bail!("dnsx is unavailable: configure LASTEST_DNSX_PATH");
    }
    anyhow::ensure!(
        (1..=config.dns_wordlist_rate).contains(&params.rate_limit),
        "rate_limit must be between 1 and {} DNS requests per second",
        config.dns_wordlist_rate
    );
    anyhow::ensure!(
        matches!(params.resolver.as_str(), "dedicated" | "system"),
        "resolver must be dedicated or system"
    );
    let words = words(&params, db)?;
    // Validate the exact hostname, including legacy explicit prefixes.
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

pub(crate) fn candidate(word: &str, domain: &str) -> Result<String> {
    let word = word.trim();
    if word.is_empty() || word.len() > 100 || word.len() + domain.len() + 1 > 253 {
        anyhow::bail!("DNS wordlist prefix is too long or empty");
    }
    // Reject whitespace, options and punctuation before passing a file to dnsx.
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
