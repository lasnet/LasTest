//! Narrow passive-provider adapters. They parse only documented name fields;
//! arbitrary banners, links, issuer names and error text never become
//! candidates.
pub mod censys;
pub mod shodan;

use crate::scope::{canonical_ip, normalize_domain};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// A provider response after bounded normalization.
#[derive(Debug, Clone)]
pub struct ProviderParse {
    pub names: Vec<String>,
    /// Normalized passive data (ports, CPE, services, certificates, ASN).
    pub passive: Value,
    /// Looked valid but some fields were ignored or malformed.
    pub partial: bool,
    pub notes: Vec<String>,
}

/// Normalize a candidate name. Wildcards, IP literals, service labels and
/// overlong/invalid names are rejected. A trailing dot and IDNA are handled by
/// the shared domain normalizer.
pub fn normalize_candidate(raw: &str) -> Option<String> {
    let value = raw.trim().trim_end_matches('.');
    if value.is_empty() || value.starts_with("*.") {
        return None;
    }
    if canonical_ip(value).is_ok() {
        return None;
    }
    normalize_domain(value).ok()
}

/// Deduplicate and bound candidate names while preserving first-seen order.
pub fn bounded_names<I: IntoIterator<Item = String>>(names: I, limit: usize) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for name in names {
        if out.len() >= limit {
            break;
        }
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

pub fn parse(provider: &str, value: &Value, limit: usize) -> ProviderParse {
    match provider {
        "shodan_internetdb" => shodan::parse(value, limit),
        "censys" => censys::parse(value, limit),
        other => ProviderParse {
            names: Vec::new(),
            passive: json!({}),
            partial: false,
            notes: vec![format!("unsupported provider {other}")],
        },
    }
}

/// Extracts a bounded list of string values from a JSON field.
pub(crate) fn string_array(value: Option<&Value>) -> (Vec<String>, bool) {
    match value {
        None => (Vec::new(), false),
        Some(Value::Array(items)) => {
            let mut strings = Vec::new();
            let mut malformed = false;
            for item in items {
                match item.as_str() {
                    Some(text) => strings.push(text.to_string()),
                    None => malformed = true,
                }
            }
            (strings, malformed)
        }
        Some(Value::String(text)) => (vec![text.clone()], false),
        Some(_) => (Vec::new(), true),
    }
}

pub(crate) fn passive_ports(value: Option<&Value>) -> (Vec<u16>, bool) {
    match value {
        None => (Vec::new(), false),
        Some(Value::Array(items)) => {
            let mut ports = Vec::new();
            let mut malformed = false;
            for item in items {
                match item.as_u64().and_then(|port| u16::try_from(port).ok()) {
                    Some(port) if port > 0 => ports.push(port),
                    _ => malformed = true,
                }
            }
            ports.sort_unstable();
            ports.dedup();
            (ports, malformed)
        }
        Some(_) => (Vec::new(), true),
    }
}

pub(crate) fn passive_strings(value: Option<&Value>, limit: usize) -> (Vec<String>, bool) {
    let (mut items, malformed) = string_array(value);
    items.sort();
    items.dedup();
    items.truncate(limit);
    (items, malformed)
}
