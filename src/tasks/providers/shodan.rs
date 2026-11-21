//! Shodan InternetDB adapter. Only the documented `hostnames` array yields
//! candidates. Ports, CPEs, vulns and tags are stored as passive data.
use super::ProviderParse;
use super::{bounded_names, normalize_candidate, passive_ports, passive_strings};
use serde_json::{json, Value};

pub fn parse(value: &Value, limit: usize) -> ProviderParse {
    let mut notes = Vec::new();
    let mut partial = false;
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return ProviderParse {
                names: Vec::new(),
                passive: json!({}),
                partial: true,
                notes: vec!["Shodan InternetDB response was not a JSON object".to_string()],
            }
        }
    };
    if !object.get("hostnames").is_some_and(Value::is_array) {
        partial = true;
        notes.push("Shodan hostnames must be an array".to_string());
    }
    let (hostnames, malformed) = super::string_array(object.get("hostnames"));
    if malformed {
        partial = true;
        notes.push("ignored non-string hostnames".to_string());
    }
    if hostnames.len() > limit {
        partial = true;
        notes.push("candidate limit reached; results are incomplete".into());
    }
    let names = bounded_names(
        hostnames.into_iter().filter_map(|raw| {
            let normalized = normalize_candidate(&raw);
            if normalized.is_none() {
                notes.push(format!("ignored non-name candidate: {raw}"));
            }
            normalized
        }),
        limit,
    );
    let (ports, bad_ports) = passive_ports(object.get("ports"));
    if bad_ports {
        partial = true;
        notes.push("ignored malformed ports".to_string());
    }
    let (cpes, bad_cpes) = passive_strings(object.get("cpes"), limit);
    if bad_cpes {
        partial = true;
    }
    let (tags, bad_tags) = passive_strings(object.get("tags"), limit);
    if bad_tags {
        partial = true;
    }
    let vulns = match object.get("vulns") {
        Some(Value::Array(items)) => {
            let mut ids: Vec<String> = items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            ids.sort();
            ids.dedup();
            ids.truncate(limit);
            json!(ids)
        }
        Some(Value::Object(items)) => {
            let mut ids: Vec<String> = items.keys().cloned().collect();
            ids.sort();
            ids.truncate(limit);
            json!(ids)
        }
        Some(_) => {
            partial = true;
            json!([])
        }
        None => json!([]),
    };
    ProviderParse {
        names,
        passive: json!({
            "provider": "shodan_internetdb",
            "classification": "passive_reported",
            "ports": ports,
            "cpes": cpes,
            "tags": tags,
            "vulns": vulns,
        }),
        partial,
        notes,
    }
}
