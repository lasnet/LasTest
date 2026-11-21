//! Censys Platform v3 and legacy v2 adapter.
//!
//! Candidate names come only from documented DNS name fields and from
//! certificate leaf subject CN / SAN fields. Issuer names, banners, links and
//! error strings are deliberately ignored.
use super::ProviderParse;
use super::{bounded_names, normalize_candidate, passive_ports, passive_strings};
use serde_json::{json, Value};

fn resource(value: &Value) -> Option<(&Value, &'static str)> {
    if let Some(resource) = value.pointer("/result/resource") {
        if resource.is_object() {
            return Some((resource, "platform_v3"));
        }
    }
    if let Some(result) = value.get("result") {
        if result.is_object() {
            return Some((result, "legacy_v2"));
        }
    }
    if let Some(resource) = value.get("resource") {
        if resource.is_object() {
            return Some((resource, "platform_v3"));
        }
    }
    None
}

fn leaf_certificates(service: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    let Some(tls) = service.get("tls") else {
        return out;
    };
    for key in ["certificates", "certificate", "cert"] {
        match tls.get(key) {
            Some(Value::Array(items)) => out.extend(items.iter()),
            Some(value @ Value::Object(_)) => out.push(value.get("leaf_data").unwrap_or(value)),
            _ => {}
        }
    }
    out
}

fn leaf_name_values(leaf: &Value) -> Vec<&Value> {
    let leaf = leaf.get("leaf_data").unwrap_or(leaf);
    let mut out = Vec::new();
    if let Some(value) = leaf.pointer("/subject/common_name") {
        out.push(value);
    }
    if let Some(value) = leaf.get("common_name") {
        out.push(value);
    }
    for key in [
        "names",
        "dns_names",
        "subject_alt_names",
        "subject_alternative_names",
    ] {
        if let Some(value) = leaf.get(key) {
            out.push(value);
        }
    }
    out
}

pub fn parse(value: &Value, limit: usize) -> ProviderParse {
    let Some((resource, version)) = resource(value) else {
        return ProviderParse {
            names: Vec::new(),
            passive: json!({}),
            partial: true,
            notes: vec!["Censys response did not contain a host resource".to_string()],
        };
    };
    let mut notes = Vec::new();
    let mut partial = false;
    let mut candidates = Vec::new();

    for key in ["dns", "names"] {
        let field = if key == "dns" {
            resource.get("dns").and_then(|dns| dns.get("names"))
        } else {
            resource.get("names")
        };
        let (items, malformed) = super::string_array(field);
        if malformed {
            partial = true;
            notes.push(format!("ignored malformed {key} values"));
        }
        candidates.extend(items);
    }
    for key in ["hostnames", "name"] {
        let (items, malformed) = super::string_array(resource.get(key));
        if malformed {
            partial = true;
            notes.push(format!("ignored malformed {key} values"));
        }
        candidates.extend(items);
    }
    let mut tls_names = Vec::new();
    let mut certificates = Vec::new();
    let mut services = Vec::new();
    let mut passive_ports_found = Vec::new();
    let mut cpes = Vec::new();
    let mut vulns = Vec::new();
    if let Some(Value::Array(items)) = resource.get("services") {
        for service in items.iter().take(limit) {
            if let Some(port) = service
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
            {
                passive_ports_found.push(port);
            }
            for leaf in leaf_certificates(service) {
                let leaf_data = leaf.get("leaf_data").unwrap_or(leaf);
                certificates.push(json!({
                    "subject": leaf_data.pointer("/subject/common_name").cloned().unwrap_or(Value::Null),
                    "names": leaf_data.get("names").cloned().unwrap_or_else(|| json!([])),
                    "not_after": leaf_data
                        .pointer("/validity/not_after")
                        .cloned()
                        .or_else(|| leaf_data.get("not_after").cloned())
                        .unwrap_or(Value::Null),
                    "sha256": leaf_data
                        .get("fingerprint_sha256")
                        .cloned()
                        .or_else(|| leaf_data.get("sha256").cloned())
                        .unwrap_or(Value::Null),
                }));
                for value in leaf_name_values(leaf) {
                    match value {
                        Value::String(text) => tls_names.push(text.clone()),
                        Value::Array(items) => {
                            for item in items {
                                match item.as_str() {
                                    Some(text) => tls_names.push(text.to_string()),
                                    None => partial = true,
                                }
                            }
                        }
                        _ => partial = true,
                    }
                }
                if let Some(value) = leaf.pointer("/subject/common_name").and_then(Value::as_str) {
                    tls_names.push(value.to_string());
                }
            }
            if let Some(Value::Array(software)) = service.get("software") {
                for product in software {
                    if let Some(cpe) = product.get("cpe").and_then(Value::as_str) {
                        cpes.push(cpe.to_string());
                    }
                }
            }
            for key in ["vulnerabilities", "cve", "cves"] {
                if let Some(value) = service.get(key) {
                    let (items, _) = super::string_array(Some(value));
                    vulns.extend(items);
                }
            }
            services.push(json!({
                "port": service.get("port").cloned().unwrap_or(Value::Null),
                "transport": service.get("transport_protocol").cloned().unwrap_or(Value::Null),
                "service_name": service.get("service_name").cloned().unwrap_or(Value::Null),
                "software": service.get("software").cloned().unwrap_or_else(|| json!([])),
            }));
        }
    }
    candidates.extend(tls_names);
    let (ports_from_field, malformed) = passive_ports(resource.get("ports"));
    if malformed {
        partial = true;
    }
    passive_ports_found.extend(ports_from_field);
    passive_ports_found.sort_unstable();
    passive_ports_found.dedup();
    cpes.sort();
    cpes.dedup();
    vulns.sort();
    vulns.dedup();
    vulns.truncate(limit);
    certificates.truncate(limit);

    let mut names = Vec::new();
    for raw in candidates {
        match normalize_candidate(&raw) {
            Some(name) => names.push(name),
            None => notes.push(format!("ignored non-name candidate: {raw}")),
        }
    }
    if names.len() > limit {
        partial = true;
        notes.push("candidate limit reached; results are incomplete".into());
    }
    let names = bounded_names(names, limit);
    let asn = resource
        .get("autonomous_system")
        .or_else(|| resource.get("asn"))
        .cloned()
        .unwrap_or(Value::Null);
    let organization = asn
        .get("name")
        .or_else(|| asn.get("description"))
        .or_else(|| resource.pointer("/autonomous_system/organization"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let asn_number = asn
        .get("asn")
        .or_else(|| asn.get("number"))
        .cloned()
        .unwrap_or(Value::Null);
    let country = resource
        .pointer("/location/country")
        .or_else(|| asn.get("country"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let ip = resource
        .get("ip")
        .or_else(|| resource.get("ip_address"))
        .cloned()
        .unwrap_or(Value::Null);
    let (tags, _) = passive_strings(resource.get("labels"), 64);
    ProviderParse {
        names,
        passive: json!({
            "provider": "censys",
            "api_version": version,
            "classification": "passive_reported",
            "ip": ip,
            "ports": passive_ports_found,
            "services": services,
            "certificates": certificates,
            "cpes": cpes,
            "vulns": vulns,
            "asn": asn_number,
            "organization": organization,
            "country": country,
            "labels": tags,
        }),
        partial,
        notes,
    }
}
