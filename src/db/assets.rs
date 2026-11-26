//! Project inventory derived from stored observations, without new DNS requests.
use super::discovery::{inventory_candidates, inventory_classifications};
use super::{insert_audit, json_or_empty, Db};
use crate::scope::normalize_domain;
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub struct InventoryRow {
    pub id: String,
    pub kind: String,
    pub host: Option<String>,
    pub ips: Vec<String>,
    pub last_seen: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub technologies: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub interest: Option<String>,
    #[serde(default)]
    pub providers: Vec<String>,
}

pub enum DeleteAssetResult {
    Deleted,
    NotFound,
    LinkedIp,
}

struct Asset {
    id: String,
    kind: String,
    value: String,
    canonical: String,
    last_seen: String,
}

struct Observation {
    id: String,
    canonical: String,
    kind: String,
    data: Value,
    observed_at: String,
}

fn host_key(value: &str) -> Option<String> {
    normalize_domain(value).ok()
}

fn url_host(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    host_key(url.host_str()?)
}

fn belongs_to_host(value: &str, host: &str) -> bool {
    host_key(value).as_deref() == Some(host) || url_host(value).as_deref() == Some(host)
}

fn observation_host(observation: &Observation) -> Option<String> {
    // IP observations carry the DNS name explicitly; PTR uses `name`.
    if observation.canonical.parse::<IpAddr>().is_ok() {
        return observation
            .data
            .get("host")
            .or_else(|| {
                (observation.kind == "ptr")
                    .then(|| observation.data.get("name"))
                    .flatten()
            })
            .and_then(Value::as_str)
            .and_then(host_key);
    }
    url_host(&observation.canonical).or_else(|| host_key(&observation.canonical))
}

fn observation_ips(observation: &Observation) -> BTreeSet<String> {
    let mut ips = BTreeSet::new();
    let mut add = |value: &str| {
        if let Ok(ip) = value.parse::<IpAddr>() {
            ips.insert(ip.to_string());
        }
    };
    add(&observation.canonical);
    if matches!(observation.data["record_type"].as_str(), Some("A" | "AAAA")) {
        if let Some(value) = observation.data["value"].as_str() {
            add(value);
        }
    }
    for key in ["addresses", "ips"] {
        if let Some(values) = observation.data[key].as_array() {
            for value in values.iter().filter_map(Value::as_str) {
                add(value);
            }
        }
    }
    // A probe can redirect to another host. Attribute its remote IP only to
    // the final URL's host, never the original host merely because it initiated it.
    let same_host = observation.data["url"]
        .as_str()
        .is_none_or(|url| url_host(url) == observation_host(observation));
    if same_host {
        if let Some(value) = observation.data["verified_ip"].as_str() {
            add(value);
        }
    }
    ips
}

fn snapshot(conn: &Connection, project_id: &str) -> Result<(Vec<Asset>, Vec<Observation>)> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, value, canonical_value, last_seen FROM assets
         WHERE project_id = ?1 ORDER BY kind, canonical_value",
    )?;
    let assets = stmt
        .query_map([project_id], |row| {
            Ok(Asset {
                id: row.get(0)?,
                kind: row.get(1)?,
                value: row.get(2)?,
                canonical: row.get(3)?,
                last_seen: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut stmt = conn.prepare(
        "SELECT id, canonical_asset, kind, data, observed_at FROM observations WHERE project_id = ?1",
    )?;
    let observations = stmt
        .query_map([project_id], |row| {
            Ok(Observation {
                id: row.get(0)?,
                canonical: row.get(1)?,
                kind: row.get(2)?,
                data: json_or_empty(row.get(3)?),
                observed_at: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((assets, observations))
}

fn inventory(assets: &[Asset], observations: &[Observation]) -> Vec<InventoryRow> {
    let mut hosts: BTreeMap<String, (InventoryRow, BTreeSet<String>)> = assets
        .iter()
        .filter(|asset| asset.kind == "host")
        .map(|asset| {
            (
                asset.canonical.clone(),
                (
                    InventoryRow {
                        id: asset.id.clone(),
                        kind: asset.kind.clone(),
                        host: Some(asset.value.clone()),
                        ips: Vec::new(),
                        last_seen: asset.last_seen.clone(),
                        groups: Vec::new(),
                        technologies: Vec::new(),
                        categories: Vec::new(),
                        confidence: None,
                        interest: None,
                        providers: Vec::new(),
                    },
                    BTreeSet::new(),
                ),
            )
        })
        .collect();
    for observation in observations {
        if let Some((row, ips)) =
            observation_host(observation).and_then(|host| hosts.get_mut(&host))
        {
            ips.extend(observation_ips(observation));
            if observation.observed_at > row.last_seen {
                row.last_seen.clone_from(&observation.observed_at);
            }
        }
    }
    let linked: BTreeSet<String> = hosts
        .values()
        .flat_map(|(_, ips)| ips.iter().cloned())
        .collect();
    let mut rows: Vec<_> = hosts
        .into_values()
        .map(|(mut row, ips)| {
            row.ips = ips.into_iter().collect();
            row
        })
        .collect();
    rows.extend(
        assets
            .iter()
            .filter(|asset| asset.kind == "ip" && !linked.contains(&asset.canonical))
            .map(|asset| InventoryRow {
                id: asset.id.clone(),
                kind: asset.kind.clone(),
                host: None,
                ips: vec![asset.value.clone()],
                last_seen: asset.last_seen.clone(),
                groups: Vec::new(),
                technologies: Vec::new(),
                categories: Vec::new(),
                confidence: None,
                interest: None,
                providers: Vec::new(),
            }),
    );
    rows
}

fn search_inventory(
    assets: &[Asset],
    observations: &[Observation],
    search: &str,
) -> Vec<InventoryRow> {
    let query = search.trim().to_lowercase();
    let mut rows = inventory(assets, observations);
    if !query.is_empty() {
        rows.retain(|row| {
            row.host
                .as_deref()
                .unwrap_or_default()
                .to_lowercase()
                .contains(&query)
                || row.ips.iter().any(|ip| ip.to_lowercase().contains(&query))
        });
    }
    rows
}

impl Db {
    pub fn inventory_rows(&self, project_id: &str, search: &str) -> Result<Vec<InventoryRow>> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let (assets, observations) = snapshot(&tx, project_id)?;
        let rows = search_inventory(&assets, &observations, search);
        tx.commit()?;
        Ok(rows)
    }

    pub fn list_asset_urls(&self, project_id: &str, limit: u32) -> Result<Vec<Value>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT value, last_seen FROM assets
             WHERE project_id = ?1 AND kind = 'url' ORDER BY canonical_value LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![project_id, limit], |row| {
                Ok(json!({ "value": row.get::<_, String>(0)?, "last_seen": row.get::<_, String>(1)? }))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn delete_inventory_asset(
        &self,
        project_id: &str,
        asset_id: &str,
        actor: &str,
    ) -> Result<DeleteAssetResult> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (assets, observations) = snapshot(&tx, project_id)?;
        let Some(asset) = assets
            .iter()
            .find(|asset| asset.id == asset_id && matches!(asset.kind.as_str(), "host" | "ip"))
        else {
            return Ok(DeleteAssetResult::NotFound);
        };
        if asset.kind == "ip"
            && !inventory(&assets, &observations)
                .iter()
                .any(|row| row.id == asset_id)
        {
            return Ok(DeleteAssetResult::LinkedIp);
        }
        let host = &asset.canonical;
        for observation in &observations {
            let remove = if asset.kind == "host" {
                belongs_to_host(&observation.canonical, host)
                    || observation_host(observation).as_deref() == Some(host)
            } else {
                observation.canonical == *host
            };
            if remove {
                tx.execute("DELETE FROM observations WHERE id = ?1", [&observation.id])?;
            }
        }
        let mut deleted_assets = 0;
        for candidate in &assets {
            if candidate.id == asset_id
                || (asset.kind == "host"
                    && candidate.kind == "url"
                    && url_host(&candidate.canonical).as_deref() == Some(host))
            {
                deleted_assets +=
                    tx.execute("DELETE FROM assets WHERE id = ?1", [&candidate.id])?;
            }
        }
        let mut stmt = tx.prepare("SELECT id, asset FROM findings WHERE project_id = ?1")?;
        let findings = stmt
            .query_map([project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        let mut deleted_findings = 0;
        for (id, value) in findings {
            if (asset.kind == "host" && belongs_to_host(&value, host))
                || (asset.kind == "ip" && value == *host)
            {
                deleted_findings += tx.execute("DELETE FROM findings WHERE id = ?1", [id])?;
            }
        }
        // Candidate rows and their provenance stay; the foreign key clears the
        // asset link. Classification rows attached to the deleted asset must not
        // leave a broken subject reference.
        tx.execute(
            "DELETE FROM asset_classifications WHERE project_id = ?1 AND subject_type = 'asset' AND subject_id = ?2",
            rusqlite::params![project_id, asset_id],
        )?;
        // Legacy import bookkeeping must not point at removed records.
        tx.execute("DELETE FROM import_records WHERE project_id = ?1 AND (
            (target_table = 'assets' AND NOT EXISTS (SELECT 1 FROM assets WHERE id = target_id)) OR
            (target_table = 'observations' AND NOT EXISTS (SELECT 1 FROM observations WHERE id = target_id)) OR
            (target_table = 'findings' AND NOT EXISTS (SELECT 1 FROM findings WHERE id = target_id)))", [project_id])?;
        insert_audit(
            &tx,
            actor,
            "asset.delete",
            "asset",
            Some(asset_id),
            &json!({
                "project_id": project_id, "kind": asset.kind, "value": asset.value,
                "deleted_assets": deleted_assets, "deleted_findings": deleted_findings,
                "ip_assets_preserved": asset.kind == "host"
            }),
        )?;
        tx.commit()?;
        Ok(DeleteAssetResult::Deleted)
    }
}

impl Db {
    /// Inventory with additive technology/provider/category filters. Stored
    /// classifications and candidate provenance are read; no network is used.
    pub fn inventory_rows_filtered(
        &self,
        project_id: &str,
        search: &str,
        technology: Option<&str>,
        provider: Option<&str>,
        category: Option<&str>,
    ) -> Result<Vec<InventoryRow>> {
        // Build the inventory and its metadata from the same project snapshot.
        // Loading metadata once avoids opening multiple connections per row.
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let (assets, observations) = snapshot(&tx, project_id)?;
        let mut rows = search_inventory(&assets, &observations, search);
        if rows.is_empty() {
            return Ok(rows);
        }
        let canonical_by_id: BTreeMap<_, _> = assets
            .iter()
            .filter(|asset| asset.kind == "host")
            .map(|asset| (asset.id.as_str(), asset.canonical.as_str()))
            .collect();
        let classifications = inventory_classifications(&tx, project_id)?;
        let mut classification_by_asset = BTreeMap::new();
        let mut classification_by_host = BTreeMap::new();
        for classification in &classifications {
            if let Some(id) = classification["subject_id"]
                .as_str()
                .filter(|_| classification["subject_type"] == "asset")
            {
                classification_by_asset.insert(id, classification);
            }
            if let Some(host) = classification["host"].as_str() {
                classification_by_host.entry(host).or_insert(classification);
            }
        }
        let candidates = inventory_candidates(&tx, project_id)?;
        let mut candidate_by_asset = BTreeMap::new();
        let mut candidate_by_host = BTreeMap::new();
        for (index, candidate) in candidates.iter().enumerate() {
            if let Some(id) = candidate["asset_id"].as_str() {
                candidate_by_asset.entry(id).or_insert(index);
            }
            if let Some(host) = candidate["hostname"].as_str() {
                candidate_by_host.insert(host, index);
            }
        }
        tx.commit()?;
        for row in &mut rows {
            let host = row.host.as_deref().unwrap_or_default();
            let classification = classification_by_asset.get(row.id.as_str()).or_else(|| {
                row.host
                    .as_deref()
                    .filter(|host| !host.is_empty())
                    .and_then(|host| classification_by_host.get(host))
            });
            if let Some(classification) = classification {
                let strings = |value: &Value| {
                    value
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                };
                row.groups = strings(&classification["groups"]);
                row.categories = strings(&classification["categories"]);
                row.technologies = classification["technologies"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.get("name").and_then(Value::as_str))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                row.confidence = classification["confidence"].as_str().map(str::to_string);
                row.interest = classification["interest"].as_str().map(str::to_string);
            }
            if !host.is_empty() {
                // The existing lookup prefers the most recent candidate linked
                // by asset ID or matching the asset's canonical hostname.
                let candidate = candidate_by_asset
                    .get(row.id.as_str())
                    .into_iter()
                    .chain(
                        canonical_by_id
                            .get(row.id.as_str())
                            .and_then(|host| candidate_by_host.get(host)),
                    )
                    .min()
                    .or_else(|| {
                        host_key(host).and_then(|host| candidate_by_host.get(host.as_str()))
                    });
                if let Some(&index) = candidate {
                    let candidate = &candidates[index];
                    row.providers = candidate["sources"]
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect::<BTreeSet<_>>()
                                .into_iter()
                                .collect()
                        })
                        .unwrap_or_default();
                }
            }
        }
        if let Some(technology) = technology {
            let needle = technology.to_ascii_lowercase();
            rows.retain(|row| {
                row.technologies
                    .iter()
                    .any(|item| item.to_ascii_lowercase() == needle)
            });
        }
        if let Some(provider) = provider {
            rows.retain(|row| row.providers.iter().any(|item| item == provider));
        }
        if let Some(category) = category {
            rows.retain(|row| row.categories.iter().any(|item| item == category));
        }
        Ok(rows)
    }

    pub fn host_asset_by_canonical(&self, project_id: &str, host: &str) -> Result<Option<Value>> {
        let Ok(host) = normalize_domain(host) else {
            return Ok(None);
        };
        let conn = self.connect()?;
        Ok(conn
            .query_row(
                "SELECT id, kind, value, canonical_value, first_seen, last_seen
                 FROM assets WHERE project_id = ?1 AND kind = 'host' AND canonical_value = ?2",
                rusqlite::params![project_id, host],
                |row| {
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "kind": row.get::<_, String>(1)?,
                        "value": row.get::<_, String>(2)?,
                        "canonical_value": row.get::<_, String>(3)?,
                        "first_seen": row.get::<_, String>(4)?,
                        "last_seen": row.get::<_, String>(5)?,
                    }))
                },
            )
            .optional()?)
    }

    pub fn candidate_by_host(&self, project_id: &str, host: &str) -> Result<Option<Value>> {
        let Ok(host) = normalize_domain(host) else {
            return Ok(None);
        };
        let conn = self.connect()?;
        let id: Option<String> = conn
            .query_row(
                "SELECT id FROM discovery_candidates WHERE project_id = ?1 AND hostname = ?2",
                rusqlite::params![project_id, host],
                |row| row.get(0),
            )
            .optional()?;
        match id {
            Some(id) => self.candidate_by_id_raw(project_id, &id),
            None => Ok(None),
        }
    }

    pub fn asset_detail(&self, project_id: &str, asset_id: &str) -> Result<Option<Value>> {
        let conn = self.connect()?;
        let asset = conn
            .query_row(
                "SELECT id, kind, value, canonical_value, first_seen, last_seen
                 FROM assets WHERE project_id = ?1 AND id = ?2",
                rusqlite::params![project_id, asset_id],
                |row| {
                    Ok(json!({
                        "id": row.get::<_, String>(0)?,
                        "kind": row.get::<_, String>(1)?,
                        "value": row.get::<_, String>(2)?,
                        "canonical_value": row.get::<_, String>(3)?,
                        "first_seen": row.get::<_, String>(4)?,
                        "last_seen": row.get::<_, String>(5)?,
                    }))
                },
            )
            .optional()?;
        let Some(mut asset) = asset else {
            return Ok(None);
        };
        let canonical = asset["canonical_value"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let kind = asset["kind"].as_str().unwrap_or_default().to_string();
        let mut observations = self.observations_for_host(project_id, &canonical)?;
        // Choose the latest verified mapping, never the union of every DNS
        // address ever observed for this host.
        let latest = self.latest_enrichment(project_id, &canonical)?;
        let candidate = self.candidate_for_asset(project_id, asset_id)?;
        let mut linked_ips = BTreeSet::new();
        let addresses = candidate
            .as_ref()
            .and_then(|c| c.get("addresses"))
            .or_else(|| {
                latest
                    .as_ref()
                    .and_then(|e| e.pointer("/data/dns/addresses"))
            })
            .and_then(Value::as_array)
            .cloned();
        if let Some(addresses) = addresses {
            linked_ips.extend(
                addresses
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        } else if let Some(mapping) = observations.iter().find(|o| o["kind"] == "host") {
            for key in ["addresses", "ips"] {
                linked_ips.extend(
                    mapping["data"][key]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string),
                );
            }
            if let Some(ip) = mapping["data"]["verified_ip"].as_str() {
                linked_ips.insert(ip.to_string());
            }
        }
        for ip in &linked_ips {
            observations.extend(
                self.observations_for_host(project_id, ip)?
                    .into_iter()
                    .filter(|o| {
                        matches!(o["kind"].as_str(), Some("port" | "service" | "provider"))
                    }),
            );
        }
        asset["addresses"] = if kind == "ip" {
            json!([canonical])
        } else {
            json!(linked_ips)
        };
        let mut dns = Vec::new();
        let mut http = Vec::new();
        let mut services = Vec::new();
        let mut confirmed_ports = Vec::new();
        let mut passive_ports = Vec::new();
        let passive = crate::tasks::asset_enrich::provider_passive(&observations);
        for observation in &observations {
            match observation["kind"].as_str().unwrap_or_default() {
                "dns" | "ptr" | "dns_empty" => dns.push(observation.clone()),
                "http" => http.push(observation.clone()),
                "port" | "service" => {
                    if observation["kind"] == "port" && observation["data"]["state"] == "open" {
                        confirmed_ports.push(observation.clone());
                    } else {
                        services.push(observation.clone());
                    }
                }
                _ => {}
            }
        }
        if let Some(ports) = passive.get("ports").and_then(Value::as_array) {
            passive_ports = ports.clone();
        }
        let technologies = crate::tasks::tech_catalog::from_stored(&observations);
        let candidate = if kind == "host" {
            self.candidate_for_asset(project_id, asset_id)?.or_else(|| {
                self.candidate_by_host(project_id, &canonical)
                    .ok()
                    .flatten()
            })
        } else {
            None
        };
        asset["dns"] = Value::Array(dns);
        asset["http"] = Value::Array(http);
        asset["services"] = Value::Array(services);
        asset["ports"] = json!({
            "confirmed": confirmed_ports,
            "passive_reported": passive_ports,
        });
        asset["technologies"] = Value::Array(technologies);
        asset["network"] = json!({
            "asn": passive.get("asn").cloned().unwrap_or(Value::Null),
            "organization": passive.get("organization").cloned().unwrap_or(Value::Null),
            "country": passive.get("country").cloned().unwrap_or(Value::Null),
        });
        asset["candidate"] = candidate.unwrap_or(Value::Null);
        asset["enrichment"] = if kind == "host" || kind == "ip" {
            self.latest_enrichment(project_id, &canonical)?
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        asset["classification"] = self
            .classification_for(project_id, "asset", asset_id)?
            .or_else(|| {
                if kind == "host" {
                    self.classification_for_host(project_id, &canonical)
                        .ok()
                        .flatten()
                } else {
                    None
                }
            })
            .unwrap_or(Value::Null);
        asset["sources"] = json!(observations
            .iter()
            .filter_map(|observation| observation["source"].as_str())
            .collect::<BTreeSet<_>>());
        Ok(Some(asset))
    }
}
