//! Project inventory derived from stored observations, without new DNS requests.
use super::{insert_audit, json_or_empty, Db};
use crate::scope::normalize_domain;
use anyhow::Result;
use rusqlite::{Connection, TransactionBehavior};
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
            }),
    );
    rows
}

impl Db {
    pub fn inventory_rows(&self, project_id: &str, search: &str) -> Result<Vec<InventoryRow>> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let (assets, observations) = snapshot(&tx, project_id)?;
        let query = search.trim().to_lowercase();
        let rows = inventory(&assets, &observations)
            .into_iter()
            .filter(|row| {
                row.host
                    .as_deref()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&query)
                    || row.ips.iter().any(|ip| ip.to_lowercase().contains(&query))
            })
            .collect();
        tx.commit()?;
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
