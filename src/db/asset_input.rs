//! Project-local scan inputs. Scope import is atomic and never performs network IO.
use super::{insert_audit, Db};
use crate::domain::{new_id, now_rfc3339, ScopeStatus};
use crate::scope::{canonical_ip, NetworkPolicy, RuleKind, Scope};
use anyhow::{Context, Result};
use rusqlite::{params, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInput {
    pub id: String,
    pub host: Option<String>,
    pub ips: Vec<String>,
    pub urls: Vec<String>,
}

pub fn scope_has_dns(scope: &Scope) -> bool {
    scope.rules.iter().any(|rule| {
        !rule.exclusion
            && matches!(rule.kind, RuleKind::ExactDomain | RuleKind::SubdomainTree)
            && scope.allows_host(&rule.value)
    })
}

pub fn scope_import_ips(
    scope: &Scope,
    policy: &NetworkPolicy,
    limit: usize,
) -> Result<Vec<String>> {
    anyhow::ensure!(
        !scope_has_dns(scope),
        "run Subdomain Enumeration first: Scope contains DNS names"
    );
    let mut ips = BTreeSet::new();
    for rule in scope.rules.iter().filter(|rule| !rule.exclusion) {
        match rule.kind {
            RuleKind::Ip => {
                let ip = canonical_ip(&rule.value)?;
                if scope.allows_ip(ip) {
                    policy.permits(ip)?;
                    ips.insert(ip.to_string());
                }
            }
            RuleKind::Cidr => {
                let net = crate::scope::canonical_cidr(&rule.value)?;
                // Reject oversized ranges before iteration, including IPv6 /0.
                let bits = if net.addr().is_ipv4() { 32 } else { 128 };
                let size = 1u128.checked_shl(bits - u32::from(net.prefix_len()));
                anyhow::ensure!(size.is_some_and(|size| size <= limit as u128),
                    "Network {} exceeds the import limit of {limit} addresses; use a smaller Network", rule.value);
                for ip in net.hosts() {
                    if scope.allows_ip(ip) {
                        policy.permits(ip)?;
                        ips.insert(ip.to_string());
                    }
                }
            }
            _ => {}
        }
        anyhow::ensure!(
            ips.len() <= limit,
            "Scope exceeds the import limit of {limit} addresses"
        );
    }
    anyhow::ensure!(
        !ips.is_empty(),
        "add allowed IP addresses or Networks to Scope first"
    );
    Ok(ips.into_iter().collect())
}

impl Db {
    pub fn asset_input_catalog(&self, project_id: &str) -> Result<Vec<Value>> {
        let mut urls: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let conn = self.connect()?;
        let mut stmt =
            conn.prepare("SELECT canonical_value FROM assets WHERE project_id=?1 AND kind='url'")?;
        let values = stmt
            .query_map([project_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for value in values {
            if let Ok(url) = crate::scope::parse_target_url(&value) {
                if let Some(host) = url.host_str() {
                    urls.entry(host.trim_matches(['[', ']']).to_string())
                        .or_default()
                        .insert(url.to_string());
                }
            }
        }
        self.inventory_rows_filtered(project_id, "", None, None, None)?
            .into_iter()
            .map(|row| {
                let keys = row
                    .host
                    .clone()
                    .map(|host| vec![host])
                    .unwrap_or_else(|| row.ips.clone());
                let selected_urls: BTreeSet<_> = keys
                    .iter()
                    .filter_map(|key| urls.get(key))
                    .flatten()
                    .cloned()
                    .collect();
                let mut value = serde_json::to_value(row)?;
                value["urls"] = json!(selected_urls);
                Ok(value)
            })
            .collect()
    }

    pub fn select_asset_inputs(
        &self,
        project_id: &str,
        ids: &[String],
        limit: usize,
    ) -> Result<Vec<AssetInput>> {
        let ids: BTreeSet<_> = ids.iter().collect();
        anyhow::ensure!(
            !ids.is_empty() && ids.len() <= limit,
            "select 1-{limit} Assets"
        );
        let catalog = self.asset_input_catalog(project_id)?;
        let selected = catalog
            .into_iter()
            .filter(|row| {
                row["id"]
                    .as_str()
                    .is_some_and(|id| ids.iter().any(|value| value.as_str() == id))
            })
            .map(serde_json::from_value)
            .collect::<serde_json::Result<Vec<AssetInput>>>()?;
        anyhow::ensure!(
            selected.len() == ids.len(),
            "selected Asset was deleted or is not in this project"
        );
        Ok(selected)
    }

    pub fn import_scope_assets(
        &self,
        project_id: &str,
        version: i64,
        policy: &NetworkPolicy,
        limit: usize,
        actor: &str,
    ) -> Result<usize> {
        let revision = self
            .current_scope(project_id)?
            .context("project Scope is missing")?;
        anyhow::ensure!(
            revision.version == version && revision.status == ScopeStatus::Approved,
            "Scope changed or is not approved; reload before importing"
        );
        let ips = scope_import_ips(&revision.scope, policy, limit)?;
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest: (String, String) = tx.query_row("SELECT id, status FROM scope_revisions WHERE project_id=?1 ORDER BY version DESC LIMIT 1", [project_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        anyhow::ensure!(
            latest.0 == revision.id && latest.1 == "approved",
            "Scope changed; reload before importing"
        );
        let now = now_rfc3339();
        let mut added = 0;
        for ip in &ips {
            added += tx.execute("INSERT INTO assets(id,project_id,kind,value,canonical_value,first_seen,last_seen) VALUES(?1,?2,'ip',?3,?3,?4,?4) ON CONFLICT(project_id,kind,canonical_value) DO NOTHING",
                params![new_id("ast"),project_id,ip,now])?;
        }
        insert_audit(
            &tx,
            actor,
            "asset.import_scope",
            "project",
            Some(project_id),
            &json!({"scope_revision_id":revision.id,"addresses":ips.len(),"added":added}),
        )?;
        tx.commit()?;
        Ok(added)
    }
}
