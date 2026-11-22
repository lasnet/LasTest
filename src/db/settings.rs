use super::{insert_audit, Db};
use crate::domain::new_id;
use anyhow::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct Wordlist {
    pub id: String,
    pub name: String,
    pub entries: usize,
}

impl Db {
    pub(crate) fn provider_key_suffixes(&self) -> Result<BTreeMap<String, String>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare("SELECT provider, last_four FROM provider_credentials")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub(crate) fn provider_ciphertext(&self, provider: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connect()?
            .query_row(
                "SELECT ciphertext FROM provider_credentials WHERE provider = ?1",
                [provider],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn save_provider_credential(
        &self,
        actor: &str,
        provider: &str,
        ciphertext: &[u8],
        last_four: &str,
    ) -> Result<()> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO provider_credentials(provider, ciphertext, last_four) VALUES (?1, ?2, ?3)
             ON CONFLICT(provider) DO UPDATE SET ciphertext = excluded.ciphertext, last_four = excluded.last_four",
            params![provider, ciphertext, last_four],
        )?;
        insert_audit(
            &tx,
            actor,
            "provider.key.update",
            "provider",
            Some(provider),
            &json!({}),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn dns_wordlists(&self) -> Result<Vec<Wordlist>> {
        let conn = self.connect()?;
        let mut stmt =
            conn.prepare("SELECT id, name, entries FROM dns_wordlists ORDER BY name_key, id")?;
        let rows = stmt.query_map([], |row| {
            Ok(Wordlist {
                id: row.get(0)?,
                name: row.get(1)?,
                entries: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn dns_wordlist_contents(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .connect()?
            .query_row(
                "SELECT contents FROM dns_wordlists WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn add_dns_wordlist(
        &self,
        actor: &str,
        name: &str,
        words: &[String],
    ) -> Result<Option<Wordlist>> {
        let wordlist = Wordlist {
            id: new_id("wl"),
            name: name.to_owned(),
            entries: words.len(),
        };
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT INTO dns_wordlists(id, name, name_key, entries, contents)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(name_key) DO NOTHING",
            params![
                wordlist.id,
                wordlist.name,
                name.to_lowercase(),
                wordlist.entries,
                words.join("\n")
            ],
        )?;
        if inserted == 0 {
            return Ok(None);
        }
        insert_audit(
            &tx,
            actor,
            "wordlist.create",
            "dns_wordlist",
            Some(&wordlist.id),
            &json!({"name": name, "entries": wordlist.entries}),
        )?;
        tx.commit()?;
        Ok(Some(wordlist))
    }
}
