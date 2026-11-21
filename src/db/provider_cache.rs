//! Installation-wide passive-provider cache, cooldown and reservation helper.
//!
//! The cache is shared by every project and worker, but project API endpoints
//! never read it. Cache keys contain a hashed credential context, never a
//! token. Reservations make a concurrent cache miss wait for one owner and
//! expire automatically if the owner dies.
use super::{json_or_empty, Db};
use anyhow::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ProviderCacheEntry {
    pub http_status: i64,
    pub body: Value,
    pub negative: bool,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveOutcome {
    Acquired,
    /// Another worker is fetching the same key.
    Busy,
    /// Provider-wide cooldown after a rate limit.
    Cooldown(String),
    /// Shared rate limit: wait this many milliseconds.
    Wait(u64),
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn seconds_from_now(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl Db {
    pub fn provider_cache_get(&self, cache_key: &str) -> Result<Option<ProviderCacheEntry>> {
        let conn = self.connect()?;
        let entry = conn
            .query_row(
                "SELECT http_status, body, negative, expires_at FROM provider_cache
                 WHERE cache_key = ?1",
                params![cache_key],
                |row| {
                    Ok(ProviderCacheEntry {
                        http_status: row.get(0)?,
                        body: json_or_empty(row.get(1)?),
                        negative: row.get::<_, i64>(2)? != 0,
                        expires_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(entry.filter(|entry| entry.expires_at > now_rfc3339()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn provider_cache_put(
        &self,
        cache_key: &str,
        provider: &str,
        api_version: &str,
        endpoint: &str,
        credential_context: &str,
        http_status: u16,
        body: &Value,
        negative: bool,
        ttl_seconds: i64,
        max_entries: usize,
    ) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO provider_cache(cache_key, provider, api_version, endpoint,
                 credential_context, http_status, body, negative, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(cache_key) DO UPDATE SET
                 http_status = excluded.http_status, body = excluded.body,
                 negative = excluded.negative, created_at = excluded.created_at,
                 expires_at = excluded.expires_at",
            params![
                cache_key,
                provider,
                api_version,
                endpoint,
                credential_context,
                http_status as i64,
                body.to_string(),
                i64::from(negative),
                now,
                seconds_from_now(ttl_seconds.max(1))
            ],
        )?;
        self.provider_cache_prune(max_entries)?;
        Ok(())
    }

    pub fn provider_cache_prune(&self, max_entries: usize) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM provider_cache WHERE expires_at <= ?1",
            params![now_rfc3339()],
        )?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM provider_cache", [], |row| row.get(0))?;
        if count > max_entries as i64 {
            let excess = count - max_entries as i64;
            conn.execute(
                "DELETE FROM provider_cache WHERE cache_key IN (
                     SELECT cache_key FROM provider_cache ORDER BY created_at ASC LIMIT ?1)",
                params![excess],
            )?;
        }
        Ok(())
    }

    pub fn provider_cache_clear(&self) -> Result<u64> {
        let conn = self.connect()?;
        Ok(conn.execute("DELETE FROM provider_cache", [])? as u64)
    }

    /// Reserve the right to fetch one cache key and advance the shared rate
    /// limiter. A short SQLite transaction is held only for bookkeeping.
    pub fn provider_try_acquire(
        &self,
        cache_key: &str,
        provider: &str,
        namespace: &str,
        owner: &str,
        reservation_seconds: i64,
        min_interval_ms: u64,
    ) -> Result<ReserveOutcome> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_rfc3339();
        tx.execute(
            "DELETE FROM provider_reservations WHERE expires_at <= ?1",
            params![now],
        )?;
        let state: Option<(Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT next_allowed_at, cooldown_until FROM provider_state
                 WHERE provider = ?1 AND namespace = ?2",
                params![provider, namespace],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((next_allowed, cooldown)) = state {
            if let Some(until) = cooldown.filter(|until| until > &now) {
                tx.commit()?;
                return Ok(ReserveOutcome::Cooldown(until));
            }
            if let Some(until) = next_allowed.filter(|until| until > &now) {
                let wait = chrono::DateTime::parse_from_rfc3339(&until)
                    .ok()
                    .map(|value| {
                        (value.with_timezone(&chrono::Utc) - chrono::Utc::now())
                            .num_milliseconds()
                            .max(1) as u64
                    })
                    .unwrap_or(min_interval_ms.max(1));
                tx.commit()?;
                return Ok(ReserveOutcome::Wait(wait));
            }
        }
        let reserved: Option<String> = tx
            .query_row(
                "SELECT owner FROM provider_reservations WHERE cache_key = ?1",
                params![cache_key],
                |row| row.get(0),
            )
            .optional()?;
        if reserved
            .as_deref()
            .is_some_and(|existing| existing != owner)
        {
            tx.commit()?;
            return Ok(ReserveOutcome::Busy);
        }
        tx.execute(
            "INSERT INTO provider_reservations(cache_key, owner, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(cache_key) DO UPDATE SET expires_at = excluded.expires_at",
            params![
                cache_key,
                owner,
                now,
                seconds_from_now(reservation_seconds.max(1))
            ],
        )?;
        let next_allowed = if min_interval_ms == 0 {
            now.clone()
        } else {
            (chrono::Utc::now() + chrono::Duration::milliseconds(min_interval_ms as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        tx.execute(
            "INSERT INTO provider_state(provider, namespace, next_allowed_at, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(provider, namespace) DO UPDATE SET
                 next_allowed_at = excluded.next_allowed_at, updated_at = excluded.updated_at",
            params![provider, namespace, next_allowed, now],
        )?;
        tx.commit()?;
        Ok(ReserveOutcome::Acquired)
    }

    pub fn provider_release(&self, cache_key: &str, owner: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM provider_reservations WHERE cache_key = ?1 AND owner = ?2",
            params![cache_key, owner],
        )?;
        Ok(())
    }

    pub fn provider_set_cooldown(
        &self,
        provider: &str,
        namespace: &str,
        seconds: i64,
    ) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO provider_state(provider, namespace, cooldown_until, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(provider, namespace) DO UPDATE SET
                 cooldown_until = MAX(COALESCE(provider_state.cooldown_until, ''), excluded.cooldown_until),
                 updated_at = excluded.updated_at",
            params![provider, namespace, seconds_from_now(seconds.max(1)), now],
        )?;
        Ok(())
    }

    pub fn provider_cooldown(&self, provider: &str, namespace: &str) -> Result<Option<String>> {
        let conn = self.connect()?;
        let until: Option<String> = conn
            .query_row(
                "SELECT cooldown_until FROM provider_state WHERE provider = ?1 AND namespace = ?2",
                params![provider, namespace],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(until.filter(|value| value > &now_rfc3339()))
    }
}
