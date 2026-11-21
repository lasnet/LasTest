//! SQLite access. Connections are short lived, use WAL, foreign keys and a
//! bounded busy timeout. Migrations are versioned and applied under an
//! immediate transaction so API and worker can start concurrently.

pub mod asset_input;
pub mod assets;
pub mod discovery;
pub mod import;
pub mod jobs;
pub mod projects;
pub mod provider_cache;
pub mod users;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SCHEMA_VERSION: i64 = 3;
const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../../migrations/0001_init.sql")),
    (2, include_str!("../../migrations/0002_setup_code.sql")),
    (3, include_str!("../../migrations/0003_asset_discovery.sql")),
];

#[derive(Clone, Debug)]
pub struct Db {
    path: Arc<PathBuf>,
}

impl Db {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let db = Self {
            path: Arc::new(path.into()),
        };
        if let Some(parent) = db.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("cannot create database directory {}", parent.display())
            })?;
        }
        db.migrate()?;
        Ok(db)
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(self.path())
            .with_context(|| format!("cannot open SQLite database {}", self.path().display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Ok(conn)
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = Connection::open(self.path())?;
        conn.busy_timeout(std::time::Duration::from_secs(15))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )",
        )?;
        let applied: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT version FROM schema_migrations")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if let Some(max) = applied.iter().max() {
            if *max > SCHEMA_VERSION {
                anyhow::bail!(
                    "database schema version {max} is newer than this binary (supported {SCHEMA_VERSION}); restore a compatible backup or upgrade the binary"
                );
            }
        }
        for (version, sql) in MIGRATIONS {
            if !applied.contains(version) {
                tx.execute_batch(sql)
                    .with_context(|| format!("cannot apply migration {version}"))?;
                tx.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                    params![version, crate::domain::now_rfc3339()],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.connect()?;
        let version = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(version)
    }

    pub fn healthy(&self) -> bool {
        self.connect()
            .and_then(|conn| {
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map(|_| ())
                    .map_err(Into::into)
            })
            .is_ok()
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        entity_type: &str,
        entity_id: Option<&str>,
        details: &Value,
    ) -> Result<()> {
        insert_audit(
            &self.connect()?,
            actor,
            action,
            entity_type,
            entity_id,
            details,
        )
    }

    pub fn backup_to(&self, destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = self.connect()?;
        conn.execute("VACUUM INTO ?1", params![destination.to_string_lossy()])?;
        Ok(())
    }
}

fn insert_audit(
    conn: &Connection,
    actor: &str,
    action: &str,
    entity_type: &str,
    entity_id: Option<&str>,
    details: &Value,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events(id, actor, action, entity_type, entity_id, details, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            crate::domain::new_id("aud"),
            actor,
            action,
            entity_type,
            entity_id,
            details.to_string(),
            crate::domain::now_rfc3339()
        ],
    )?;
    Ok(())
}

pub fn json_or_empty(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(Default::default()))
}

pub fn get_i64(conn: &Connection, sql: &str, values: &[&dyn rusqlite::ToSql]) -> Result<i64> {
    let value = conn.query_row(sql, values, |row| row.get::<_, i64>(0))?;
    Ok(value)
}
