use crate::db::Db;
use crate::domain::{new_id, now_rfc3339, Role, User};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;

fn map_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        role: Role::parse(&row.get::<_, String>(2)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(err)),
            )
        })?,
        is_active: row.get::<_, i64>(3)? != 0,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        last_login_at: row.get(6)?,
    })
}

fn insert_user_record(
    conn: &Connection,
    username: &str,
    password_hash: &str,
    role: Role,
    must_change_password: bool,
) -> Result<User> {
    let now = now_rfc3339();
    let user = User {
        id: new_id("usr"),
        username: username.to_string(),
        role,
        is_active: true,
        created_at: now.clone(),
        updated_at: now,
        last_login_at: None,
    };
    conn.execute(
        "INSERT INTO users(id, username, password_hash, role, is_active, must_change_password,
                            created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
        params![
            user.id,
            user.username,
            password_hash,
            role.as_str(),
            i64::from(must_change_password),
            user.created_at,
            user.updated_at
        ],
    )
    .with_context(|| format!("cannot create user {username}"))?;
    Ok(user)
}

fn can_bootstrap(conn: &Connection, code_hash: Option<&str>) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM users)
            AND (?1 IS NULL OR EXISTS(
                SELECT 1 FROM setup_code WHERE token_hash = ?1 AND expires_at > ?2
            ))",
        params![code_hash, chrono::Utc::now().timestamp()],
        |row| row.get(0),
    )?)
}

impl Db {
    pub fn count_users(&self) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?)
    }

    pub fn store_setup_code(&self, code_hash: &str, expires_at: i64) -> Result<bool> {
        let changed = self.connect()?.execute(
            "INSERT INTO setup_code(id, token_hash, expires_at)
             SELECT 1, ?1, ?2 WHERE NOT EXISTS(SELECT 1 FROM users)
             ON CONFLICT(id) DO UPDATE SET
                token_hash = excluded.token_hash, expires_at = excluded.expires_at",
            params![code_hash, expires_at],
        )?;
        Ok(changed == 1)
    }

    pub fn setup_code_valid(&self, code_hash: &str) -> Result<bool> {
        can_bootstrap(&self.connect()?, Some(code_hash))
    }

    pub fn bootstrap_admin(
        &self,
        username: &str,
        password_hash: &str,
        code_hash: Option<&str>,
    ) -> Result<Option<User>> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !can_bootstrap(&tx, code_hash)? {
            return Ok(None);
        }
        let user = insert_user_record(&tx, username, password_hash, Role::Admin, false)?;
        tx.execute("DELETE FROM setup_code", [])?;
        super::insert_audit(
            &tx,
            username,
            "admin.bootstrap",
            "user",
            Some(&user.id),
            &serde_json::json!({"role": "admin"}),
        )?;
        tx.commit()?;
        Ok(Some(user))
    }

    pub fn user_by_username(&self, username: &str) -> Result<Option<User>> {
        let conn = self.connect()?;
        let user = conn
            .query_row(
                "SELECT id, username, role, is_active, created_at, updated_at, last_login_at
                 FROM users WHERE username = ?1",
                params![username],
                map_user,
            )
            .optional()?;
        Ok(user)
    }

    pub fn user_by_id(&self, id: &str) -> Result<Option<User>> {
        let conn = self.connect()?;
        let user = conn
            .query_row(
                "SELECT id, username, role, is_active, created_at, updated_at, last_login_at
                 FROM users WHERE id = ?1",
                params![id],
                map_user,
            )
            .optional()?;
        Ok(user)
    }

    pub fn password_hash(&self, user_id: &str) -> Result<Option<(String, bool)>> {
        let conn = self.connect()?;
        let row = conn
            .query_row(
                "SELECT password_hash, must_change_password FROM users WHERE id = ?1",
                params![user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_users(&self, limit: u32, offset: u32) -> Result<(Vec<User>, i64)> {
        let conn = self.connect()?;
        let total = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        let mut stmt = conn.prepare(
            "SELECT id, username, role, is_active, created_at, updated_at, last_login_at
             FROM users ORDER BY username LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![limit, offset], map_user)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, total))
    }

    pub fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
        must_change_password: bool,
        source: Option<&str>,
    ) -> Result<User> {
        let user = insert_user_record(
            &self.connect()?,
            username,
            password_hash,
            role,
            must_change_password,
        )?;
        if let Some(source) = source {
            self.audit(
                "system",
                "user.import",
                "user",
                Some(&user.id),
                &serde_json::json!({"source": source}),
            )?;
        }
        Ok(user)
    }

    pub fn update_user(
        &self,
        id: &str,
        role: Option<Role>,
        is_active: Option<bool>,
        password_hash: Option<&str>,
        must_change_password: Option<bool>,
    ) -> Result<Option<User>> {
        let Some(existing) = self.user_by_id(id)? else {
            return Ok(None);
        };
        let new_role = role.unwrap_or(existing.role);
        let new_active = is_active.unwrap_or(existing.is_active);
        if existing.role == Role::Admin
            && existing.is_active
            && (new_role != Role::Admin || !new_active)
        {
            let admins = self.active_admin_count()?;
            if admins <= 1 {
                anyhow::bail!("cannot remove the last active administrator");
            }
        }
        let conn = self.connect()?;
        conn.execute(
            "UPDATE users SET role = ?1, is_active = ?2, password_hash = COALESCE(?3, password_hash),
                    must_change_password = COALESCE(?4, must_change_password), updated_at = ?5
             WHERE id = ?6",
            params![
                new_role.as_str(),
                i64::from(new_active),
                password_hash,
                must_change_password.map(i64::from),
                now_rfc3339(),
                id
            ],
        )?;
        self.user_by_id(id)
    }

    pub fn active_admin_count(&self) -> Result<i64> {
        let conn = self.connect()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn set_last_login(&self, user_id: &str) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        conn.execute(
            "UPDATE users SET last_login_at = ?1, updated_at = ?1 WHERE id = ?2",
            params![now, user_id],
        )?;
        Ok(())
    }

    pub fn insert_session(
        &self,
        token_hash: &str,
        user_id: &str,
        kind: &str,
        expires_at: &str,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO sessions(token_hash, user_id, kind, created_at, expires_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?4)",
            params![token_hash, user_id, kind, now_rfc3339(), expires_at],
        )?;
        Ok(())
    }

    pub fn session_user(&self, token_hash: &str) -> Result<Option<(User, String)>> {
        let conn = self.connect()?;
        let row = conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.is_active, u.created_at, u.updated_at,
                        u.last_login_at, s.kind
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND s.revoked_at IS NULL
                   AND s.expires_at > ?2 AND u.is_active = 1",
                params![token_hash, now_rfc3339()],
                |row| {
                    let user = map_user(row)?;
                    let kind = row.get::<_, String>(7)?;
                    Ok((user, kind))
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn touch_session(&self, token_hash: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE sessions SET last_seen_at = ?1 WHERE token_hash = ?2",
            params![now_rfc3339(), token_hash],
        )?;
        Ok(())
    }

    pub fn revoke_session(&self, token_hash: &str) -> Result<bool> {
        let conn = self.connect()?;
        let changed = conn.execute(
            "UPDATE sessions SET revoked_at = ?1 WHERE token_hash = ?2 AND revoked_at IS NULL",
            params![now_rfc3339(), token_hash],
        )?;
        Ok(changed > 0)
    }

    pub fn revoke_user_sessions(&self, user_id: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now_rfc3339(), user_id],
        )?;
        Ok(())
    }

    pub fn login_locked_until(&self, username: &str) -> Result<Option<String>> {
        let conn = self.connect()?;
        let row = conn
            .query_row(
                "SELECT locked_until FROM login_attempts WHERE username = ?1",
                params![username],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(match row {
            Some(value) if value > now_rfc3339() => Some(value),
            _ => None,
        })
    }

    pub fn record_login_failure(&self, username: &str, max: u32, lock_minutes: i64) -> Result<()> {
        let conn = self.connect()?;
        let now = now_rfc3339();
        let current: i64 = conn
            .query_row(
                "SELECT failed_count FROM login_attempts WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let failed = current + 1;
        let locked_until = if failed >= i64::from(max) {
            Some(
                (chrono::Utc::now() + chrono::Duration::minutes(lock_minutes))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            )
        } else {
            None
        };
        conn.execute(
            "INSERT INTO login_attempts(username, failed_count, locked_until, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(username) DO UPDATE SET failed_count = ?2, locked_until = ?3, updated_at = ?4",
            params![username, failed, locked_until, now],
        )?;
        Ok(())
    }

    pub fn clear_login_failures(&self, username: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM login_attempts WHERE username = ?1",
            params![username],
        )?;
        Ok(())
    }

    pub fn list_audit(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<crate::domain::AuditEvent>, i64)> {
        let conn = self.connect()?;
        let total = conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?;
        let mut stmt = conn.prepare(
            "SELECT id, actor, action, entity_type, entity_id, details, created_at
             FROM audit_events ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let items = stmt
            .query_map(params![limit, offset], |row| {
                Ok(crate::domain::AuditEvent {
                    id: row.get(0)?,
                    actor: row.get(1)?,
                    action: row.get(2)?,
                    entity_type: row.get(3)?,
                    entity_id: row.get(4)?,
                    details: crate::db::json_or_empty(row.get(5)?),
                    created_at: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((items, total))
    }

    pub fn delete_login_attempt(&self, username: &str) -> Result<()> {
        self.clear_login_failures(username)
    }

    pub fn audit_value(&self, actor: &str, action: &str, id: &str, details: Value) -> Result<()> {
        self.audit(actor, action, "user", Some(id), &details)
    }
}
