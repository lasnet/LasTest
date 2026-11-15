//! Argon2id passwords, revocable opaque sessions and role checks.

use crate::config::Config;
use crate::db::Db;
use crate::domain::{now_rfc3339, Role, User};
use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const SESSION_COOKIE: &str = "lastest_session";

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub token: String,
    pub expires_at: String,
    pub user: User,
    pub kind: String,
}

#[derive(Clone)]
pub struct AuthService {
    pub db: Db,
    pub config: Config,
}

impl AuthService {
    pub fn new(db: Db, config: Config) -> Self {
        Self { db, config }
    }

    pub fn validate_username(username: &str) -> Result<String> {
        let username = username.trim();
        if username.len() < 2 || username.len() > 128 {
            anyhow::bail!("username must be between 2 and 128 characters");
        }
        let mut chars = username.chars();
        let first = chars.next().unwrap_or(' ');
        if !first.is_ascii_alphanumeric() {
            anyhow::bail!("username must start with a letter or digit");
        }
        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
        {
            anyhow::bail!("username contains unsupported characters");
        }
        Ok(username.to_string())
    }

    pub fn validate_password(password: &str) -> Result<()> {
        if password.chars().count() < 12 {
            anyhow::bail!("password must be at least 12 characters long");
        }
        if password.len() > 1024 {
            anyhow::bail!("password is too long");
        }
        Ok(())
    }

    pub fn hash_password(password: &str) -> Result<String> {
        Self::validate_password(password)?;
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| anyhow::anyhow!("cannot hash password: {err}"))
    }

    pub fn verify_password(password: &str, encoded: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(encoded) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    pub fn bootstrap(&self, username: &str, password: &str) -> Result<User> {
        let username = Self::validate_username(username)?;
        if self.db.count_users()? > 0 {
            anyhow::bail!("bootstrap refused: users already exist");
        }
        let hash = Self::hash_password(password)?;
        let user = self
            .db
            .insert_user(&username, &hash, Role::Admin, false, Some("bootstrap"))?;
        self.db.audit(
            &username,
            "admin.bootstrap",
            "user",
            Some(&user.id),
            &serde_json::json!({"role": "admin"}),
        )?;
        Ok(user)
    }

    pub fn create_user(
        &self,
        actor: &str,
        username: &str,
        password: &str,
        role: Role,
        must_change_password: bool,
        source: Option<&str>,
    ) -> Result<User> {
        let username = Self::validate_username(username)?;
        let hash = Self::hash_password(password)?;
        let user = self
            .db
            .insert_user(&username, &hash, role, must_change_password, source)?;
        self.db.audit(
            actor,
            "user.create",
            "user",
            Some(&user.id),
            &serde_json::json!({"username": username, "role": role.as_str()}),
        )?;
        Ok(user)
    }

    pub fn login(&self, username: &str, password: &str, kind: &str) -> Result<LoginResult> {
        if !matches!(kind, "web" | "cli") {
            anyhow::bail!("unsupported session kind");
        }
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            anyhow::bail!("invalid username or password");
        }
        if let Some(until) = self.db.login_locked_until(username)? {
            let _ = until;
            anyhow::bail!("invalid username or password");
        }
        let Some(user) = self.db.user_by_username(username)? else {
            self.db.record_login_failure(
                username,
                self.config.login_max_attempts,
                self.config.login_lock_minutes,
            )?;
            anyhow::bail!("invalid username or password");
        };
        let Some((hash, _)) = self.db.password_hash(&user.id)? else {
            anyhow::bail!("invalid username or password");
        };
        if !user.is_active || !Self::verify_password(password, &hash) {
            self.db.record_login_failure(
                username,
                self.config.login_max_attempts,
                self.config.login_lock_minutes,
            )?;
            self.db.audit(
                username,
                "auth.login_failed",
                "session",
                None,
                &serde_json::json!({"kind": kind}),
            )?;
            anyhow::bail!("invalid username or password");
        }
        self.db.clear_login_failures(username)?;
        self.db.set_last_login(&user.id)?;
        let (token, token_hash) = new_token();
        let hours = if kind == "cli" {
            self.config.cli_token_ttl_hours
        } else {
            self.config.session_ttl_hours
        };
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(hours))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.db
            .insert_session(&token_hash, &user.id, kind, &expires_at)?;
        self.db.audit(
            &user.username,
            "auth.login",
            "session",
            None,
            &serde_json::json!({"kind": kind}),
        )?;
        Ok(LoginResult {
            token,
            expires_at,
            user,
            kind: kind.to_string(),
        })
    }

    pub fn authenticate(&self, token: &str) -> Result<Option<(User, String)>> {
        if token.len() < 20 || token.len() > 256 {
            return Ok(None);
        }
        let token_hash = hash_token(token);
        let Some((user, kind)) = self.db.session_user(&token_hash)? else {
            return Ok(None);
        };
        let _ = self.db.touch_session(&token_hash);
        Ok(Some((user, kind)))
    }

    pub fn logout(&self, token: &str, actor: &str) -> Result<bool> {
        let token_hash = hash_token(token);
        let revoked = self.db.revoke_session(&token_hash)?;
        if revoked {
            let _ = self.db.audit(
                actor,
                "auth.logout",
                "session",
                None,
                &serde_json::json!({}),
            );
        }
        Ok(revoked)
    }

    pub fn change_password(&self, actor: &str, user_id: &str, new_password: &str) -> Result<()> {
        let hash = Self::hash_password(new_password)?;
        let updated = self
            .db
            .update_user(user_id, None, None, Some(&hash), Some(false))?;
        if updated.is_none() {
            anyhow::bail!("user does not exist");
        }
        self.db.revoke_user_sessions(user_id)?;
        self.db.audit(
            actor,
            "user.password_reset",
            "user",
            Some(user_id),
            &serde_json::json!({}),
        )?;
        Ok(())
    }
}

pub fn new_token() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    (token.clone(), hash_token(&token))
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn require_role(user: &User, required: Role) -> Result<()> {
    if user.role.at_least(required) && user.is_active {
        Ok(())
    } else {
        anyhow::bail!("insufficient permissions")
    }
}

pub fn parse_cookie(header: &str, name: &str) -> Option<String> {
    for part in header.split(';') {
        let mut pieces = part.trim().splitn(2, '=');
        let key = pieces.next()?.trim();
        if key == name {
            let value = pieces.next().unwrap_or("").trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn bearer_token(header: Option<&str>) -> Option<String> {
    let value = header?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

pub fn new_password_placeholder() -> Result<String> {
    // Imported accounts never receive a usable password; an administrator must
    // explicitly reset it before the account can log in.
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let value = format!("imported-disabled-{}", URL_SAFE_NO_PAD.encode(raw));
    AuthService::hash_password(&value)
}

pub fn expires_in_days(days: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::days(days))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn touch_now() -> String {
    now_rfc3339()
}
