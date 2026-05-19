from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.jobs import sqlite_path_from_url, utc_now


ROLES = {"viewer": 10, "analyst": 20, "admin": 30}
PASSWORD_HASH_ITERATIONS = 260_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{1,127}$")


def utc_datetime() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_role(value: str) -> str:
    role = str(value or "").strip().lower()
    if role not in ROLES:
        raise ValueError(f"Unsupported role: {value}")
    return role


def has_role(user_role: str, required_role: str) -> bool:
    return ROLES.get(user_role, 0) >= ROLES[required_role]


def hash_password(password: str) -> str:
    raw = str(password or "")
    if len(raw) < 12:
        raise ValueError("Password must be at least 12 characters long")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_HASH_ITERATIONS,
        _b64(salt),
        _b64(digest),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            str(password or "").encode("utf-8"),
            _b64decode(salt),
            int(iterations),
        )
        return hmac.compare_digest(_b64(digest), expected)
    except Exception:
        return False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _json_b64(data: dict[str, Any]) -> str:
    return _b64(json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def jwt_secret(settings: Settings) -> str:
    return settings.auth_jwt_secret or settings.web_api_key


def encode_jwt(payload: dict[str, Any], secret: str) -> str:
    if not secret:
        raise RuntimeError("AUTH_JWT_SECRET is not configured")
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64(signature)}"


def decode_jwt(token: str, secret: str) -> dict[str, Any]:
    if not secret:
        raise ValueError("JWT secret is not configured")
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
    except ValueError as exc:
        raise ValueError("Invalid token format") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    expected = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_b64(expected), signature_b64):
        raise ValueError("Invalid token signature")

    payload = json.loads(_b64decode(payload_b64).decode("utf-8"))
    if int(payload.get("exp", 0)) < int(utc_datetime().timestamp()):
        raise ValueError("Token expired")
    return payload


class AuthStore:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.db_path = sqlite_path_from_url(self.settings.database_url)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def ensure_schema(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    jti TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor_username TEXT,
                    actor_role TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    status TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_username ON auth_sessions(username)"
            )

    def bootstrap_admin_from_env(self) -> None:
        self.ensure_schema()
        username = self.settings.auth_bootstrap_admin_username or "admin"
        password = self.settings.auth_bootstrap_admin_password
        if not password or self.user_count() > 0:
            return
        self.create_user(username, password, "admin")
        self.audit(
            actor=None,
            action="auth.bootstrap_admin",
            resource_type="user",
            resource_id=username,
            status="success",
        )

    def user_count(self) -> int:
        self.ensure_schema()
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"])

    def setup_required(self) -> bool:
        return not self.settings.web_auth_disabled and self.user_count() == 0

    def create_user(self, username: str, password: str, role: str) -> dict[str, Any]:
        self.ensure_schema()
        user = _normalize_username(username)
        user_role = normalize_role(role)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username, password_hash, role, is_active,
                    created_at, updated_at, last_login_at
                )
                VALUES (?, ?, ?, 1, ?, ?, NULL)
                """,
                (user, hash_password(password), user_role, now, now),
            )
        return self.get_user(user)

    def list_users(self) -> list[dict[str, Any]]:
        self.ensure_schema()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT username, role, is_active, created_at, updated_at, last_login_at
                FROM users
                ORDER BY username
                """
            ).fetchall()
        return [dict(row) | {"is_active": bool(row["is_active"])} for row in rows]

    def active_admin_count(self) -> int:
        self.ensure_schema()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()
        return int(row["count"])

    def get_user(self, username: str) -> dict[str, Any]:
        self.ensure_schema()
        user = _normalize_username(username)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT username, role, is_active, created_at, updated_at, last_login_at
                FROM users
                WHERE username = ?
                """,
                (user,),
            ).fetchone()
        if row is None:
            raise KeyError(f"User not found: {username}")
        return dict(row) | {"is_active": bool(row["is_active"])}

    def update_user(
        self,
        username: str,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        password: str | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        user = _normalize_username(username)
        current = self.get_user(user)
        if (
            current["role"] == "admin"
            and current["is_active"]
            and self.active_admin_count() <= 1
            and (role is not None and normalize_role(role) != "admin" or is_active is False)
        ):
            raise ValueError("Cannot disable or demote the last active admin")

        updates = []
        params: list[Any] = []
        if role is not None:
            updates.append("role = ?")
            params.append(normalize_role(role))
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)
        if password:
            updates.append("password_hash = ?")
            params.append(hash_password(password))
        if not updates:
            return self.get_user(user)

        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(user)
        with self.connect() as conn:
            result = conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE username = ?",
                params,
            )
        if result.rowcount != 1:
            raise KeyError(f"User not found: {username}")
        if is_active is False:
            self.revoke_user_sessions(user)
        return self.get_user(user)

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        self.ensure_schema()
        user = _normalize_username(username)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (user,),
            ).fetchone()
        if row is None or not row["is_active"]:
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = ?, updated_at = ? WHERE username = ?",
                (utc_now(), utc_now(), user),
            )
        return self.get_user(user)

    def create_session(
        self,
        user: dict[str, Any],
        *,
        ip_address: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        self.ensure_schema()
        now = utc_datetime()
        expires = now + timedelta(minutes=max(5, self.settings.auth_token_ttl_minutes))
        jti = uuid.uuid4().hex
        payload = {
            "sub": user["username"],
            "role": user["role"],
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
        }
        token = encode_jwt(payload, jwt_secret(self.settings))
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    jti, username, created_at, expires_at, revoked_at, ip_address, user_agent
                )
                VALUES (?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    jti,
                    user["username"],
                    now.isoformat().replace("+00:00", "Z"),
                    expires.isoformat().replace("+00:00", "Z"),
                    ip_address,
                    user_agent[:500],
                ),
            )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "user": user,
        }

    def validate_token(self, token: str) -> dict[str, Any]:
        self.ensure_schema()
        payload = decode_jwt(token, jwt_secret(self.settings))
        username = _normalize_username(payload.get("sub", ""))
        jti = str(payload.get("jti") or "")
        if not jti:
            raise ValueError("Token missing session id")
        with self.connect() as conn:
            session = conn.execute(
                "SELECT * FROM auth_sessions WHERE jti = ?",
                (jti,),
            ).fetchone()
        if session is None or session["revoked_at"]:
            raise ValueError("Session is not active")
        if parse_utc(session["expires_at"]) <= utc_datetime():
            raise ValueError("Session expired")
        user = self.get_user(username)
        if not user["is_active"]:
            raise ValueError("User is disabled")
        if user["role"] != payload.get("role"):
            raise ValueError("User role changed; login again")
        return user | {"session_id": jti}

    def revoke_session(self, jti: str) -> None:
        self.ensure_schema()
        with self.connect() as conn:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL",
                (utc_now(), jti),
            )

    def revoke_user_sessions(self, username: str) -> None:
        self.ensure_schema()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = ?
                WHERE username = ? AND revoked_at IS NULL
                """,
                (utc_now(), _normalize_username(username)),
            )

    def audit(
        self,
        *,
        actor: dict[str, Any] | None,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        status: str = "success",
        ip_address: str = "",
        user_agent: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.ensure_schema()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    created_at, actor_username, actor_role, action, resource_type,
                    resource_id, status, ip_address, user_agent, details_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    actor.get("username") if actor else None,
                    actor.get("role") if actor else None,
                    action,
                    resource_type,
                    resource_id,
                    status,
                    ip_address,
                    user_agent[:500],
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        self.ensure_schema()
        limit = max(1, min(int(limit), 500))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_events
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json") or "{}")
            events.append(item)
        return events


def _normalize_username(value: str) -> str:
    username = str(value or "").strip().lower()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "Username must be 2-128 chars and contain only letters, digits, dots, underscores, @ or hyphens"
        )
    return username
