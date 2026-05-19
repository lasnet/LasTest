from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.paths import resolve_path
from app.services.validation import validate_project_name


JOB_STATUSES = {"queued", "running", "succeeded", "failed"}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sqlite_path_from_url(database_url: str) -> Path:
    if database_url.startswith("sqlite:////"):
        return Path(database_url.removeprefix("sqlite:///"))
    if database_url.startswith("sqlite:///"):
        return resolve_path(Path(database_url.removeprefix("sqlite:///")))
    raise ValueError("Only sqlite:/// DATABASE_URL is supported in v1")


class JobStore:
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
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    project_name TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    result_json TEXT,
                    log_path TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_project_created ON jobs(project_name, created_at)"
            )

    def create_job(
        self,
        project_name: str,
        task_type: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        project = validate_project_name(project_name)
        job_id = uuid.uuid4().hex
        log_dir = resolve_path(self.settings.logs_dir) / "jobs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{job_id}.log"
        created_at = utc_now()

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    id, project_name, task_type, status, params_json, result_json,
                    log_path, error, created_at, started_at, finished_at
                )
                VALUES (?, ?, ?, 'queued', ?, NULL, ?, NULL, ?, NULL, NULL)
                """,
                (
                    job_id,
                    project,
                    task_type,
                    json.dumps(params or {}, ensure_ascii=False),
                    str(log_path),
                    created_at,
                ),
            )
        return self.get_job(job_id)

    def list_jobs(
        self,
        project_name: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.ensure_schema()
        limit = max(1, min(int(limit), 500))
        params: list[Any] = []
        where = ""
        if project_name:
            where = "WHERE project_name = ?"
            params.append(validate_project_name(project_name))

        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM jobs {where} ORDER BY created_at DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
        return [self._row_to_job(row) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"Job not found: {job_id}")
        return self._row_to_job(row)

    def acquire_next_job(self) -> dict[str, Any] | None:
        self.ensure_schema()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM jobs
                WHERE status = 'queued'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None

            updated = conn.execute(
                """
                UPDATE jobs
                SET status = 'running', started_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (utc_now(), row["id"]),
            )
            if updated.rowcount != 1:
                return None

        return self.get_job(row["id"])

    def finish_job(
        self,
        job_id: str,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"succeeded", "failed"}:
            raise ValueError(f"Unsupported final status: {status}")

        with self.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, result_json = ?, error = ?, finished_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    json.dumps(result or {}, ensure_ascii=False),
                    error,
                    utc_now(),
                    job_id,
                ),
            )
        return self.get_job(job_id)

    def read_log_tail(self, job_id: str) -> str:
        job = self.get_job(job_id)
        path = Path(job["log_path"])
        if not path.exists():
            return ""

        max_bytes = self.settings.max_log_tail_bytes
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
            data = handle.read()
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "project_name": row["project_name"],
            "task_type": row["task_type"],
            "status": row["status"],
            "params": json.loads(row["params_json"] or "{}"),
            "result": json.loads(row["result_json"] or "{}"),
            "log_path": row["log_path"],
            "error": row["error"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }
