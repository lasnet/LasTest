from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _as_float(value: str | None, default: float) -> float:
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_name: str = "LasTest Pentest Platform"
    app_env: str = "local"
    web_api_key: str = ""
    web_auth_disabled: bool = False
    projects_dir: Path = Path("projects")
    data_dir: Path = Path("data")
    logs_dir: Path = Path("logs")
    database_url: str = "sqlite:///data/lastest.sqlite3"
    job_poll_interval_sec: float = 2.0
    command_timeout_sec: int = 3600
    max_log_tail_bytes: int = 200_000

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            app_name=os.getenv("APP_NAME", cls.app_name),
            app_env=os.getenv("APP_ENV", cls.app_env),
            web_api_key=os.getenv("WEB_API_KEY", "").strip(),
            web_auth_disabled=_as_bool(os.getenv("WEB_AUTH_DISABLED"), False),
            projects_dir=Path(os.getenv("PROJECTS_DIR", str(cls.projects_dir))),
            data_dir=Path(os.getenv("DATA_DIR", str(cls.data_dir))),
            logs_dir=Path(os.getenv("LOGS_DIR", str(cls.logs_dir))),
            database_url=os.getenv("DATABASE_URL", cls.database_url),
            job_poll_interval_sec=_as_float(
                os.getenv("JOB_POLL_INTERVAL_SEC"), cls.job_poll_interval_sec
            ),
            command_timeout_sec=_as_int(
                os.getenv("COMMAND_TIMEOUT_SEC"), cls.command_timeout_sec
            ),
            max_log_tail_bytes=_as_int(
                os.getenv("MAX_LOG_TAIL_BYTES"), cls.max_log_tail_bytes
            ),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()

