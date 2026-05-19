from __future__ import annotations

from pathlib import Path

from app.core.settings import Settings, get_settings


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return repo_root() / path


def ensure_runtime_dirs(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    for path in (settings.projects_dir, settings.data_dir, settings.logs_dir):
        resolve_path(path).mkdir(parents=True, exist_ok=True)

