from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.core.settings import Settings, get_settings
from app.services.paths import resolve_path
from app.services.validation import (
    normalize_domains,
    normalize_ips,
    validate_project_name,
)


PROJECT_SUBDIRS = ("recon", "web", "osint", "phishing", "reports", "logs")
SYSTEM_FILES = {"config.yaml", ".gitkeep"}


def projects_root(settings: Settings | None = None) -> Path:
    settings = settings or get_settings()
    root = resolve_path(settings.projects_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root


def project_path(project_name: str, settings: Settings | None = None) -> Path:
    name = validate_project_name(project_name)
    return projects_root(settings) / name


def _config_path(project_name: str, settings: Settings | None = None) -> Path:
    return project_path(project_name, settings) / "config.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Project config not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid project config: {path}")
    return data


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def list_projects(settings: Settings | None = None) -> list[dict[str, Any]]:
    root = projects_root(settings)
    items = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_dir() or path.name in SYSTEM_FILES or path.name.startswith("."):
            continue
        config_path = path / "config.yaml"
        if not config_path.exists():
            continue
        try:
            config = _load_yaml(config_path)
        except Exception:
            config = {}
        project = config.get("project", {}) if isinstance(config, dict) else {}
        scope = config.get("scope", {}) if isinstance(config, dict) else {}
        items.append(
            {
                "name": path.name,
                "client": project.get("client", ""),
                "description": project.get("description", ""),
                "created_at": project.get("created_at", ""),
                "domains_count": len(scope.get("domains", []) or []),
                "ips_count": len(scope.get("ips", []) or []),
            }
        )
    return items


def get_project(project_name: str, settings: Settings | None = None) -> dict[str, Any]:
    name = validate_project_name(project_name)
    path = project_path(name, settings)
    if not path.exists():
        raise FileNotFoundError(f"Project does not exist: {name}")
    config = _load_yaml(path / "config.yaml")
    config.setdefault("project", {})
    config.setdefault("scope", {})
    config["project"].setdefault("name", name)
    config["scope"].setdefault("domains", [])
    config["scope"].setdefault("ips", [])
    config["scope"].setdefault("exclusions", [])
    return config


def create_project(
    name: str,
    client: str = "",
    description: str = "",
    settings: Settings | None = None,
) -> dict[str, Any]:
    project_name = validate_project_name(name)
    path = project_path(project_name, settings)
    if path.exists():
        raise FileExistsError(f"Project already exists: {project_name}")

    path.mkdir(parents=True)
    for dirname in PROJECT_SUBDIRS:
        (path / dirname).mkdir(parents=True, exist_ok=True)

    config = {
        "project": {
            "name": project_name,
            "client": str(client or "").strip(),
            "description": str(description or "").strip(),
            "created_at": datetime.now().strftime("%Y-%m-%d"),
        },
        "scope": {
            "domains": [],
            "ips": [],
            "exclusions": [],
        },
    }
    _save_yaml(path / "config.yaml", config)
    return config


def update_scope(
    project_name: str,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    replace: bool = False,
    settings: Settings | None = None,
) -> dict[str, Any]:
    config = get_project(project_name, settings)
    scope = config.setdefault("scope", {})

    if domains is not None:
        incoming = normalize_domains(domains)
        existing = [] if replace else scope.get("domains", []) or []
        scope["domains"] = sorted(dict.fromkeys([*existing, *incoming]))

    if ips is not None:
        incoming = normalize_ips(ips)
        existing = [] if replace else scope.get("ips", []) or []
        scope["ips"] = sorted(dict.fromkeys([*existing, *incoming]))

    _save_yaml(_config_path(project_name, settings), config)
    return config


def merge_project_config(
    project_name: str,
    updates: dict[str, Any],
    settings: Settings | None = None,
) -> dict[str, Any]:
    config = get_project(project_name, settings)

    def merge_dict(base: dict[str, Any], extra: dict[str, Any]) -> None:
        for key, value in extra.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                merge_dict(base[key], value)
            else:
                base[key] = value

    merge_dict(config, updates)
    _save_yaml(_config_path(project_name, settings), config)
    return config

