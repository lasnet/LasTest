from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict


def user_config_path() -> Path:
    configured = os.getenv("PENTEST_CONFIG_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path("core") / "config.yaml"


def load_user_config() -> Dict[str, Any]:
    cfg_path = user_config_path()
    data: Dict[str, Any] = {}

    if cfg_path.exists():
        try:
            import yaml  # type: ignore
        except Exception:
            yaml = None

        if yaml is not None:
            try:
                loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
                data = loaded if isinstance(loaded, dict) else {}
            except Exception:
                data = {}

    _apply_env_overrides(data)
    return data


def _set_nested(data: Dict[str, Any], value: Any, *keys: str) -> None:
    cur = data
    for key in keys[:-1]:
        item = cur.setdefault(key, {})
        if not isinstance(item, dict):
            item = {}
            cur[key] = item
        cur = item
    cur[keys[-1]] = value


def _apply_env_overrides(data: Dict[str, Any]) -> None:
    censys_token = os.getenv("CENSYS_PERSONAL_ACCESS_TOKEN", "").strip()
    if censys_token:
        _set_nested(data, censys_token, "apis", "censys", "personal_access_token")

    findomain_vt = os.getenv("FINDOMAIN_VIRUSTOTAL_TOKEN", "").strip()
    if findomain_vt:
        _set_nested(data, findomain_vt, "apis", "findomain", "virustotal_token")

    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    if shodan_key:
        _set_nested(data, shodan_key, "apis", "shodan", "api_key")


def get_api(conf: Dict[str, Any], *keys: str, default=None):
    cur = conf
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
