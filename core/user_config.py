from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


def user_config_path() -> Path:
    return Path.home() / "pentest-platform" / "core" / "config.yaml"


def load_user_config() -> Dict[str, Any]:
    cfg_path = user_config_path()
    if not cfg_path.exists():
        return {}

    try:
        import yaml  # type: ignore
    except Exception:
        # Если PyYAML не установлен
        return {}

    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_api(conf: Dict[str, Any], *keys: str, default=None):
    cur = conf
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
