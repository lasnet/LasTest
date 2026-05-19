from __future__ import annotations

import ipaddress
import re


PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,62}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


def validate_project_name(value: str) -> str:
    name = str(value or "").strip()
    if not PROJECT_NAME_RE.fullmatch(name):
        raise ValueError(
            "Project name must be 2-63 chars and contain only letters, digits, dots, underscores or hyphens"
        )
    if name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("Project name contains an unsafe path segment")
    return name


def normalize_domain(value: str) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"Invalid domain: {value}")
    return domain


def normalize_ip(value: str) -> str:
    raw = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def normalize_scope_exclusion(value: str) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        raise ValueError("Invalid empty exclusion")

    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid exclusion: {value}") from exc

    try:
        return normalize_ip(raw)
    except ValueError:
        return normalize_domain(raw)


def normalize_domains(values: list[str] | None) -> list[str]:
    normalized = [normalize_domain(item) for item in values or []]
    return sorted(dict.fromkeys(normalized))


def normalize_ips(values: list[str] | None) -> list[str]:
    normalized = [normalize_ip(item) for item in values or []]
    return sorted(dict.fromkeys(normalized))


def normalize_scope_exclusions(values: list[str] | None) -> list[str]:
    normalized = [normalize_scope_exclusion(item) for item in values or []]
    return sorted(dict.fromkeys(normalized))


def normalize_severities(value: str | list[str] | None) -> str:
    if value is None:
        return "critical,high,medium"
    if isinstance(value, str):
        raw = value.split(",")
    else:
        raw = value

    items = []
    for item in raw:
        severity = str(item or "").strip().lower()
        if not severity:
            continue
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"Unsupported nuclei severity: {severity}")
        if severity not in items:
            items.append(severity)

    if not items:
        raise ValueError("At least one nuclei severity is required")
    return ",".join(items)
