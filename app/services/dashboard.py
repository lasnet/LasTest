from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.settings import Settings, get_settings
from app.services.jobs import JobStore
from app.services.projects import get_project, project_path


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def build_project_dashboard(
    project_name: str,
    settings: Settings | None = None,
    job_store: JobStore | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    config = get_project(project_name, settings)
    root = project_path(project_name, settings)

    subdomains = _load_subdomains(root)
    dns_records = _load_dns_records(root)
    alive_hosts = _load_alive_hosts(root, config)
    findings = _load_findings(root)
    jobs = (job_store or JobStore(settings)).list_jobs(project_name=project_name, limit=8)
    severity_counts = _severity_counts(findings)

    scope = config.get("scope", {}) or {}
    metrics = {
        "domains": len(scope.get("domains", []) or []),
        "ips": len(scope.get("ips", []) or []),
        "exclusions": len(scope.get("exclusions", []) or []),
        "subdomains": len(subdomains),
        "dns_hosts": len(dns_records),
        "alive_hosts": len(alive_hosts),
        "open_ports": _count_ports(alive_hosts),
        "findings": len(findings),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "info": severity_counts["info"],
    }

    return {
        "project": config.get("project", {}),
        "scope": scope,
        "metrics": metrics,
        "assets": {
            "subdomains": subdomains[:500],
            "dns_records": dns_records[:500],
            "alive_hosts": alive_hosts[:500],
        },
        "findings": findings[:100],
        "severity_counts": severity_counts,
        "scans": jobs,
        "activity": _activity_from_jobs(jobs),
        "artifacts": {
            "subdomains": "recon/subdomains/subdomains.json",
            "dns_records": "recon/dns_records/dns_records.json",
            "alive_hosts": "recon/httpx/alive_hosts.json",
            "findings": "web/nuclei/findings.json",
        },
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return default


def _load_subdomains(root: Path) -> list[str]:
    data = _read_json(root / "recon" / "subdomains" / "subdomains.json", {})
    values = data.get("all", []) if isinstance(data, dict) else []
    return sorted(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def _load_dns_records(root: Path) -> list[dict[str, Any]]:
    data = _read_json(root / "recon" / "dns_records" / "dns_records.json", {})
    hosts = data.get("hosts", []) if isinstance(data, dict) else []
    return [item for item in hosts if isinstance(item, dict)]


def _load_alive_hosts(root: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    data = _read_json(root / "recon" / "httpx" / "alive_hosts.json", {})
    hosts = data.get("hosts", []) if isinstance(data, dict) else []
    if hosts:
        return [_normalize_alive_host(item) for item in hosts if isinstance(item, dict)]

    urls = (
        config.get("recon", {})
        .get("httpx", {})
        .get("root_alive_hosts", [])
        or config.get("recon", {}).get("alive_hosts", [])
        or []
    )
    return [{"url": str(item), "host": "", "status_code": None, "tech": []} for item in urls]


def _normalize_alive_host(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": item.get("url") or item.get("input") or "",
        "host": item.get("host") or item.get("input") or "",
        "scheme": item.get("scheme") or "",
        "port": item.get("port"),
        "status_code": item.get("status_code") or item.get("status-code"),
        "title": item.get("title") or "",
        "webserver": item.get("webserver") or item.get("server") or "",
        "tech": item.get("tech") or item.get("technologies") or [],
    }


def _load_findings(root: Path) -> list[dict[str, Any]]:
    data = _read_json(root / "web" / "nuclei" / "findings.json", {})
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return [item for item in findings if isinstance(item, dict)]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _count_ports(alive_hosts: list[dict[str, Any]]) -> int:
    ports = {
        str(item.get("port"))
        for item in alive_hosts
        if item.get("port") not in (None, "", 0)
    }
    return len(ports)


def _activity_from_jobs(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for job in jobs[:10]:
        status = job.get("status") or "queued"
        result = job.get("result") or {}
        items.append(
            {
                "time": job.get("finished_at") or job.get("started_at") or job.get("created_at"),
                "status": status,
                "event": _activity_event(status),
                "task": job.get("task_type") or "scan",
                "asset": _result_asset(result),
                "detail": job.get("error") or _result_summary(result),
            }
        )
    return items


def _activity_event(status: str) -> str:
    if status == "succeeded":
        return "Scan completed"
    if status == "failed":
        return "Scan failed"
    if status == "running":
        return "Scan running"
    return "Scan queued"


def _result_asset(result: dict[str, Any]) -> str:
    for key in ("found", "alive", "findings", "targets", "records"):
        if key in result:
            return f"{result[key]} {key}"
    return "-"


def _result_summary(result: dict[str, Any]) -> str:
    if not result:
        return "-"
    parts = [f"{key}: {value}" for key, value in sorted(result.items()) if key != "output"]
    return ", ".join(parts[:3]) or "-"
