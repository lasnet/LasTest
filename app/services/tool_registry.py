from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import dns.exception
import dns.resolver

from app.core.settings import Settings, get_settings
from app.services.projects import get_project, merge_project_config, project_path
from app.services.validation import normalize_domain, normalize_domains, normalize_severities


LogWriter = Callable[[str], None]


@dataclass(frozen=True)
class TaskSpec:
    task_type: str
    title: str
    description: str
    required_tools: tuple[str, ...]


TASK_SPECS = {
    "subfinder": TaskSpec(
        task_type="subfinder",
        title="Subfinder",
        description="Passive subdomain discovery for domains in project scope.",
        required_tools=("subfinder",),
    ),
    "httpx-root": TaskSpec(
        task_type="httpx-root",
        title="HTTPX Root Probe",
        description="HTTP probing for discovered subdomains.",
        required_tools=("httpx",),
    ),
    "dns-records": TaskSpec(
        task_type="dns-records",
        title="DNS Records",
        description="Resolve A, AAAA, CNAME, MX, NS and TXT records for scoped assets.",
        required_tools=(),
    ),
    "nuclei": TaskSpec(
        task_type="nuclei",
        title="Nuclei Scan",
        description="Template-based web vulnerability scan for alive HTTP targets.",
        required_tools=("nuclei",),
    ),
}


def available_tasks() -> list[dict[str, Any]]:
    items = []
    for spec in TASK_SPECS.values():
        missing = [tool for tool in spec.required_tools if shutil.which(tool) is None]
        items.append(
            {
                "task_type": spec.task_type,
                "title": spec.title,
                "description": spec.description,
                "required_tools": list(spec.required_tools),
                "available": not missing,
                "missing_tools": missing,
            }
        )
    return items


def validate_task_type(task_type: str) -> str:
    value = str(task_type or "").strip()
    if value not in TASK_SPECS:
        raise ValueError(f"Unsupported task type: {task_type}")
    return value


def run_task(
    task_type: str,
    project_name: str,
    params: dict[str, Any] | None,
    log: LogWriter,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    task = validate_task_type(task_type)
    params = params or {}
    spec = TASK_SPECS[task]

    missing = [tool for tool in spec.required_tools if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(f"Missing required tools: {', '.join(missing)}")

    if task == "subfinder":
        return _run_subfinder(project_name, params, log, settings)
    if task == "httpx-root":
        return _run_httpx_root(project_name, params, log, settings)
    if task == "dns-records":
        return _run_dns_records(project_name, params, log, settings)
    if task == "nuclei":
        return _run_nuclei(project_name, params, log, settings)
    raise ValueError(f"Unsupported task type: {task}")


def _run_command(
    cmd: list[str],
    log: LogWriter,
    settings: Settings,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    log("$ " + " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            timeout=settings.command_timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        for line in output.splitlines():
            log(line)
        raise TimeoutError(
            f"Command exceeded timeout of {settings.command_timeout_sec}s"
        ) from exc

    for line in (result.stdout or "").splitlines():
        log(line)
    return result.returncode, result.stdout or ""


def _list_param(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]
    return list(value)


def _scope_domains(project_name: str, params: dict[str, Any], settings: Settings) -> list[str]:
    if "domains" in params:
        return normalize_domains(_list_param(params.get("domains")))

    config = get_project(project_name, settings)
    domains = normalize_domains(config.get("scope", {}).get("domains", []) or [])
    mode = str(params.get("domain_mode", "all")).strip().lower()
    if mode == "first" and domains:
        return domains[:1]
    return domains


def _subdomains_dir(project_name: str, settings: Settings) -> Path:
    path = project_path(project_name, settings) / "recon" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _httpx_dir(project_name: str, settings: Settings) -> Path:
    path = project_path(project_name, settings) / "recon" / "httpx"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _dns_records_dir(project_name: str, settings: Settings) -> Path:
    path = project_path(project_name, settings) / "recon" / "dns_records"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _nuclei_dir(project_name: str, settings: Settings) -> Path:
    path = project_path(project_name, settings) / "web" / "nuclei"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_subdomains(project_name: str, settings: Settings) -> list[str]:
    path = _subdomains_dir(project_name, settings) / "subdomains.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return sorted(dict.fromkeys(data.get("all", []) or []))


def _save_subdomains(project_name: str, source: str, values: list[str], settings: Settings) -> None:
    out_file = _subdomains_dir(project_name, settings) / "subdomains.json"
    data = {"updated_at": datetime.now().isoformat(), "sources": {}, "all": []}
    if out_file.exists():
        data = json.loads(out_file.read_text(encoding="utf-8"))

    existing_source = data.get("sources", {}).get(source, []) or []
    data.setdefault("sources", {})[source] = sorted(
        dict.fromkeys([*existing_source, *values])
    )
    data["all"] = sorted(dict.fromkeys([*(data.get("all", []) or []), *values]))
    data["updated_at"] = datetime.now().isoformat()
    out_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _run_subfinder(
    project_name: str,
    params: dict[str, Any],
    log: LogWriter,
    settings: Settings,
) -> dict[str, Any]:
    domains = _scope_domains(project_name, params, settings)
    if not domains:
        raise RuntimeError("Project scope has no domains")

    env = os.environ.copy()
    vt_token = env.get("FINDOMAIN_VIRUSTOTAL_TOKEN", "").strip()
    if vt_token:
        env["findomain_virustotal_token"] = vt_token

    discovered: list[str] = []
    scope_roots = tuple(domains)
    for domain in domains:
        domain = normalize_domain(domain)
        log(f"Scanning domain: {domain}")
        code, stdout = _run_command(["subfinder", "-d", domain, "-silent"], log, settings, env)
        if code != 0:
            raise RuntimeError(f"subfinder failed for {domain} with exit code {code}")
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                candidate = normalize_domain(line)
            except ValueError:
                log(f"Skipping invalid subfinder output: {line[:160]}")
                continue
            if not any(candidate == root or candidate.endswith(f".{root}") for root in scope_roots):
                log(f"Skipping out-of-scope subdomain: {candidate}")
                continue
            discovered.append(candidate)

    unique = sorted(dict.fromkeys(discovered))
    out_dir = _subdomains_dir(project_name, settings)
    (out_dir / "subfinder_raw.txt").write_text("\n".join(unique), encoding="utf-8")
    _save_subdomains(project_name, "subfinder", unique, settings)
    merge_project_config(
        project_name,
        {
            "recon": {
                "subdomains": {
                    "count": len(unique),
                    "updated_at": datetime.now().isoformat(),
                }
            }
        },
        settings,
    )
    return {"domains_scanned": domains, "found": len(unique), "output": str(out_dir)}


def _run_httpx_root(
    project_name: str,
    params: dict[str, Any],
    log: LogWriter,
    settings: Settings,
) -> dict[str, Any]:
    targets = _list_param(params.get("targets")) or _load_subdomains(project_name, settings)
    if not targets:
        targets = _scope_domains(project_name, {}, settings)
    targets = sorted(dict.fromkeys(str(item).strip() for item in targets if str(item).strip()))
    if not targets:
        raise RuntimeError("No DNS targets found. Add scope, run subfinder, or pass targets.")

    out_dir = _httpx_dir(project_name, settings)
    input_file = out_dir / "input.txt"
    input_file.write_text("\n".join(targets), encoding="utf-8")

    cmd = [
        "httpx",
        "-l",
        str(input_file),
        "-json",
        "-title",
        "-status-code",
        "-tech-detect",
        "-follow-redirects",
        "-silent",
    ]
    code, stdout = _run_command(cmd, log, settings)
    if code != 0:
        raise RuntimeError(f"httpx failed with exit code {code}")

    raw_data: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_data.append(json.loads(line))
        except json.JSONDecodeError:
            log(f"Skipping non-JSON line from httpx: {line[:160]}")

    alive_hosts = [
        {
            "url": item.get("url") or item.get("input"),
            "host": item.get("host") or item.get("input"),
            "scheme": item.get("scheme"),
            "port": item.get("port"),
            "status_code": item.get("status_code") or item.get("status-code"),
            "title": item.get("title"),
            "webserver": item.get("webserver") or item.get("server"),
            "tech": item.get("tech") or item.get("technologies", []),
        }
        for item in raw_data
        if item.get("url") or item.get("input")
    ]
    alive_urls = [item["url"] for item in alive_hosts]

    (out_dir / "httpx_raw.json").write_text(
        json.dumps(raw_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "alive_hosts.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(alive_hosts),
                "hosts": alive_hosts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (out_dir / "alive_hosts.txt").write_text("\n".join(alive_urls), encoding="utf-8")
    merge_project_config(
        project_name,
        {"recon": {"httpx": {"root_alive_hosts": alive_urls, "alive_hosts": alive_urls}}},
        settings,
    )
    return {"targets": len(targets), "alive": len(alive_urls), "output": str(out_dir)}


def _run_dns_records(
    project_name: str,
    params: dict[str, Any],
    log: LogWriter,
    settings: Settings,
) -> dict[str, Any]:
    config = get_project(project_name, settings)
    scope_roots = normalize_domains(config.get("scope", {}).get("domains", []) or [])
    if not scope_roots:
        raise RuntimeError("Project scope has no domains")

    explicit_targets = _list_param(params.get("targets"))
    if explicit_targets:
        targets = [normalize_domain(str(item)) for item in explicit_targets]
        targets = [
            item
            for item in targets
            if any(item == root or item.endswith(f".{root}") for root in scope_roots)
        ]
    else:
        targets = [*scope_roots, *_load_subdomains(project_name, settings)]

    targets = sorted(dict.fromkeys(targets))
    max_hosts = int(params.get("max_hosts") or 500)
    targets = targets[: max(1, min(max_hosts, 5000))]
    if not targets:
        raise RuntimeError("No in-scope DNS targets to resolve")

    record_types = _list_param(params.get("record_types")) or ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
    record_types = [str(item).upper().strip() for item in record_types if str(item).strip()]
    allowed_types = {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
    record_types = [item for item in dict.fromkeys(record_types) if item in allowed_types]
    if not record_types:
        raise RuntimeError("No supported DNS record types requested")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = float(params.get("lifetime") or 5)
    resolver.timeout = float(params.get("timeout") or 3)

    hosts: list[dict[str, Any]] = []
    total_records = 0
    for host in targets:
        log(f"Resolving DNS records for {host}")
        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}
        for record_type in record_types:
            try:
                answers = resolver.resolve(host, record_type, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                errors[record_type] = "NXDOMAIN"
                continue
            except dns.resolver.NoNameservers:
                errors[record_type] = "No nameservers"
                continue
            except dns.resolver.LifetimeTimeout:
                errors[record_type] = "Timeout"
                continue
            except dns.exception.DNSException as exc:
                errors[record_type] = exc.__class__.__name__
                continue

            values = [answer.to_text().strip('"') for answer in answers if answer.to_text()]
            if values:
                records[record_type] = sorted(dict.fromkeys(values))
                total_records += len(records[record_type])

        if records or errors:
            hosts.append({"host": host, "records": records, "errors": errors})

    out_dir = _dns_records_dir(project_name, settings)
    (out_dir / "dns_records.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(hosts),
                "records": total_records,
                "record_types": record_types,
                "hosts": hosts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    merge_project_config(
        project_name,
        {"recon": {"dns_records": {"hosts": len(hosts), "records": total_records}}},
        settings,
    )
    return {
        "targets": len(targets),
        "hosts": len(hosts),
        "records": total_records,
        "output": str(out_dir),
    }


def _load_alive_targets(project_name: str, settings: Settings) -> list[str]:
    config = get_project(project_name, settings)
    hosts = (
        config.get("recon", {})
        .get("httpx", {})
        .get("root_alive_hosts", [])
        or config.get("recon", {}).get("alive_hosts", [])
        or []
    )
    if hosts:
        return sorted(dict.fromkeys(str(item).strip() for item in hosts if str(item).strip()))

    alive_file = _httpx_dir(project_name, settings) / "alive_hosts.txt"
    if alive_file.exists():
        return [
            line.strip()
            for line in alive_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    return []


def _run_nuclei(
    project_name: str,
    params: dict[str, Any],
    log: LogWriter,
    settings: Settings,
) -> dict[str, Any]:
    targets = _list_param(params.get("targets")) or _load_alive_targets(project_name, settings)
    targets = sorted(dict.fromkeys(str(item).strip() for item in targets if str(item).strip()))
    if not targets:
        raise RuntimeError("No alive HTTP targets found. Run httpx-root first.")

    severities = normalize_severities(params.get("severities"))
    out_dir = _nuclei_dir(project_name, settings)
    targets_file = out_dir / "targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")

    cmd = [
        "nuclei",
        "-l",
        str(targets_file),
        "-severity",
        severities,
        "-jsonl",
        "-silent",
    ]
    code, stdout = _run_command(cmd, log, settings)
    if code != 0:
        raise RuntimeError(f"nuclei failed with exit code {code}")

    raw_data: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_data.append(json.loads(line))
        except json.JSONDecodeError:
            log(f"Skipping non-JSON line from nuclei: {line[:160]}")

    findings = []
    for item in raw_data:
        info = item.get("info", {})
        findings.append(
            {
                "template_id": item.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "host": item.get("host"),
                "matched_at": item.get("matched-at"),
                "description": info.get("description", ""),
                "references": info.get("reference", []),
            }
        )

    (out_dir / "nuclei_raw.json").write_text(
        json.dumps(raw_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "findings.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(findings),
                "findings": findings,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return {"targets": len(targets), "findings": len(findings), "output": str(out_dir)}
