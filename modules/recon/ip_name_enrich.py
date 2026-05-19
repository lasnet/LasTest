from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from rich.console import Console

from core.project_context import project_context

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None


console = Console()

IP_NAME_SOURCE_MARKERS = (
    "hakrevdns_ptr",
    "reverse_ip",
)

DEFAULT_HTTPX_PATHS = [
    "httpx",
    "/root/go/bin/httpx",
    "/usr/local/bin/httpx",
    "/usr/bin/httpx",
]

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)

PROVIDER_SUFFIXES = (
    "amazonaws.com",
    "cloudfront.net",
    "akamaiedge.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "azureedge.net",
    "trafficmanager.net",
    "cloudflare.net",
    "workers.dev",
    "herokudns.com",
    "github.io",
    "netlify.app",
    "vercel.app",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _recon_dir() -> Path:
    path = project_context.path / "recon" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _subdomains_json() -> Path:
    return _recon_dir() / "subdomains.json"


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _list_to_sorted_unique(values: list[str]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _normalize_host(value: str) -> str | None:
    if not value:
        return None

    host = str(value).strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]

    if not host or " " in host or "\t" in host or "\n" in host:
        return None

    if _is_ip(host):
        return None

    if not DOMAIN_RE.fullmatch(host):
        return None

    return host


def _get_scope_ips() -> list[str]:
    raw_ips = project_context.get("scope", "ips", default=[]) or []
    cleaned = []
    for value in raw_ips:
        item = str(value).strip()
        if item:
            cleaned.append(item)
    return _dedupe_keep_order(cleaned)


def _is_ip_name_source(source_name: str) -> bool:
    source_name = str(source_name).strip().lower()
    return any(marker in source_name for marker in IP_NAME_SOURCE_MARKERS)


def _load_ip_name_candidates() -> dict[str, list[str]]:
    json_file = _subdomains_json()
    if not json_file.exists():
        return {}

    try:
        data = json.loads(json_file.read_text(encoding="utf-8"))
    except Exception:
        return {}

    source_map = data.get("sources", {})
    if not isinstance(source_map, dict):
        return {}

    candidates: dict[str, set[str]] = {}
    for source_name, hosts in source_map.items():
        if not _is_ip_name_source(source_name):
            continue
        if not isinstance(hosts, list):
            continue

        for host in hosts:
            normalized = _normalize_host(str(host))
            if not normalized:
                continue
            candidates.setdefault(normalized, set()).add(str(source_name))

    return {
        host: sorted(source_names)
        for host, source_names in sorted(candidates.items())
    }


def _build_dns_resolver(timeout: float = 4.0, lifetime: float = 4.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def _query_dns_records(host: str) -> dict[str, Any]:
    result = {
        "resolves": False,
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "txt": [],
        "ns": [],
        "errors": [],
    }

    if dns is None:
        result["errors"].append("dnspython not installed")
        return result

    resolver = _build_dns_resolver()
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(host, rtype, raise_on_no_answer=False)
            if answers is None:
                continue

            values = []
            for rdata in answers:
                if rtype == "A":
                    values.append(rdata.address)
                elif rtype == "AAAA":
                    values.append(rdata.address)
                elif rtype == "CNAME":
                    values.append(str(rdata.target).rstrip("."))
                elif rtype == "MX":
                    values.append(str(rdata.exchange).rstrip("."))
                elif rtype == "TXT":
                    txt_parts = []
                    for chunk in getattr(rdata, "strings", []):
                        try:
                            txt_parts.append(chunk.decode("utf-8", errors="ignore"))
                        except Exception:
                            txt_parts.append(str(chunk))
                    values.append("".join(txt_parts))
                elif rtype == "NS":
                    values.append(str(rdata.target).rstrip("."))

            result[rtype.lower()] = _list_to_sorted_unique(values)
        except dns.resolver.NXDOMAIN:
            result["errors"].append(f"{rtype}: NXDOMAIN")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            result["errors"].append(f"{rtype}: NoNameservers")
        except dns.exception.Timeout:
            result["errors"].append(f"{rtype}: Timeout")
        except Exception as exc:
            result["errors"].append(f"{rtype}: {type(exc).__name__}: {exc}")

    if any(result[key] for key in ("a", "aaaa", "cname", "mx", "txt", "ns")):
        result["resolves"] = True

    return result


def _query_dns_batch(hosts: list[str], max_workers: int = 24) -> dict[str, dict[str, Any]]:
    if not hosts:
        return {}

    if dns is None:
        return {host: _query_dns_records(host) for host in hosts}

    results: dict[str, dict[str, Any]] = {}
    workers = min(max_workers, max(4, len(hosts)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_query_dns_records, host): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                results[host] = future.result()
            except Exception as exc:
                results[host] = {
                    "resolves": False,
                    "a": [],
                    "aaaa": [],
                    "cname": [],
                    "mx": [],
                    "txt": [],
                    "ns": [],
                    "errors": [f"internal: {type(exc).__name__}: {exc}"],
                }

    return results


def _detect_httpx_path() -> str | None:
    for candidate in DEFAULT_HTTPX_PATHS:
        resolved = shutil.which(candidate) if candidate == "httpx" else candidate
        if resolved and Path(resolved).exists():
            return str(resolved)
    return None


@lru_cache(maxsize=4)
def _httpx_supported_flags(httpx_path: str) -> set[str]:
    try:
        proc = subprocess.run([httpx_path, "-h"], capture_output=True, text=True, check=False)
        help_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return set()

    candidates = {
        "-json",
        "-follow-redirects", "-fr",
        "-status-code",
        "-title",
        "-tech-detect", "-td",
        "-content-type",
        "-server", "-web-server",
        "-ip",
        "-cdn",
        "-timeout",
    }
    return {flag for flag in candidates if flag in help_text}


def _append_httpx_flag(cmd: list[str], supported: set[str], *flags: str) -> bool:
    for flag in flags:
        if flag in supported:
            cmd.append(flag)
            return True
    return False


def _default_httpx_record() -> dict[str, Any]:
    return {
        "alive": False,
        "url": None,
        "final_url": None,
        "scheme": None,
        "port": None,
        "status_code": None,
        "title": None,
        "tech": [],
        "webserver": None,
        "content_type": None,
        "content_length": None,
        "ip": [],
        "cdn": None,
        "checked_at": _utc_now_iso(),
    }


def _run_httpx(hosts: list[str], timeout: int = 8) -> dict[str, dict[str, Any]]:
    httpx_path = _detect_httpx_path()
    if not httpx_path or not hosts:
        return {host: _default_httpx_record() for host in hosts}

    supported = _httpx_supported_flags(httpx_path)
    if "-json" not in supported:
        console.print("[yellow]httpx найден, но не поддерживает -json. HTTP enrich пропущен.[/yellow]")
        return {host: _default_httpx_record() for host in hosts}

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as temp_input:
        for host in hosts:
            temp_input.write(host + "\n")
        temp_input_path = temp_input.name

    results = {host: _default_httpx_record() for host in hosts}

    try:
        cmd = [httpx_path, "-silent", "-l", temp_input_path, "-json"]
        _append_httpx_flag(cmd, supported, "-follow-redirects", "-fr")
        _append_httpx_flag(cmd, supported, "-status-code")
        _append_httpx_flag(cmd, supported, "-title")
        _append_httpx_flag(cmd, supported, "-tech-detect", "-td")
        _append_httpx_flag(cmd, supported, "-content-type")
        _append_httpx_flag(cmd, supported, "-server", "-web-server")
        _append_httpx_flag(cmd, supported, "-ip")
        _append_httpx_flag(cmd, supported, "-cdn")

        if "-timeout" in supported:
            cmd.extend(["-timeout", str(timeout)])

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )

        if proc.returncode != 0:
            console.print("[yellow]httpx завершился с ошибкой. HTTP enrich пропущен.[/yellow]")
            stderr = (proc.stderr or "").strip()
            if stderr:
                console.print(f"[dim]{stderr}[/dim]")
            return results

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            input_host = _normalize_host(str(item.get("input") or ""))
            if not input_host:
                continue

            tech = item.get("tech") or []
            if not isinstance(tech, list):
                tech = [str(tech)]

            ip_value = item.get("ip")
            ip_list: list[str] = []
            if isinstance(ip_value, list):
                ip_list = [str(value).strip() for value in ip_value if str(value).strip()]
            elif isinstance(ip_value, str) and ip_value.strip():
                ip_list = [ip_value.strip()]

            results[input_host] = {
                "alive": True,
                "url": item.get("url"),
                "final_url": item.get("location") or item.get("final-url") or item.get("url"),
                "scheme": item.get("scheme"),
                "port": item.get("port"),
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "tech": _list_to_sorted_unique([str(value) for value in tech]),
                "webserver": item.get("webserver") or item.get("server"),
                "content_type": item.get("content_type"),
                "content_length": item.get("content_length"),
                "ip": _list_to_sorted_unique(ip_list),
                "cdn": item.get("cdn"),
                "checked_at": _utc_now_iso(),
            }

        return results
    finally:
        try:
            os.unlink(temp_input_path)
        except OSError:
            pass


def _detect_tags(host: str, dns_data: dict[str, Any], http_data: dict[str, Any]) -> list[str]:
    tags = []
    host_lower = host.lower()

    keyword_map = {
        "admin": ["admin", "cpanel", "panel", "manage", "manager"],
        "vpn": ["vpn", "remote", "gateway", "gw", "rdp"],
        "mail": ["mail", "smtp", "imap", "pop", "owa", "exchange", "mx"],
        "api": ["api"],
        "dev": ["dev", "stage", "staging", "test", "qa", "uat", "preprod"],
        "auth": ["auth", "login", "sso", "oauth"],
        "storage": ["cdn", "static", "assets", "files", "media"],
    }

    for tag, patterns in keyword_map.items():
        if any(pattern in host_lower for pattern in patterns):
            tags.append(tag)

    title = str(http_data.get("title") or "").lower()
    final_url = str(http_data.get("final_url") or "").lower()

    if "login" in title or "signin" in title or "login" in final_url:
        tags.append("login")

    if dns_data.get("mx"):
        tags.append("dns-mx-present")

    if dns_data.get("txt"):
        tags.append("dns-txt-present")

    if http_data.get("alive"):
        tags.append("http-alive")

    return _list_to_sorted_unique(tags)


def _provider_hint(host: str, dns_data: dict[str, Any], http_data: dict[str, Any]) -> str | None:
    values = [host]
    values.extend(dns_data.get("cname") or [])
    values.extend(http_data.get("ip") or [])
    values.append(str(http_data.get("cdn") or ""))
    values.append(str(http_data.get("webserver") or ""))

    blob = " ".join(str(value).lower() for value in values if value)
    if "cloudflare" in blob:
        return "cloudflare"
    if "amazonaws" in blob or "cloudfront" in blob:
        return "aws"
    if "azure" in blob:
        return "azure"
    if "google" in blob or "gcp" in blob:
        return "gcp"
    if "fastly" in blob:
        return "fastly"
    if "akamai" in blob or "edgekey" in blob or "edgesuite" in blob:
        return "akamai"
    return None


def _is_provider_like(host: str, dns_data: dict[str, Any], http_data: dict[str, Any]) -> bool:
    host_lower = host.lower()
    if any(host_lower.endswith(suffix) for suffix in PROVIDER_SUFFIXES):
        return True

    for cname in dns_data.get("cname") or []:
        cname_lower = str(cname).lower()
        if any(cname_lower.endswith(suffix) for suffix in PROVIDER_SUFFIXES):
            return True

    cdn_value = str(http_data.get("cdn") or "").lower()
    if cdn_value and cdn_value not in {"false", "none"}:
        return True

    return False


def _matched_scope_ips(
    dns_data: dict[str, Any],
    http_data: dict[str, Any],
    scope_ip_set: set[str],
) -> list[str]:
    combined = []
    combined.extend(dns_data.get("a") or [])
    combined.extend(dns_data.get("aaaa") or [])
    combined.extend(http_data.get("ip") or [])
    return sorted({ip for ip in combined if ip in scope_ip_set})


def _calc_confidence(
    source_names: list[str],
    dns_data: dict[str, Any],
    http_data: dict[str, Any],
    provider_like: bool,
    matched_scope_ips: list[str],
) -> str:
    source_count = len(source_names)
    resolves = bool(dns_data.get("resolves"))
    http_alive = bool(http_data.get("alive"))

    if matched_scope_ips and not provider_like:
        return "high"

    if matched_scope_ips and source_count >= 2:
        return "high"

    if source_count >= 2 and (resolves or http_alive) and not provider_like:
        return "medium"

    if matched_scope_ips or resolves or http_alive or dns_data.get("cname"):
        return "medium"

    return "low"


def _calc_interest(
    host: str,
    tags: list[str],
    http_data: dict[str, Any],
    matched_scope_ips: list[str],
    provider_like: bool,
    source_count: int,
) -> str:
    score = 0
    host_lower = host.lower()

    if matched_scope_ips:
        score += 2

    if http_data.get("alive"):
        score += 1

    if http_data.get("status_code") in {200, 401, 403}:
        score += 1

    if source_count >= 2:
        score += 1

    if any(tag in tags for tag in ("admin", "vpn", "auth", "login", "api", "dev")):
        score += 2

    if any(value in host_lower for value in ("admin", "vpn", "auth", "login", "api", "dev", "stage", "test")):
        score += 1

    if provider_like and not matched_scope_ips:
        score -= 1

    if score >= 5:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def _build_record(
    host: str,
    source_names: list[str],
    dns_data: dict[str, Any],
    http_data: dict[str, Any],
    scope_ip_set: set[str],
) -> dict[str, Any]:
    provider_like = _is_provider_like(host, dns_data, http_data)
    provider_hint = _provider_hint(host, dns_data, http_data)
    matched_scope_ips = _matched_scope_ips(dns_data, http_data, scope_ip_set)
    tags = _detect_tags(host, dns_data, http_data)

    if provider_like:
        tags.append("provider-like")
    if matched_scope_ips:
        tags.append("scope-ip-match")
    if len(source_names) >= 2:
        tags.append("multi-source")

    tags = _list_to_sorted_unique(tags)
    confidence = _calc_confidence(
        source_names=source_names,
        dns_data=dns_data,
        http_data=http_data,
        provider_like=provider_like,
        matched_scope_ips=matched_scope_ips,
    )
    interest = _calc_interest(
        host=host,
        tags=tags,
        http_data=http_data,
        matched_scope_ips=matched_scope_ips,
        provider_like=provider_like,
        source_count=len(source_names),
    )

    return {
        "host": host,
        "sources": source_names,
        "source_count": len(source_names),
        "dns": {
            "resolves": dns_data.get("resolves", False),
            "a": dns_data.get("a", []),
            "aaaa": dns_data.get("aaaa", []),
            "cname": dns_data.get("cname", []),
            "mx": dns_data.get("mx", []),
            "txt": dns_data.get("txt", []),
            "ns": dns_data.get("ns", []),
            "errors": dns_data.get("errors", []),
        },
        "network": {
            "dns_ips": _list_to_sorted_unique((dns_data.get("a") or []) + (dns_data.get("aaaa") or [])),
            "http_ips": http_data.get("ip", []),
            "matched_scope_ips": matched_scope_ips,
            "has_exact_scope_ip_match": bool(matched_scope_ips),
            "provider_like": provider_like,
            "provider_hint": provider_hint,
        },
        "http": {
            "alive": http_data.get("alive", False),
            "url": http_data.get("url"),
            "final_url": http_data.get("final_url"),
            "scheme": http_data.get("scheme"),
            "port": http_data.get("port"),
            "status_code": http_data.get("status_code"),
            "title": http_data.get("title"),
            "content_type": http_data.get("content_type"),
            "content_length": http_data.get("content_length"),
            "webserver": http_data.get("webserver"),
            "tech": http_data.get("tech", []),
            "ip": http_data.get("ip", []),
            "cdn": http_data.get("cdn"),
            "checked_at": http_data.get("checked_at"),
        },
        "classification": {
            "confidence": confidence,
            "interest": interest,
            "tags": tags,
        },
        "notes": "",
    }


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_csv(path: Path, items: list[dict[str, Any]]) -> None:
    fieldnames = [
        "host",
        "sources",
        "source_count",
        "matched_scope_ips",
        "confidence",
        "interest",
        "provider_like",
        "provider_hint",
        "dns_resolves",
        "dns_a",
        "dns_aaaa",
        "cname",
        "http_alive",
        "url",
        "status_code",
        "title",
        "tech",
        "http_ip",
    ]

    with path.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()

        for item in items:
            writer.writerow(
                {
                    "host": item["host"],
                    "sources": ",".join(item["sources"]),
                    "source_count": item["source_count"],
                    "matched_scope_ips": ",".join(item["network"]["matched_scope_ips"]),
                    "confidence": item["classification"]["confidence"],
                    "interest": item["classification"]["interest"],
                    "provider_like": item["network"]["provider_like"],
                    "provider_hint": item["network"]["provider_hint"] or "",
                    "dns_resolves": item["dns"]["resolves"],
                    "dns_a": ",".join(item["dns"]["a"]),
                    "dns_aaaa": ",".join(item["dns"]["aaaa"]),
                    "cname": ",".join(item["dns"]["cname"]),
                    "http_alive": item["http"]["alive"],
                    "url": item["http"]["url"] or "",
                    "status_code": item["http"]["status_code"] or "",
                    "title": item["http"]["title"] or "",
                    "tech": ",".join(item["http"]["tech"]),
                    "http_ip": ",".join(item["http"]["ip"]),
                }
            )


def _build_summary(
    scope_ips: list[str],
    candidate_sources: dict[str, list[str]],
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    source_counts: dict[str, int] = {}
    for source_names in candidate_sources.values():
        for source_name in source_names:
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

    exact_match_hosts = [
        item["host"] for item in items if item["network"]["has_exact_scope_ip_match"]
    ]
    high_confidence_hosts = [
        item["host"] for item in items if item["classification"]["confidence"] == "high"
    ]
    high_interest_hosts = [
        item["host"] for item in items if item["classification"]["interest"] == "high"
    ]

    return {
        "generated_at": _utc_now_iso(),
        "scope_ip_count": len(scope_ips),
        "candidate_count": len(candidate_sources),
        "source_counts": source_counts,
        "stats": {
            "dns_resolves": sum(1 for item in items if item["dns"]["resolves"]),
            "http_alive": sum(1 for item in items if item["http"]["alive"]),
            "exact_scope_ip_match": len(exact_match_hosts),
            "provider_like": sum(1 for item in items if item["network"]["provider_like"]),
            "high_confidence": len(high_confidence_hosts),
            "high_interest": len(high_interest_hosts),
        },
        "exact_scope_ip_match_hosts": sorted(exact_match_hosts),
        "high_confidence_hosts": sorted(high_confidence_hosts),
        "high_interest_hosts": sorted(high_interest_hosts),
    }


def _priority_hosts(items: list[dict[str, Any]]) -> list[str]:
    output = []
    seen = set()
    for item in items:
        if item["network"]["has_exact_scope_ip_match"]:
            if item["host"] not in seen:
                seen.add(item["host"])
                output.append(item["host"])
            continue
        if item["classification"]["confidence"] == "high":
            if item["host"] not in seen:
                seen.add(item["host"])
                output.append(item["host"])
            continue
        if item["classification"]["interest"] == "high":
            if item["host"] not in seen:
                seen.add(item["host"])
                output.append(item["host"])
            continue
    return output


def run_ip_name_enrich() -> None:
    candidates = _load_ip_name_candidates()
    if not candidates:
        console.print("[yellow]Нет кандидатов из PTR/reverse IP источников. Сначала запусти reverse DNS for IPs.[/yellow]")
        return

    scope_ips = _get_scope_ips()
    scope_ip_set = set(scope_ips)
    hosts = sorted(candidates.keys())
    out_dir = _recon_dir()

    console.rule("[cyan]IP name enrich[/cyan]")
    console.print(f"[green]Candidates:[/green] {len(hosts)}")
    console.print(f"[green]Scope IPs:[/green] {len(scope_ips)}")

    console.print("[cyan]Stage 1/3: DNS enrich[/cyan]")
    dns_results = _query_dns_batch(hosts)

    console.print("[cyan]Stage 2/3: HTTP enrich[/cyan]")
    http_results = _run_httpx(hosts)

    console.print("[cyan]Stage 3/3: build artifacts[/cyan]")
    items = []
    for host in hosts:
        dns_data = dns_results.get(host)
        if dns_data is None:
            dns_data = _query_dns_records(host)

        items.append(
            _build_record(
                host=host,
                source_names=candidates.get(host, []),
                dns_data=dns_data,
                http_data=http_results.get(host, _default_httpx_record()),
                scope_ip_set=scope_ip_set,
            )
        )

    items.sort(
        key=lambda item: (
            0 if item["classification"]["confidence"] == "high" else 1 if item["classification"]["confidence"] == "medium" else 2,
            0 if item["classification"]["interest"] == "high" else 1 if item["classification"]["interest"] == "medium" else 2,
            item["host"],
        )
    )

    summary = _build_summary(scope_ips, candidates, items)
    priority_hosts = _priority_hosts(items)

    report_json = out_dir / "ip_name_enrich.json"
    summary_json = out_dir / "ip_name_enrich_summary.json"
    report_csv = out_dir / "ip_name_enrich.csv"
    priority_txt = out_dir / "ip_name_enrich_priority.txt"

    _write_json(report_json, {"generated_at": _utc_now_iso(), "items": items})
    _write_json(summary_json, summary)
    _write_csv(report_csv, items)
    priority_txt.write_text("\n".join(priority_hosts) + ("\n" if priority_hosts else ""), encoding="utf-8")

    project_context.set(priority_hosts, "recon", "ip_name_enrich", "priority_hosts")
    project_context.set(summary.get("exact_scope_ip_match_hosts", []), "recon", "ip_name_enrich", "exact_scope_ip_match_hosts")

    console.print(f"[green]High confidence:[/green] {summary['stats']['high_confidence']}")
    console.print(f"[green]Exact scope IP match:[/green] {summary['stats']['exact_scope_ip_match']}")
    console.print(f"[green]HTTP alive:[/green] {summary['stats']['http_alive']}")
    console.print(f"[cyan]Report JSON:[/cyan] {report_json}")
    console.print(f"[cyan]Summary JSON:[/cyan] {summary_json}")
    console.print(f"[cyan]CSV:[/cyan] {report_csv}")
    console.print(f"[cyan]Priority hosts:[/cyan] {priority_txt}")
