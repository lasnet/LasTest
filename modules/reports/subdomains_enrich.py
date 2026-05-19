#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console

from core.project_context import project_context
from core.user_config import get_api, load_user_config

try:
    import dns.exception
    import dns.resolver
except ImportError as e:
    raise RuntimeError(
        "Missing dependency: dnspython. Install with: pip install dnspython"
    ) from e


console = Console()

DEFAULT_HTTPX_PATHS = [
    "httpx",
    "/root/go/bin/httpx",
    "/usr/local/bin/httpx",
    "/usr/bin/httpx",
]

MAIL_HOST_MARKERS = [
    "mail",
    "smtp",
    "imap",
    "pop",
    "owa",
    "exchange",
    "mx",
]

TILDA_NS_SUFFIXES = [
    "tildadns.com",
]

SHARED_HOSTING_PATTERNS = {
    "hosting_beget": {
        "ns_suffixes": ["beget.com", "beget.pro", "beget.ru", "beget.de"],
        "blob_tokens": ["beget"],
    },
    "hosting_timeweb": {
        "ns_suffixes": ["timeweb.ru", "timeweb.org"],
        "blob_tokens": ["timeweb"],
    },
    "hosting_reg_ru": {
        "ns_suffixes": ["hosting.reg.ru"],
        "blob_tokens": ["hosting.reg.ru"],
    },
}

DEFAULT_IPDETAILS_URL_TEMPLATES = [
    "https://api.ipdetails.io/?ip={ip}",
    "https://api.ipdetails.io/{ip}",
    "https://api.ipdetails.io/ip/{ip}",
    "https://ipdetails.io/{ip}",
]


def _report_dir() -> Path:
    path = project_context.path / "reports" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _nmap_dir() -> Path:
    return project_context.path / "recon" / "nmap"


def _ip_intel_cache_dir(provider: str) -> Path:
    path = _report_dir() / "ip_intel_cache" / provider
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_scope_domains() -> List[str]:
    domains = project_context.get("scope", "domains", default=[])
    return normalize_domains(domains if domains else [])


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def list_to_sorted_unique(values: List[str]) -> List[str]:
    return sorted(set(v.strip() for v in values if isinstance(v, str) and v.strip()))


def normalize_domains(domains: List[str]) -> List[str]:
    result: List[str] = []
    seen = set()

    for domain in domains:
        if not domain:
            continue
        value = str(domain).strip().lower().rstrip(".")
        if not value:
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def normalize_host_key(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def safe_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def normalize_open_ports(values: Any) -> List[int]:
    ports: List[int] = []
    seen = set()

    for value in values or []:
        try:
            port = int(value)
        except Exception:
            continue
        if port not in seen:
            seen.add(port)
            ports.append(port)

    return sorted(ports)


def load_open_ports_map() -> Dict[str, List[int]]:
    nmap_dir = _nmap_dir()
    if not nmap_dir.exists():
        return {}

    results: Dict[str, List[int]] = {}
    summary_path = nmap_dir / "open_ports_summary.json"
    summary_data = load_json_file(summary_path)

    if isinstance(summary_data, list):
        for item in summary_data:
            if not isinstance(item, dict):
                continue
            host_key = normalize_host_key(item.get("target"))
            if not host_key:
                continue
            results[host_key] = normalize_open_ports(item.get("open_ports"))

    for target_dir in nmap_dir.iterdir():
        if not target_dir.is_dir():
            continue

        per_target_path = target_dir / "open_ports.json"
        if not per_target_path.exists():
            continue

        payload = load_json_file(per_target_path)
        if not isinstance(payload, dict):
            continue

        host_key = normalize_host_key(payload.get("target") or target_dir.name)
        if not host_key:
            continue

        current = results.get(host_key, [])
        merged = normalize_open_ports(current + (payload.get("open_ports") or []))
        results[host_key] = merged

    return results


def load_domain_ip_snapshot() -> Dict[str, List[str]]:
    nmap_dir = _nmap_dir()
    snapshot_path = nmap_dir / "domain_ip_map.json"
    payload = load_json_file(snapshot_path)
    if not isinstance(payload, dict):
        return {}

    results: Dict[str, List[str]] = {}
    domains = payload.get("domains")
    if not isinstance(domains, dict):
        return {}

    for host, values in domains.items():
        host_key = normalize_host_key(host)
        if not host_key:
            continue
        ipv4s = [
            value
            for value in list_to_sorted_unique([str(item) for item in values or []])
            if is_valid_ipv4(value)
        ]
        results[host_key] = ipv4s

    return results


def load_open_ports_ip_map() -> Dict[str, List[int]]:
    nmap_dir = _nmap_dir()
    if not nmap_dir.exists():
        return {}

    results: Dict[str, List[int]] = {}
    summary_path = nmap_dir / "open_ports_ip_summary.json"
    summary_data = load_json_file(summary_path)

    if isinstance(summary_data, list):
        for item in summary_data:
            if not isinstance(item, dict):
                continue
            target = str(item.get("target") or "").strip()
            if not is_valid_ipv4(target):
                continue
            results[target] = normalize_open_ports(item.get("open_ports"))

    for target_dir in nmap_dir.iterdir():
        if not target_dir.is_dir():
            continue

        per_target_path = target_dir / "open_ports.json"
        if not per_target_path.exists():
            continue

        payload = load_json_file(per_target_path)
        if not isinstance(payload, dict):
            continue

        target = str(payload.get("target") or "").strip()
        target_type = str(payload.get("target_type") or "").strip().lower()
        if target_type and target_type != "ipv4":
            continue
        if not is_valid_ipv4(target):
            continue

        current = results.get(target, [])
        merged = normalize_open_ports(current + (payload.get("open_ports") or []))
        results[target] = merged

    return results


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False


def is_valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()).version == 4
    except Exception:
        return False


def cache_is_fresh(path: Path, max_age_seconds: int) -> bool:
    if not path.exists():
        return False
    try:
        age = datetime.now().timestamp() - path.stat().st_mtime
    except Exception:
        return False
    return age <= max_age_seconds


def load_cached_json(path: Path, max_age_seconds: int) -> Optional[Dict[str, Any]]:
    if not cache_is_fresh(path, max_age_seconds):
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    return data if isinstance(data, dict) else None


def save_cached_json(path: Path, data: Dict[str, Any]) -> None:
    safe_write_json(path, data)


def collect_unique_ips(
    dns_map: Dict[str, Dict[str, Any]],
    httpx_map: Dict[str, Dict[str, Any]],
) -> List[str]:
    output: List[str] = []
    seen = set()

    for dns_data in dns_map.values():
        for ip in (dns_data.get("a") or []) + (dns_data.get("aaaa") or []):
            value = str(ip).strip()
            if is_valid_ip(value) and value not in seen:
                seen.add(value)
                output.append(value)

    for httpx_data in httpx_map.values():
        for ip in httpx_data.get("ip") or []:
            value = str(ip).strip()
            if is_valid_ip(value) and value not in seen:
                seen.add(value)
                output.append(value)

    return output


def get_ipdetails_url_templates(conf: Dict[str, Any]) -> List[str]:
    configured_template = get_api(conf, "apis", "ipdetails", "url_template")
    if configured_template:
        return [str(configured_template)]
    return DEFAULT_IPDETAILS_URL_TEMPLATES[:]


def build_ipdetails_request(
    ip: str,
    conf: Dict[str, Any],
) -> List[tuple[str, Dict[str, str], Dict[str, str]]]:
    api_key = get_api(conf, "apis", "ipdetails", "api_key")
    auth_mode = str(
        get_api(
            conf,
            "apis",
            "ipdetails",
            "auth_mode",
            default="bearer" if api_key else "none",
        )
    ).lower()
    auth_header = str(
        get_api(conf, "apis", "ipdetails", "auth_header", default="Authorization")
    )
    auth_prefix = str(
        get_api(conf, "apis", "ipdetails", "auth_prefix", default="Bearer ")
    )
    auth_query_param = str(
        get_api(conf, "apis", "ipdetails", "auth_query_param", default="api_key")
    )

    requests_to_try: List[tuple[str, Dict[str, str], Dict[str, str]]] = []

    for template in get_ipdetails_url_templates(conf):
        try:
            url = str(template).format(ip=ip)
        except Exception:
            continue

        headers = {"accept": "application/json"}
        params: Dict[str, str] = {}

        if api_key:
            if auth_mode == "bearer":
                headers[auth_header] = f"{auth_prefix}{api_key}"
            elif auth_mode == "header":
                headers[auth_header] = api_key
            elif auth_mode == "query":
                params[auth_query_param] = api_key

        requests_to_try.append((url, headers, params))

    return requests_to_try


def fetch_ipdetails(
    ip: str,
    conf: Dict[str, Any],
    session: requests.Session,
    timeout: int = 8,
) -> Dict[str, Any]:
    cache_path = _ip_intel_cache_dir("ipdetails") / f"{ip}.json"
    cached = load_cached_json(cache_path, max_age_seconds=7 * 24 * 3600)
    if cached and cached.get("_error"):
        cached = load_cached_json(cache_path, max_age_seconds=3600)
    if cached is not None:
        return cached

    last_error = "no_request_attempted"
    for url, headers, params in build_ipdetails_request(ip, conf):
        try:
            response = session.get(url, headers=headers, params=params, timeout=timeout)
            content_type = str(response.headers.get("content-type") or "").lower()
            data: Dict[str, Any]
            if "json" in content_type:
                data = response.json()
            else:
                try:
                    data = response.json()
                except Exception:
                    data = {
                        "_error": True,
                        "_provider": "ipdetails",
                        "_status_code": response.status_code,
                        "_text": response.text[:500],
                    }

            if (
                response.ok
                and isinstance(data, dict)
                and (data.get("ip") or data.get("company") or data.get("abuse_contact"))
            ):
                payload = {
                    "_provider": "ipdetails",
                    "_url": url,
                    "_status_code": response.status_code,
                    **data,
                }
                save_cached_json(cache_path, payload)
                return payload

            last_error = f"status={response.status_code}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

    payload = {
        "_provider": "ipdetails",
        "_error": True,
        "_error_message": last_error,
    }
    save_cached_json(cache_path, payload)
    return payload


def normalize_ipdetails(raw: Dict[str, Any]) -> Dict[str, Any]:
    abuse = (
        raw.get("abuse_contact") if isinstance(raw.get("abuse_contact"), dict) else {}
    )

    company = raw.get("company")
    company_domain = raw.get("domain")
    asn_value = raw.get("ASN") or raw.get("asn")

    normalized = {
        "provider": "ipdetails",
        "ok": bool(
            isinstance(raw, dict)
            and not raw.get("_error")
            and (raw.get("ip") or company or abuse)
        ),
        "company": company,
        "company_domain": company_domain,
        "type": raw.get("type"),
        "network": raw.get("network"),
        "rir": raw.get("rir"),
        "asn": str(asn_value) if asn_value not in (None, "") else None,
        "asname": raw.get("as_name") or raw.get("asname"),
        "org": company,
        "isp": raw.get("isp"),
        "country": raw.get("country")
        or raw.get("country_name")
        or raw.get("country_code"),
        "city": raw.get("city"),
        "hosting": str(raw.get("type") or "").lower() == "hosting",
        "proxy": raw.get("proxy"),
        "reverse": raw.get("reverse"),
        "abuse_name": abuse.get("name"),
        "abuse_email": abuse.get("email"),
        "abuse_phone": abuse.get("phone"),
        "abuse_address": abuse.get("address"),
        "abuser_score": raw.get("abuser_score"),
        "raw": raw,
    }
    return normalized


def fetch_ip_api(
    ip: str, session: requests.Session, timeout: int = 8
) -> Dict[str, Any]:
    cache_path = _ip_intel_cache_dir("ip_api") / f"{ip}.json"
    cached = load_cached_json(cache_path, max_age_seconds=24 * 3600)
    if cached and cached.get("_error"):
        cached = load_cached_json(cache_path, max_age_seconds=3600)
    if cached is not None:
        return cached

    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,query,country,city,org,isp,as,asname,reverse,proxy,hosting"
    )

    try:
        response = session.get(url, timeout=timeout)
        data = response.json() if response.content else {}
    except Exception as exc:
        payload = {
            "_provider": "ip-api",
            "_error": True,
            "_error_message": f"{type(exc).__name__}: {exc}",
        }
        save_cached_json(cache_path, payload)
        return payload

    if response.status_code == 429:
        payload = {
            "_provider": "ip-api",
            "_error": True,
            "_error_message": "rate_limited",
            "_status_code": response.status_code,
            "_headers": {
                "X-Rl": response.headers.get("X-Rl"),
                "X-Ttl": response.headers.get("X-Ttl"),
            },
        }
        save_cached_json(cache_path, payload)
        return payload

    if not isinstance(data, dict):
        data = {"_error": True, "_text": str(data)}

    payload = {
        "_provider": "ip-api",
        "_status_code": response.status_code,
        **data,
    }
    save_cached_json(cache_path, payload)
    return payload


def normalize_ip_api(raw: Dict[str, Any]) -> Dict[str, Any]:
    success = isinstance(raw, dict) and raw.get("status") == "success"
    as_value = raw.get("as")

    return {
        "provider": "ip-api",
        "ok": success,
        "company": None,
        "company_domain": None,
        "type": "hosting" if raw.get("hosting") else None,
        "network": None,
        "rir": None,
        "asn": str(as_value) if as_value not in (None, "") else None,
        "asname": raw.get("asname"),
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "country": raw.get("country"),
        "city": raw.get("city"),
        "hosting": bool(raw.get("hosting")),
        "proxy": raw.get("proxy"),
        "reverse": raw.get("reverse"),
        "abuse_name": None,
        "abuse_email": None,
        "abuse_phone": None,
        "abuse_address": None,
        "abuser_score": None,
        "raw": raw,
    }


def merge_ip_intel(
    ip: str,
    ipdetails_norm: Dict[str, Any],
    ip_api_norm: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ip_api_norm = ip_api_norm or {"provider": "ip-api", "ok": False, "raw": {}}

    provider_used = (
        "ipdetails"
        if ipdetails_norm.get("ok")
        else "ip-api"
        if ip_api_norm.get("ok")
        else "none"
    )
    fallback_used = not ipdetails_norm.get("ok") and bool(ip_api_norm.get("ok"))

    return {
        "ip": ip,
        "provider_used": provider_used,
        "fallback_used": fallback_used,
        "company": ipdetails_norm.get("company") or ip_api_norm.get("company"),
        "company_domain": ipdetails_norm.get("company_domain")
        or ip_api_norm.get("company_domain"),
        "type": ipdetails_norm.get("type") or ip_api_norm.get("type"),
        "network": ipdetails_norm.get("network") or ip_api_norm.get("network"),
        "rir": ipdetails_norm.get("rir") or ip_api_norm.get("rir"),
        "asn": ipdetails_norm.get("asn") or ip_api_norm.get("asn"),
        "asname": ipdetails_norm.get("asname") or ip_api_norm.get("asname"),
        "org": ipdetails_norm.get("org") or ip_api_norm.get("org"),
        "isp": ipdetails_norm.get("isp") or ip_api_norm.get("isp"),
        "country": ipdetails_norm.get("country") or ip_api_norm.get("country"),
        "city": ipdetails_norm.get("city") or ip_api_norm.get("city"),
        "hosting": (
            ipdetails_norm.get("hosting")
            if ipdetails_norm.get("hosting") is not None
            else ip_api_norm.get("hosting")
        ),
        "proxy": (
            ipdetails_norm.get("proxy")
            if ipdetails_norm.get("proxy") is not None
            else ip_api_norm.get("proxy")
        ),
        "reverse": ipdetails_norm.get("reverse") or ip_api_norm.get("reverse"),
        "abuse_name": ipdetails_norm.get("abuse_name") or ip_api_norm.get("abuse_name"),
        "abuse_email": ipdetails_norm.get("abuse_email")
        or ip_api_norm.get("abuse_email"),
        "abuse_phone": ipdetails_norm.get("abuse_phone")
        or ip_api_norm.get("abuse_phone"),
        "abuse_address": ipdetails_norm.get("abuse_address")
        or ip_api_norm.get("abuse_address"),
        "abuser_score": ipdetails_norm.get("abuser_score")
        or ip_api_norm.get("abuser_score"),
        "raw": {
            "ipdetails": ipdetails_norm.get("raw") or {},
            "ip_api": ip_api_norm.get("raw") or {},
        },
    }


def compact_ip_intel(ip_intel: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not ip_intel:
        return {}

    return {
        "ip": ip_intel.get("ip"),
        "provider_used": ip_intel.get("provider_used"),
        "fallback_used": ip_intel.get("fallback_used"),
        "company": ip_intel.get("company"),
        "company_domain": ip_intel.get("company_domain"),
        "type": ip_intel.get("type"),
        "network": ip_intel.get("network"),
        "rir": ip_intel.get("rir"),
        "asn": ip_intel.get("asn"),
        "asname": ip_intel.get("asname"),
        "org": ip_intel.get("org"),
        "isp": ip_intel.get("isp"),
        "country": ip_intel.get("country"),
        "city": ip_intel.get("city"),
        "hosting": ip_intel.get("hosting"),
        "proxy": ip_intel.get("proxy"),
        "reverse": ip_intel.get("reverse"),
        "abuse_name": ip_intel.get("abuse_name"),
        "abuse_email": ip_intel.get("abuse_email"),
        "abuse_phone": ip_intel.get("abuse_phone"),
        "abuse_address": ip_intel.get("abuse_address"),
        "abuser_score": ip_intel.get("abuser_score"),
    }


def build_ip_intel_map(
    unique_ips: List[str], conf: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    if not unique_ips:
        return {}

    session = requests.Session()
    results: Dict[str, Dict[str, Any]] = {}
    ipdetails_enabled = bool(
        get_api(conf, "apis", "ipdetails", "enabled", default=True)
    )
    ip_api_enabled = bool(get_api(conf, "apis", "ip_api", "enabled", default=True))

    try:
        for ip in unique_ips:
            ipdetails_raw: Dict[str, Any] = {
                "_provider": "ipdetails",
                "_error": True,
                "_error_message": "disabled",
            }
            ipdetails_norm: Dict[str, Any] = {
                "provider": "ipdetails",
                "ok": False,
                "raw": ipdetails_raw,
            }

            if ipdetails_enabled:
                ipdetails_raw = fetch_ipdetails(ip, conf, session=session)
                ipdetails_norm = normalize_ipdetails(ipdetails_raw)

            ip_api_norm: Optional[Dict[str, Any]] = None
            if ip_api_enabled and not ipdetails_norm.get("ok"):
                ip_api_raw = fetch_ip_api(ip, session=session)
                ip_api_norm = normalize_ip_api(ip_api_raw)

            results[ip] = merge_ip_intel(ip, ipdetails_norm, ip_api_norm)
    finally:
        session.close()

    return results


def select_primary_ip(
    all_ips: List[str], httpx_data: Dict[str, Any], dns_data: Dict[str, Any]
) -> Optional[str]:
    candidates = []
    candidates.extend(httpx_data.get("ip") or [])
    candidates.extend(dns_data.get("a") or [])
    candidates.extend(dns_data.get("aaaa") or [])

    for value in candidates:
        ip = str(value).strip()
        if is_valid_ip(ip):
            return ip

    return None


def detect_httpx_path() -> str:
    for candidate in DEFAULT_HTTPX_PATHS:
        resolved = shutil.which(candidate) if candidate == "httpx" else candidate
        if resolved and Path(resolved).exists():
            return resolved
    raise FileNotFoundError(
        "httpx binary not found. Checked: " + ", ".join(DEFAULT_HTTPX_PATHS)
    )


def detect_service_tags(
    host: str, httpx_data: Dict[str, Any], dns_data: Dict[str, Any]
) -> List[str]:
    tags = []
    host_lower = host.lower()

    keywords = {
        "admin": ["admin", "cpanel", "panel", "manage", "manager"],
        "vpn": ["vpn", "remote", "gateway", "gw", "rdp"],
        "mail": ["mail", "smtp", "imap", "pop", "owa", "exchange", "mx"],
        "api": ["api"],
        "dev": ["dev", "stage", "staging", "test", "qa", "uat", "preprod"],
        "auth": ["auth", "login", "sso", "oauth"],
        "web": ["www", "site", "portal", "lk", "cabinet"],
    }

    for tag, patterns in keywords.items():
        if any(p in host_lower for p in patterns):
            tags.append(tag)

    title = str(httpx_data.get("title") or "").lower()
    final_url = str(httpx_data.get("final_url") or "").lower()

    if "login" in title or "signin" in title or "login" in final_url:
        tags.append("login")

    if dns_data.get("mx"):
        tags.append("dns-mx-present")

    if dns_data.get("txt"):
        tags.append("dns-txt-present")

    return list_to_sorted_unique(tags)


def classify_asset(
    host: str, tags: List[str], httpx_data: Dict[str, Any], dns_data: Dict[str, Any]
) -> str:
    host_lower = host.lower()

    mail_host_markers = [
        "mail",
        "smtp",
        "imap",
        "pop",
        "owa",
        "exchange",
        "mx",
    ]

    if any(marker in host_lower for marker in mail_host_markers):
        return "mail"
    if "vpn" in tags:
        return "vpn"
    if "api" in tags:
        return "api"
    if httpx_data.get("alive"):
        return "web"
    return "unknown"


def calc_interest(host: str, tags: List[str], httpx_data: Dict[str, Any]) -> str:
    score = 0
    host_lower = host.lower()

    if httpx_data.get("alive"):
        score += 1

    if any(
        x in host_lower
        for x in [
            "admin",
            "vpn",
            "dev",
            "stage",
            "test",
            "api",
            "auth",
            "login",
            "mail",
        ]
    ):
        score += 2

    if httpx_data.get("status_code") in {200, 401, 403}:
        score += 1

    if httpx_data.get("tech"):
        score += 1

    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def contains_any(haystack: str, needles: List[str]) -> bool:
    value = str(haystack or "").lower()
    return any(needle in value for needle in needles)


def add_surface_evidence(
    evidence: List[str], label: str, values: List[str], limit: int = 2
) -> None:
    cleaned = list_to_sorted_unique(
        [str(value) for value in values if str(value).strip()]
    )
    for value in cleaned[:limit]:
        evidence.append(f"{label}={value}")


def detect_surface_profile(
    host: str,
    httpx_data: Dict[str, Any],
    dns_data: Dict[str, Any],
    tags: List[str],
    category: str,
    ip_intel_records: Optional[List[Dict[str, Any]]] = None,
) -> tuple[str, List[str]]:
    host_lower = host.lower()
    mail_like_host = (
        any(marker in host_lower for marker in MAIL_HOST_MARKERS) or category == "mail"
    )
    ip_intel_records = ip_intel_records or []

    ns_values = [str(x).lower().rstrip(".") for x in dns_data.get("ns") or []]
    mx_values = [str(x).lower().rstrip(".") for x in dns_data.get("mx") or []]
    cname_values = [str(x).lower().rstrip(".") for x in dns_data.get("cname") or []]
    txt_values = [str(x).lower() for x in dns_data.get("txt") or []]
    title = str(httpx_data.get("title") or "").lower()
    final_url = str(httpx_data.get("final_url") or "").lower()
    webserver = str(httpx_data.get("webserver") or "").lower()
    cdn_value = str(httpx_data.get("cdn") or "").lower()
    tech_values = [str(x).lower() for x in httpx_data.get("tech") or []]

    http_alive = bool(httpx_data.get("alive"))
    has_web_signal = http_alive or bool(title or final_url or tech_values or webserver)
    hosting_blob = " ".join(
        [
            title,
            final_url,
            webserver,
            " ".join(tech_values),
            " ".join(cname_values),
            " ".join(ns_values),
        ]
    )
    blob = " ".join(
        [
            title,
            final_url,
            webserver,
            cdn_value,
            " ".join(tech_values),
            " ".join(cname_values),
            " ".join(ns_values),
            " ".join(mx_values),
            " ".join(txt_values),
        ]
    )
    ip_type_values = [
        str(item.get("type") or "").lower()
        for item in ip_intel_records
        if item.get("type")
    ]
    ip_company_values = [
        str(item.get("company") or "").lower()
        for item in ip_intel_records
        if item.get("company")
    ]
    ip_company_domain_values = [
        str(item.get("company_domain") or "").lower()
        for item in ip_intel_records
        if item.get("company_domain")
    ]
    ip_org_values = [
        str(item.get("org") or "").lower()
        for item in ip_intel_records
        if item.get("org")
    ]
    ip_asname_values = [
        str(item.get("asname") or "").lower()
        for item in ip_intel_records
        if item.get("asname")
    ]
    ip_abuse_email_values = [
        str(item.get("abuse_email") or "").lower()
        for item in ip_intel_records
        if item.get("abuse_email")
    ]

    evidence: List[str] = []

    tilda_hits: List[str] = []
    if host_lower.endswith(".tilda.ws") or host_lower == "tilda.ws":
        tilda_hits.append(host_lower)
    tilda_hits.extend(
        [
            ns
            for ns in ns_values
            if any(ns.endswith(suffix) for suffix in TILDA_NS_SUFFIXES)
        ]
    )
    tilda_hits.extend([cname for cname in cname_values if "tilda.ws" in cname])
    if "tilda" in title or "made on tilda" in title or "tilda publishing" in title:
        tilda_hits.append(title)
    if "tilda" in final_url:
        tilda_hits.append(final_url)
    if any("tilda" in value for value in tech_values):
        tilda_hits.extend([value for value in tech_values if "tilda" in value])
    tilda_hits.extend([value for value in ip_company_values if "tilda" in value])
    tilda_hits.extend([value for value in ip_company_domain_values if "tilda" in value])
    tilda_hits.extend([value for value in ip_org_values if "tilda" in value])
    tilda_hits.extend([value for value in ip_asname_values if "tilda" in value])
    tilda_hits.extend(
        [
            value
            for value in ip_abuse_email_values
            if value.endswith("@tilda.com") or "tilda" in value
        ]
    )

    if tilda_hits:
        add_surface_evidence(evidence, "tilda", tilda_hits)
        return "site_builder_tilda", list_to_sorted_unique(evidence)

    google_mail_hits = [
        mx
        for mx in mx_values
        if mx == "smtp.google.com"
        or "aspmx.l.google.com" in mx
        or mx.endswith(".googlemail.com")
    ]
    if not google_mail_hits and contains_any(" ".join(txt_values), ["_spf.google.com"]):
        google_mail_hits.append("spf:_spf.google.com")

    microsoft_mail_hits = [
        mx for mx in mx_values if mx.endswith("mail.protection.outlook.com")
    ]
    if not microsoft_mail_hits and contains_any(
        " ".join(txt_values), ["spf.protection.outlook.com"]
    ):
        microsoft_mail_hits.append("spf:spf.protection.outlook.com")

    yandex_mail_mx_hits = [
        mx
        for mx in mx_values
        if mx in {"mx.yandex.net", "mx.yandex.ru"}
        or mx.endswith(".mx.yandex.net")
        or mx.endswith(".mx.yandex.ru")
    ]
    yandex_mail_cname_hits = [
        cname
        for cname in cname_values
        if "domain.mail.yandex.net" in cname or "domain.mail.yandex.ru" in cname
    ]
    yandex_mail_misc_hits: List[str] = []
    if not (yandex_mail_mx_hits or yandex_mail_cname_hits) and contains_any(
        blob, ["mail.yandex", "domain.mail.yandex"]
    ):
        yandex_mail_misc_hits.append("portal:yandex-mail")

    yandex_mail_hits = (
        yandex_mail_mx_hits + yandex_mail_cname_hits + yandex_mail_misc_hits
    )
    yandex_mail_hits.extend([value for value in ip_company_values if "yandex" in value])
    yandex_mail_hits.extend(
        [value for value in ip_company_domain_values if "yandex" in value]
    )
    yandex_mail_hits.extend([value for value in ip_org_values if "yandex" in value])
    yandex_mail_hits.extend(
        [value for value in ip_abuse_email_values if "yandex" in value]
    )

    google_mail_hits.extend([value for value in ip_company_values if "google" in value])
    google_mail_hits.extend(
        [value for value in ip_company_domain_values if "google" in value]
    )
    google_mail_hits.extend([value for value in ip_org_values if "google" in value])
    google_mail_hits.extend(
        [value for value in ip_abuse_email_values if "google" in value]
    )

    microsoft_mail_hits.extend(
        [value for value in ip_company_values if "microsoft" in value]
    )
    microsoft_mail_hits.extend(
        [
            value
            for value in ip_company_domain_values
            if "microsoft" in value or "outlook" in value
        ]
    )
    microsoft_mail_hits.extend(
        [value for value in ip_org_values if "microsoft" in value]
    )
    microsoft_mail_hits.extend(
        [
            value
            for value in ip_abuse_email_values
            if "microsoft" in value or "outlook" in value
        ]
    )

    if google_mail_hits and (mail_like_host or not has_web_signal):
        add_surface_evidence(evidence, "mx", google_mail_hits)
        return "third_party_mail_google_workspace", list_to_sorted_unique(evidence)

    if microsoft_mail_hits and (mail_like_host or not has_web_signal):
        add_surface_evidence(evidence, "mx", microsoft_mail_hits)
        return "third_party_mail_microsoft_365", list_to_sorted_unique(evidence)

    if yandex_mail_hits and (mail_like_host or not has_web_signal):
        add_surface_evidence(evidence, "mx", yandex_mail_mx_hits)
        add_surface_evidence(evidence, "cname", yandex_mail_cname_hits)
        add_surface_evidence(evidence, "hint", yandex_mail_misc_hits)
        add_surface_evidence(
            evidence,
            "ip_org",
            [value for value in ip_org_values if "yandex" in value],
            limit=1,
        )
        add_surface_evidence(
            evidence,
            "abuse",
            [value for value in ip_abuse_email_values if "yandex" in value],
            limit=1,
        )
        return "third_party_mail_yandex_360", list_to_sorted_unique(evidence)

    cloudflare_hits: List[str] = []
    if "cloudflare" in cdn_value:
        cloudflare_hits.append(f"cdn:{cdn_value}")
    if "cloudflare" in webserver:
        cloudflare_hits.append(f"webserver:{webserver}")
    if any("cloudflare" in cname for cname in cname_values):
        cloudflare_hits.extend(
            [f"cname:{cname}" for cname in cname_values if "cloudflare" in cname]
        )
    if any(ns.endswith(".ns.cloudflare.com") for ns in ns_values):
        cloudflare_hits.extend(
            [f"ns:{ns}" for ns in ns_values if ns.endswith(".ns.cloudflare.com")]
        )
    cloudflare_hits.extend(
        [f"org:{value}" for value in ip_org_values if "cloudflare" in value]
    )
    cloudflare_hits.extend(
        [f"company:{value}" for value in ip_company_values if "cloudflare" in value]
    )
    cloudflare_hits.extend(
        [f"asname:{value}" for value in ip_asname_values if "cloudflare" in value]
    )

    if cloudflare_hits and (
        "cloudflare" in cdn_value
        or "cloudflare" in webserver
        or any("cname:" in hit for hit in cloudflare_hits)
    ):
        add_surface_evidence(evidence, "cloudflare", cloudflare_hits)
        return "cdn_fronted_cloudflare", list_to_sorted_unique(evidence)

    for profile_name, profile_data in SHARED_HOSTING_PATTERNS.items():
        provider_hits: List[str] = []
        provider_hits.extend(
            [
                ns
                for ns in ns_values
                if any(ns.endswith(suffix) for suffix in profile_data["ns_suffixes"])
            ]
        )
        provider_hits.extend(
            [token for token in profile_data["blob_tokens"] if token in hosting_blob]
        )
        provider_hits.extend(
            [
                value
                for value in ip_company_values
                if any(token in value for token in profile_data["blob_tokens"])
            ]
        )
        provider_hits.extend(
            [
                value
                for value in ip_company_domain_values
                if any(token in value for token in profile_data["blob_tokens"])
            ]
        )
        provider_hits.extend(
            [
                value
                for value in ip_org_values
                if any(token in value for token in profile_data["blob_tokens"])
            ]
        )
        provider_hits.extend(
            [
                value
                for value in ip_abuse_email_values
                if any(token in value for token in profile_data["blob_tokens"])
            ]
        )

        if provider_hits and not mail_like_host:
            add_surface_evidence(evidence, "provider", provider_hits)
            return profile_name, list_to_sorted_unique(evidence)

    if "hosting" in ip_type_values and not mail_like_host:
        add_surface_evidence(evidence, "ip_type", ["hosting"])
        add_surface_evidence(evidence, "company", ip_company_values, limit=1)
        add_surface_evidence(evidence, "abuse", ip_abuse_email_values, limit=1)
        return "shared_hosting_or_hosted_service", list_to_sorted_unique(evidence)

    if google_mail_hits:
        add_surface_evidence(evidence, "mx", google_mail_hits)
    if microsoft_mail_hits:
        add_surface_evidence(evidence, "mx", microsoft_mail_hits)
    if yandex_mail_mx_hits:
        add_surface_evidence(evidence, "mx", yandex_mail_mx_hits)
    if yandex_mail_cname_hits:
        add_surface_evidence(evidence, "cname", yandex_mail_cname_hits)
    if yandex_mail_misc_hits:
        add_surface_evidence(evidence, "hint", yandex_mail_misc_hits)
    if any(ns.endswith(".ns.cloudflare.com") for ns in ns_values):
        add_surface_evidence(
            evidence,
            "ns",
            [ns for ns in ns_values if ns.endswith(".ns.cloudflare.com")],
        )
    if ip_company_values:
        add_surface_evidence(evidence, "company", ip_company_values, limit=1)
    if ip_abuse_email_values:
        add_surface_evidence(evidence, "abuse", ip_abuse_email_values, limit=1)

    if dns_data.get("resolves") or http_alive:
        if http_alive:
            evidence.append(f"http_status={httpx_data.get('status_code')}")
        if dns_data.get("a"):
            add_surface_evidence(evidence, "a", dns_data.get("a") or [], limit=1)
        return "likely_first_party", list_to_sorted_unique(evidence)

    return "unknown", list_to_sorted_unique(evidence)


def query_dns_records(host: str, resolver: dns.resolver.Resolver) -> Dict[str, Any]:
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
                    txt_chunks = []
                    for item in rdata.strings:
                        try:
                            txt_chunks.append(item.decode("utf-8", errors="ignore"))
                        except Exception:
                            txt_chunks.append(str(item))
                    values.append("".join(txt_chunks))
                elif rtype == "NS":
                    values.append(str(rdata.target).rstrip("."))

            result[rtype.lower()] = list_to_sorted_unique(values)

        except dns.resolver.NXDOMAIN:
            result["errors"].append(f"{rtype}: NXDOMAIN")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            result["errors"].append(f"{rtype}: NoNameservers")
        except dns.exception.Timeout:
            result["errors"].append(f"{rtype}: Timeout")
        except Exception as e:
            result["errors"].append(f"{rtype}: {type(e).__name__}: {e}")

    if (
        result["a"]
        or result["aaaa"]
        or result["cname"]
        or result["mx"]
        or result["txt"]
        or result["ns"]
    ):
        result["resolves"] = True

    return result


def build_dns_resolver(
    timeout: float = 5.0, lifetime: float = 5.0
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def query_dns_records_default(
    host: str, timeout: float = 5.0, lifetime: float = 5.0
) -> Dict[str, Any]:
    return query_dns_records(
        host, build_dns_resolver(timeout=timeout, lifetime=lifetime)
    )


@lru_cache(maxsize=1)
def _httpx_supported_flags(httpx_path: str) -> set[str]:
    try:
        proc = subprocess.run(
            [httpx_path, "-h"], capture_output=True, text=True, check=False
        )
        help_txt = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return set()

    candidates = {
        "-json",
        "-follow-redirects",
        "-fr",
        "-status-code",
        "-title",
        "-tech-detect",
        "-td",
        "-content-type",
        "-server",
        "-web-server",
        "-ip",
        "-cdn",
        "-timeout",
    }
    return {flag for flag in candidates if flag in help_txt}


def _append_httpx_flag(cmd: List[str], supported: set[str], *flags: str) -> bool:
    for flag in flags:
        if flag in supported:
            cmd.append(flag)
            return True
    return False


def run_httpx(
    hosts: List[str], httpx_path: Optional[str] = None, timeout: int = 15
) -> Dict[str, Dict[str, Any]]:
    httpx_path = httpx_path or detect_httpx_path()
    results: Dict[str, Dict[str, Any]] = {}

    if not hosts:
        return results

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as temp_in:
        for host in hosts:
            temp_in.write(host + "\n")
        temp_input_path = temp_in.name

    try:
        supported = _httpx_supported_flags(httpx_path)
        cmd = [httpx_path, "-silent", "-l", temp_input_path]

        if "-json" not in supported:
            raise RuntimeError(
                "httpx does not support -json output required by reports module"
            )

        cmd.append("-json")
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

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if proc.returncode != 0:
            raise RuntimeError(
                f"httpx exited with code {proc.returncode}. "
                f"stderr: {stderr.strip() or 'empty'}"
            )

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            input_host = str(item.get("input") or "").strip().lower().rstrip(".")
            if not input_host:
                continue

            tech = item.get("tech") or []
            if not isinstance(tech, list):
                tech = [str(tech)]

            ip_value = item.get("ip")
            ip_list: List[str] = []
            if isinstance(ip_value, list):
                ip_list = [str(x) for x in ip_value if x]
            elif isinstance(ip_value, str) and ip_value.strip():
                ip_list = [ip_value.strip()]

            results[input_host] = {
                "alive": True,
                "url": item.get("url"),
                "final_url": item.get("location")
                or item.get("final-url")
                or item.get("url"),
                "scheme": item.get("scheme"),
                "port": item.get("port"),
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "tech": list_to_sorted_unique([str(x) for x in tech]),
                "webserver": item.get("webserver") or item.get("server"),
                "content_type": item.get("content_type"),
                "content_length": item.get("content_length"),
                "ip": list_to_sorted_unique(ip_list),
                "cdn": item.get("cdn"),
                "method": item.get("method"),
                "timestamp": utc_now_iso(),
            }

        for host in hosts:
            host_key = host.lower().rstrip(".")
            if host_key not in results:
                results[host_key] = {
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
                    "method": None,
                    "timestamp": utc_now_iso(),
                }

        return results

    finally:
        try:
            os.unlink(temp_input_path)
        except OSError:
            pass


def build_enriched_record(
    host: str,
    dns_data: Dict[str, Any],
    httpx_data: Dict[str, Any],
    ip_intel_map: Optional[Dict[str, Dict[str, Any]]] = None,
    open_ports_map: Optional[Dict[str, List[int]]] = None,
    open_ports_ip_map: Optional[Dict[str, List[int]]] = None,
    domain_ip_snapshot: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    ip_intel_map = ip_intel_map or {}
    open_ports_map = open_ports_map or {}
    open_ports_ip_map = open_ports_ip_map or {}
    domain_ip_snapshot = domain_ip_snapshot or {}
    tags = detect_service_tags(host, httpx_data, dns_data)
    category = classify_asset(host, tags, httpx_data, dns_data)
    interest = calc_interest(host, tags, httpx_data)
    host_key = normalize_host_key(host)

    all_ips = list_to_sorted_unique(
        (dns_data.get("a") or [])
        + (dns_data.get("aaaa") or [])
        + (httpx_data.get("ip") or [])
    )
    frozen_mapped_ips = [
        ip for ip in domain_ip_snapshot.get(host_key, []) or [] if is_valid_ipv4(ip)
    ]
    derived_mapped_ips = [
        ip for ip in list_to_sorted_unique(dns_data.get("a") or []) if is_valid_ipv4(ip)
    ]
    if not frozen_mapped_ips:
        derived_mapped_ips.extend(
            ip for ip in httpx_data.get("ip") or [] if is_valid_ipv4(str(ip))
        )
    mapped_ipv4s = list_to_sorted_unique(frozen_mapped_ips or derived_mapped_ips)
    host_open_ports_ip_map = {
        ip: normalize_open_ports(open_ports_ip_map.get(ip))
        for ip in mapped_ipv4s
        if normalize_open_ports(open_ports_ip_map.get(ip))
    }
    open_ports = sorted(
        {int(port) for ports in host_open_ports_ip_map.values() for port in ports}
    )
    if not open_ports:
        open_ports = open_ports_map.get(host_key, [])
    ip_intel_records = [ip_intel_map[ip] for ip in all_ips if ip in ip_intel_map]
    primary_ip = select_primary_ip(all_ips, httpx_data, dns_data)
    primary_ip_intel = (
        compact_ip_intel(ip_intel_map.get(primary_ip)) if primary_ip else {}
    )

    surface_profile, surface_evidence = detect_surface_profile(
        host=host,
        httpx_data=httpx_data,
        dns_data=dns_data,
        tags=tags,
        category=category,
        ip_intel_records=ip_intel_records,
    )

    provider_hint = None
    cname_values = " ".join(dns_data.get("cname") or []).lower()
    cdn_value = str(httpx_data.get("cdn") or "").lower()
    webserver = str(httpx_data.get("webserver") or "").lower()

    if (
        "cloudflare" in cname_values
        or "cloudflare" in cdn_value
        or "cloudflare" in webserver
    ):
        provider_hint = "cloudflare"
    elif "amazonaws.com" in cname_values:
        provider_hint = "aws"
    elif "azure" in cname_values:
        provider_hint = "azure"
    elif "google" in cname_values:
        provider_hint = "gcp"

    return {
        "host": host,
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
            "all_ips": all_ips,
            "ip_count": len(all_ips),
            "primary_ip": primary_ip,
            "mapped_ipv4s": mapped_ipv4s,
            "open_ports": open_ports,
            "open_ports_ip_map": host_open_ports_ip_map,
            "cdn_waf_detected": bool(httpx_data.get("cdn")),
            "provider_hint": provider_hint,
            "ip_intel_primary": primary_ip_intel,
            "ip_intel_all": [compact_ip_intel(item) for item in ip_intel_records],
        },
        "http": {
            "alive": httpx_data.get("alive", False),
            "url": httpx_data.get("url"),
            "final_url": httpx_data.get("final_url"),
            "scheme": httpx_data.get("scheme"),
            "port": httpx_data.get("port"),
            "status_code": httpx_data.get("status_code"),
            "title": httpx_data.get("title"),
            "content_type": httpx_data.get("content_type"),
            "content_length": httpx_data.get("content_length"),
            "webserver": httpx_data.get("webserver"),
            "tech": httpx_data.get("tech", []),
            "ip": httpx_data.get("ip", []),
            "cdn": httpx_data.get("cdn"),
            "method": httpx_data.get("method"),
            "checked_at": httpx_data.get("timestamp"),
        },
        "classification": {
            "category": category,
            "interest": interest,
            "tags": tags,
        },
        "surface": {
            "profile": surface_profile,
            "evidence": surface_evidence,
        },
        "notes": "",
    }


def build_summary(
    project_name: str, domains: List[str], items: List[Dict[str, Any]]
) -> Dict[str, Any]:
    total = len(items)
    dns_resolves = sum(1 for x in items if x["dns"]["resolves"])
    http_alive = sum(1 for x in items if x["http"]["alive"])
    with_cname = sum(1 for x in items if x["dns"]["cname"])
    with_mx = sum(1 for x in items if x["dns"]["mx"])
    with_txt = sum(1 for x in items if x["dns"]["txt"])
    with_cdn = sum(1 for x in items if x["network"]["cdn_waf_detected"])
    with_ip_intel = sum(1 for x in items if x["network"]["ip_intel_primary"])
    with_open_ports = sum(1 for x in items if x["network"]["open_ports"])
    high_interest = [
        x["host"] for x in items if x["classification"]["interest"] == "high"
    ]

    categories: Dict[str, int] = {}
    for x in items:
        category = x["classification"]["category"]
        categories[category] = categories.get(category, 0) + 1

    surface_profiles: Dict[str, int] = {}
    for x in items:
        profile = x["surface"]["profile"]
        surface_profiles[profile] = surface_profiles.get(profile, 0) + 1

    ip_intel_sources: Dict[str, int] = {}
    for x in items:
        source = (
            x["network"]["ip_intel_primary"].get("provider_used")
            if x["network"]["ip_intel_primary"]
            else None
        )
        if source:
            ip_intel_sources[source] = ip_intel_sources.get(source, 0) + 1

    return {
        "project_name": project_name,
        "generated_at": utc_now_iso(),
        "source": {
            "type": "project_context",
            "section": "scope.domains",
            "total_input_domains": len(domains),
        },
        "stats": {
            "total_domains": total,
            "dns_resolves": dns_resolves,
            "dns_not_resolve": total - dns_resolves,
            "http_alive": http_alive,
            "http_not_alive": total - http_alive,
            "with_cname": with_cname,
            "with_mx": with_mx,
            "with_txt": with_txt,
            "with_cdn_or_waf": with_cdn,
            "with_ip_intel": with_ip_intel,
            "with_open_ports": with_open_ports,
        },
        "categories": categories,
        "surface_profiles": surface_profiles,
        "ip_intel_sources": ip_intel_sources,
        "high_interest_hosts": high_interest,
    }


def write_csv_report(path: Path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "host",
        "dns_resolves",
        "a",
        "http_alive",
        "url",
        "status_code",
        "title",
        "webserver",
        "tech",
        "aaaa",
        "cname",
        "mx",
        "txt",
        "ns",
        #        "all_ips",
        #        "ip_count",
        #        "cdn_waf_detected",
        #        "provider_hint",
        #        "final_url",
        #        "scheme",
        #        "port",
        "content_type",
        "content_length",
        "primary_ip",
        "open_ports",
        "http_ip",
        "cdn",
        "ip_intel_source",
        "ip_type",
        "ip_company",
        "ip_company_domain",
        "ip_org",
        "ip_asn",
        "ip_asname",
        "ip_abuse_email",
        "ip_hosting",
        "ip_proxy",
        "ip_country",
        "ip_city",
        "surface_profile",
        "surface_evidence",
        "category",
        "interest",
        "tags",
        "notes",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()

        for item in items:
            primary_ip_intel = item["network"]["ip_intel_primary"] or {}
            writer.writerow(
                {
                    "host": item["host"],
                    "dns_resolves": item["dns"]["resolves"],
                    "a": ", ".join(item["dns"]["a"]),
                    "http_alive": item["http"]["alive"],
                    "url": item["http"]["url"] or "",
                    "status_code": item["http"]["status_code"] or "",
                    "title": item["http"]["title"] or "",
                    "webserver": item["http"]["webserver"] or "",
                    "tech": ", ".join(item["http"]["tech"]),
                    "aaaa": ", ".join(item["dns"]["aaaa"]),
                    "cname": ", ".join(item["dns"]["cname"]),
                    "mx": ", ".join(item["dns"]["mx"]),
                    "txt": " | ".join(item["dns"]["txt"]),
                    "ns": ", ".join(item["dns"]["ns"]),
                    #                "all_ips": ", ".join(item["network"]["all_ips"]),
                    #                "ip_count": item["network"]["ip_count"],
                    #                "cdn_waf_detected": item["network"]["cdn_waf_detected"],
                    #                "provider_hint": item["network"]["provider_hint"] or "",
                    #                "final_url": item["http"]["final_url"] or "",
                    #                "scheme": item["http"]["scheme"] or "",
                    #                "port": item["http"]["port"] or "",
                    "content_type": item["http"]["content_type"] or "",
                    "content_length": item["http"]["content_length"] or "",
                    "primary_ip": item["network"]["primary_ip"] or "",
                    "open_ports": ", ".join(
                        str(port) for port in item["network"]["open_ports"]
                    ),
                    "http_ip": ", ".join(item["http"]["ip"]),
                    "cdn": item["http"]["cdn"] or "",
                    "ip_intel_source": primary_ip_intel.get("provider_used") or "",
                    "ip_type": primary_ip_intel.get("type") or "",
                    "ip_company": primary_ip_intel.get("company") or "",
                    "ip_company_domain": primary_ip_intel.get("company_domain") or "",
                    "ip_org": primary_ip_intel.get("org") or "",
                    "ip_asn": primary_ip_intel.get("asn") or "",
                    "ip_asname": primary_ip_intel.get("asname") or "",
                    "ip_abuse_email": primary_ip_intel.get("abuse_email") or "",
                    "ip_hosting": primary_ip_intel.get("hosting")
                    if primary_ip_intel
                    else "",
                    "ip_proxy": primary_ip_intel.get("proxy")
                    if primary_ip_intel
                    else "",
                    "ip_country": primary_ip_intel.get("country") or "",
                    "ip_city": primary_ip_intel.get("city") or "",
                    "surface_profile": item["surface"]["profile"],
                    "surface_evidence": " | ".join(item["surface"]["evidence"]),
                    "category": item["classification"]["category"],
                    "interest": item["classification"]["interest"],
                    "tags": ", ".join(item["classification"]["tags"]),
                    "notes": item["notes"],
                }
            )


def enrich_domains(httpx_path: Optional[str] = None) -> Dict[str, Path]:
    project_name = project_context.path.name
    domains = get_scope_domains()
    conf = load_user_config()

    if not domains:
        raise ValueError("No domains found in scope.domains")

    output_dir = _report_dir()

    console.print(f"[*] Project: [bold]{project_name}[/bold]")
    console.print(f"[*] Domains in scope.domains: [bold]{len(domains)}[/bold]")

    dns_map: Dict[str, Dict[str, Any]] = {}
    max_workers = min(16, max(4, len(domains)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(query_dns_records_default, domain): domain
            for domain in domains
        }
        for future in as_completed(futures):
            domain = futures[future]
            console.print(f"[*] DNS enrich: {domain}")
            dns_map[domain] = future.result()

    console.print("[*] Running httpx...")
    httpx_map = run_httpx(domains, httpx_path=httpx_path)

    open_ports_map = load_open_ports_map()
    open_ports_ip_map = load_open_ports_ip_map()
    domain_ip_snapshot = load_domain_ip_snapshot()
    unique_ips = collect_unique_ips(dns_map, httpx_map)
    console.print(f"[*] IP intelligence candidates: [bold]{len(unique_ips)}[/bold]")
    ip_intel_map = build_ip_intel_map(unique_ips, conf)

    items: List[Dict[str, Any]] = []
    for domain in domains:
        items.append(
            build_enriched_record(
                host=domain,
                dns_data=dns_map.get(domain, {}),
                httpx_data=httpx_map.get(domain, {}),
                ip_intel_map=ip_intel_map,
                open_ports_map=open_ports_map,
                open_ports_ip_map=open_ports_ip_map,
                domain_ip_snapshot=domain_ip_snapshot,
            )
        )

    summary = build_summary(project_name, domains, items)

    enriched_path = output_dir / f"{project_name}_subdomains_enriched.json"
    summary_path = output_dir / f"{project_name}_summary.json"
    csv_path = output_dir / f"{project_name}_subdomains_report.csv"
    ip_intel_path = output_dir / f"{project_name}_ip_intel.json"

    enriched_json = {
        "meta": {
            "project_name": project_name,
            "generated_at": utc_now_iso(),
            "source": {
                "type": "project_context",
                "section": "scope.domains",
            },
            "artifacts": {
                "summary_json": str(summary_path),
                "report_csv": str(csv_path),
                "ip_intel_json": str(ip_intel_path),
            },
        },
        "items": items,
    }

    ip_intel_json = {
        "meta": {
            "project_name": project_name,
            "generated_at": utc_now_iso(),
            "provider_priority": ["ipdetails", "ip-api"],
            "unique_ip_count": len(unique_ips),
        },
        "ips": ip_intel_map,
    }

    safe_write_json(enriched_path, enriched_json)
    safe_write_json(summary_path, summary)
    safe_write_json(ip_intel_path, ip_intel_json)
    write_csv_report(csv_path, items)

    return {
        "subdomains_enriched_json": enriched_path,
        "summary_json": summary_path,
        "subdomains_report_csv": csv_path,
        "ip_intel_json": ip_intel_path,
    }


def run_subdomains_enrich_report() -> None:
    domains = get_scope_domains()
    if not domains:
        console.print("[red]Scope domains пуст.[/red]")
        return

    console.rule("[cyan]Subdomains enrich report[/cyan]")
    console.print(f"[yellow]Project:[/yellow] {project_context.path.name}")
    console.print(f"[yellow]Domains in scope:[/yellow] {len(domains)}")

    try:
        result = enrich_domains()

        console.print("[green][+][/green] Report generated successfully")
        console.print(f"[green][+][/green] JSON: {result['subdomains_enriched_json']}")
        console.print(f"[green][+][/green] SUMMARY: {result['summary_json']}")
        console.print(f"[green][+][/green] CSV: {result['subdomains_report_csv']}")
        console.print(f"[green][+][/green] IP INTEL: {result['ip_intel_json']}")

    except Exception as e:
        console.print(f"[red][!][/red] Report generation failed: {e}")
