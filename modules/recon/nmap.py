import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt

from core.project_context import project_context
from core.utils import require_project
from modules.recon.proxy_pool import (
    ProxySelector,
    check_proxy_pool,
    load_alive_proxies,
    load_proxy_settings,
    proxy_config_path,
)

try:
    import nmap
except ImportError:
    nmap = None

console = Console()

POPULAR_TCP_PORTS = (
    """
80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1049,1048,2967,1053,3703,1056,1065,1064,1054,17,808,3689,1031,1044,1071,5901,100,9102,8010,2869,1039,5120,4001,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1993,1761,5003,2002,2005,1998,1032,1050,6112,3690,1521,2161,6002,1080,2401,4045,902,7937,787,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,593,2301,3,1,3268,7938,1234,1022,1074,8002,1036,1035,9001,1037,464,497,1935,6666,2003,6543,1352,24,3269,1111,407,500,20,2006,3260,15000,1218,1034,4444,264,2004,33,1042,42510,999,3052,1023,1068,222,7100,888,4827,1999,563,1717,2008,992,32770,32772,7001,8082,2007,740,5550,2009,5801,1043,512,2701,7019,50001,1700,4662,2065,2010,42,9535,2602,3333,161,5100,5002,2604,4002,6059,1047,8192,8193,2702,6789,9595,1051,9594,9593,16993,16992,5226,5225,32769,3283,1052,8194,1055,1062,9415,8701,8652,8651,8089,65389,65000,64680,64623,55600,55555,52869,35500,33354,23502,20828,1311,1060,4443,730,731,709,1067,13782,5902,366,9050,1002,85,5500,5431,1864,1863,8085,51103,49999,45100,10243,49,3495,6667,90,475,27000,1503,6881,1500,8021,340,78,5566,8088,2222
""".strip()
    .replace("\n", "")
    .replace(" ", "")
)


def _normalize_ports_csv(ports_csv: str) -> str:
    seen = set()
    ordered = []
    for item in str(ports_csv).split(","):
        port = item.strip()
        if not port or port in seen:
            continue
        seen.add(port)
        ordered.append(port)
    return ",".join(ordered)


POPULAR_TCP_PORTS = _normalize_ports_csv(POPULAR_TCP_PORTS)


def _recon_dir():
    path = project_context.path / "recon" / "nmap"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_scope_domains():
    domains = project_context.get("scope", "domains", default=[])
    return domains if domains else []


def _normalize_host_key(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _normalize_ipv4_value(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        return None

    if ip_obj.version != 4:
        return None
    return str(ip_obj)


def _get_scope_ipv4s() -> list[str]:
    ips = project_context.get("scope", "ips", default=[]) or []
    seen: set[str] = set()
    results: list[str] = []

    for value in ips:
        ip = _normalize_ipv4_value(value)
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results.append(ip)

    return results


def _resolve_domain_ipv4s(domain: str) -> list[str]:
    host = _normalize_host_key(domain)
    if not host:
        return []

    results: list[str] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    except Exception:
        return []

    for item in infos:
        sockaddr = item[4] if len(item) > 4 else None
        ip = None
        if isinstance(sockaddr, tuple) and sockaddr:
            ip = _normalize_ipv4_value(sockaddr[0])
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results.append(ip)

    return results


def _build_ipv4_scan_inventory(domains: list[str]) -> dict[str, Any]:
    selected_domains = [_normalize_host_key(domain) for domain in domains if domain]
    selected_domains = [domain for domain in selected_domains if domain]
    scope_ips = _get_scope_ipv4s()

    domain_map: dict[str, list[str]] = {}
    unresolved_domains: list[str] = []
    ip_targets: dict[str, dict[str, Any]] = {}
    unique_ipv4_targets: list[str] = []
    seen_ips: set[str] = set()

    def ensure_ip_target(ip: str, source: str, domain: str | None = None) -> None:
        meta = ip_targets.setdefault(
            ip,
            {
                "mapped_domains": [],
                "sources": [],
            },
        )
        if domain and domain not in meta["mapped_domains"]:
            meta["mapped_domains"].append(domain)
        if source not in meta["sources"]:
            meta["sources"].append(source)
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ipv4_targets.append(ip)

    for domain in selected_domains:
        ipv4s = _resolve_domain_ipv4s(domain)
        domain_map[domain] = ipv4s
        if not ipv4s:
            unresolved_domains.append(domain)
            continue
        for ip in ipv4s:
            ensure_ip_target(ip, "scope_domain_resolution", domain)

    for ip in scope_ips:
        ensure_ip_target(ip, "scope_ip")

    standalone_scope_ips = [
        ip
        for ip in scope_ips
        if "scope_domain_resolution" not in ip_targets.get(ip, {}).get("sources", [])
    ]

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "proxied_socks5_connect_ipv4_dedup",
        "selected_domains": selected_domains,
        "domains": domain_map,
        "unresolved_domains": unresolved_domains,
        "standalone_scope_ips": standalone_scope_ips,
        "unique_ipv4_targets": unique_ipv4_targets,
        "ip_targets": ip_targets,
    }


def _write_domain_ip_inventory(
    inventory: dict[str, Any],
) -> tuple[Path, Path]:
    json_path = _recon_dir() / "domain_ip_map.json"
    txt_path = _recon_dir() / "domain_ip_map.txt"

    json_path.write_text(
        json.dumps(_json_safe(inventory), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = []
    for domain in inventory.get("selected_domains", []):
        ips = inventory.get("domains", {}).get(domain, []) or []
        lines.append(f"{domain};{','.join(ips)}")

    standalone_scope_ips = inventory.get("standalone_scope_ips", []) or []
    if standalone_scope_ips:
        lines.append("")
        lines.append("# standalone_scope_ips")
        for ip in standalone_scope_ips:
            lines.append(f"{ip};scope_ip")

    unresolved_domains = inventory.get("unresolved_domains", []) or []
    if unresolved_domains:
        lines.append("")
        lines.append("# unresolved_domains")
        for domain in unresolved_domains:
            lines.append(f"{domain};")

    txt_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return json_path, txt_path


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _scan_files(scan_name: str):
    out_dir = _recon_dir()
    stamp = _ts()
    base = out_dir / f"{scan_name}_{stamp}"
    return (
        base.with_suffix(".json"),
        base.with_suffix(".txt"),
        base.parent / f"{base.name}_raw.txt",
    )


def _latest_nmap_artifacts() -> list[Path]:
    out_dir = _recon_dir()
    return sorted(
        [p for p in out_dir.rglob("*") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def _decode_bytes(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("utf-8", errors="replace")


def _process_output_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return _decode_bytes(value)
    return str(value)


def _json_safe(obj):
    if isinstance(obj, bytes):
        return _decode_bytes(obj)
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(x) for x in obj]
    if isinstance(obj, set):
        return [_json_safe(x) for x in obj]
    return obj


def _safe_str(s: str, limit: int = 240) -> str:
    if s is None:
        return ""
    s = str(s).replace("\r", " ").replace("\t", " ")
    s = "\n".join(line.strip() for line in s.splitlines() if line.strip())
    if len(s) > limit:
        return s[:limit] + "…"
    return s


def _safe_target_name(target: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target).strip().lower())
    value = value.strip("._-")
    return value or "target"


def _target_scan_dir(target: str) -> Path:
    path = _recon_dir() / _safe_target_name(target)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _find_proxychains_binary() -> str | None:
    for name in ("proxychains4", "proxychains", "proxychains-ng"):
        binary = shutil.which(name)
        if binary:
            return binary
    return None


def _find_nmap_binary() -> str | None:
    return shutil.which("nmap")


def _write_temp_proxychains_config(
    proxy: dict[str, Any],
    settings: dict[str, Any],
) -> Path:
    proxychains = settings["proxychains"]
    lines = [
        "strict_chain",
        "proxy_dns" if proxychains["proxy_dns"] else "# proxy_dns disabled",
        f"tcp_connect_time_out {proxychains['tcp_connect_time_out_ms']}",
        f"tcp_read_time_out {proxychains['tcp_read_time_out_ms']}",
        "[ProxyList]",
        f"socks5 {proxy['host']} {proxy['port']}",
    ]

    with tempfile.NamedTemporaryFile(
        "w", delete=False, encoding="utf-8", prefix="proxychains_", suffix=".conf"
    ) as tmp:
        tmp.write("\n".join(lines) + "\n")
        return Path(tmp.name)


def _build_proxied_nmap_command(
    proxychains_bin: str,
    proxychains_conf: Path,
    nmap_bin: str,
    ports: str,
    target: str,
    xml_path: Path,
) -> list[str]:
    return [
        proxychains_bin,
        "-f",
        str(proxychains_conf),
        nmap_bin,
        "-sT",
        "-n",
        "-T4",
        "-Pn",
        "--max-retries",  # Max number of port scan probe retransmissions
        "0",
        "--max-rtt-timeout",  # Max time for scan to wait for a response
        "2s",
        "-p",
        ports,
        "-oX",
        str(xml_path),
        target,
    ]


def _is_retryable_proxy_error(
    return_code: int | None, stdout: str, stderr: str
) -> bool:
    stdout_lower = stdout.lower()
    if "nmap scan report for" in stdout_lower and "nmap done:" in stdout_lower:
        return False

    if _stderr_has_target_hits(stderr):
        return False

    text = f"{stdout}\n{stderr}".lower()
    keywords = [
        "need more proxies",
        "general socks server failure",
        "connection not allowed by ruleset",
        "network unreachable",
        "network is unreachable",
        "host unreachable",
        "connection refused",
        "address type not supported",
        "no valid proxy",
        "proxy error",
        "proxy refused connection",
    ]

    if any(keyword in text for keyword in keywords):
        return True

    return bool(
        return_code not in (None, 0)
        and ("proxychains" in text or "socks5" in text or "socks" in text)
    )


def _stderr_has_target_hits(stderr: str) -> bool:
    pattern = re.compile(
        r"strict chain\s+\.\.\.\s+\d{1,3}(?:\.\d{1,3}){3}:\d+\s+"
        r"\.\.\.\s+\d{1,3}(?:\.\d{1,3}){3}:\d+",
        re.IGNORECASE,
    )
    return bool(pattern.search(stderr or ""))


def _stderr_has_broken_proxy_timeout(stderr: str) -> bool:
    pattern = re.compile(
        r"strict chain\s+\.\.\.\s+\d{1,3}(?:\.\d{1,3}){3}:\d+\s+\.\.\.\s+timeout\b",
        re.IGNORECASE,
    )
    return bool(pattern.search(stderr or ""))


def _merge_ports_status(base: dict[str, str], update: dict[str, str]) -> dict[str, str]:
    severity = {
        "open": 5,
        "open|filtered": 4,
        "filtered": 3,
        "unfiltered": 2,
        "closed": 1,
    }

    merged = dict(base)
    for port, state in update.items():
        current = merged.get(port)
        if current is None:
            merged[port] = state
            continue

        if severity.get(state, 0) >= severity.get(current, 0):
            merged[port] = state

    return merged


def _parse_ports_status_from_xml(xml_path: Path) -> dict[str, str]:
    if not xml_path.exists():
        return {}

    try:
        xml_text = xml_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    if not xml_text.strip():
        return {}

    ports_status: dict[str, str] = {}
    pattern = re.compile(
        r'<port\b[^>]*portid="(?P<port>\d+)"[^>]*>.*?'
        r'<state\b[^>]*state="(?P<state>[^"]+)"',
        re.IGNORECASE | re.DOTALL,
    )

    for match in pattern.finditer(xml_text):
        ports_status[match.group("port")] = match.group("state")

    return ports_status


def _parse_ports_status_from_stdout(stdout_text: str) -> dict[str, str]:
    ports_status: dict[str, str] = {}
    pattern = re.compile(
        r"^\s*(?P<port>\d+)/tcp\s+(?P<state>\S+)\s+(?P<service>\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(stdout_text or ""):
        ports_status[match.group("port")] = match.group("state")
    return ports_status


def _parse_open_ports_from_proxychains_stderr(stderr_text: str) -> dict[str, str]:
    ports_status: dict[str, str] = {}
    pattern = re.compile(
        r"strict chain\s+\.\.\.\s+\d{1,3}(?:\.\d{1,3}){3}:\d+\s+"
        r"\.\.\.\s+\d{1,3}(?:\.\d{1,3}){3}:(?P<port>\d+)\s+\.\.\.\s+ok\b",
        re.IGNORECASE,
    )
    for match in pattern.finditer(stderr_text or ""):
        ports_status[match.group("port")] = "open"
    return ports_status


def _extract_open_ports(ports_status: dict[str, str]) -> list[int]:
    open_states = {"open", "open|filtered"}
    open_ports = []
    for port, state in (ports_status or {}).items():
        if state.lower() in open_states:
            try:
                open_ports.append(int(port))
            except ValueError:
                continue
    return sorted(set(open_ports))


def _build_open_port_votes(attempts: list[dict[str, Any]]) -> dict[str, int]:
    return _build_open_port_votes_filtered(attempts, excluded_attempt_ids=set())


def _build_open_port_votes_filtered(
    attempts: list[dict[str, Any]],
    excluded_attempt_ids: set[int],
) -> dict[str, int]:
    votes: dict[str, int] = {}
    for attempt in attempts:
        if attempt.get("status") != "ok":
            continue
        if int(attempt.get("attempt") or 0) in excluded_attempt_ids:
            continue

        attempt_ports = attempt.get("ports_status") or {}
        if not isinstance(attempt_ports, dict):
            continue

        for port, state in attempt_ports.items():
            if str(state).lower() not in {"open", "open|filtered"}:
                continue
            port_key = str(port)
            votes[port_key] = votes.get(port_key, 0) + 1

    return votes


def _count_open_ports_in_attempt(attempt: dict[str, Any]) -> int:
    ports_status = attempt.get("ports_status") or {}
    if not isinstance(ports_status, dict):
        return 0
    return len(_extract_open_ports(ports_status))


def _median_int(values: list[int]) -> int:
    if not values:
        return 0
    sorted_values = sorted(values)
    mid = len(sorted_values) // 2
    if len(sorted_values) % 2 == 1:
        return sorted_values[mid]
    return int((sorted_values[mid - 1] + sorted_values[mid]) / 2)


def _detect_suspicious_attempts(
    attempts: list[dict[str, Any]],
    total_ports: int,
) -> list[dict[str, Any]]:
    ok_attempts = [attempt for attempt in attempts if attempt.get("status") == "ok"]
    if not ok_attempts:
        return []

    counts = [_count_open_ports_in_attempt(attempt) for attempt in ok_attempts]
    baseline_count = _median_int(counts)
    absolute_threshold = max(80, int(total_ports * 0.25))
    relative_threshold = max(40, int(total_ports * 0.15))
    suspicious: list[dict[str, Any]] = []

    for attempt, open_count in zip(ok_attempts, counts):
        is_suspicious = False
        reasons: list[str] = []

        if open_count >= absolute_threshold:
            is_suspicious = True
            reasons.append(
                f"open_ports_count={open_count} exceeded absolute threshold "
                f"{absolute_threshold}"
            )

        if (
            baseline_count <= 20
            and open_count >= relative_threshold
            and open_count >= max(20, baseline_count * 3)
        ):
            is_suspicious = True
            reasons.append(
                f"open_ports_count={open_count} is disproportionate to baseline "
                f"{baseline_count}"
            )

        if not is_suspicious:
            continue

        proxy = attempt.get("proxy") or {}
        suspicious.append(
            {
                "attempt": attempt.get("attempt"),
                "proxy_id": proxy.get("id"),
                "proxy_host": proxy.get("host"),
                "proxy_port": proxy.get("port"),
                "open_ports_count": open_count,
                "baseline_open_ports_count": baseline_count,
                "reasons": reasons,
            }
        )

    return suspicious


def _get_open_port_confirmation_threshold(successful_attempts_required: int) -> int:
    return 3 if successful_attempts_required >= 6 else 2


def _classify_open_ports(
    port_votes: dict[str, int], min_confirmations: int = 2
) -> tuple[list[int], list[int]]:
    confirmed = []
    candidate = []

    for port, count in port_votes.items():
        try:
            port_num = int(port)
        except ValueError:
            continue

        if count >= min_confirmations:
            confirmed.append(port_num)
        elif count > 0:
            candidate.append(port_num)

    return sorted(set(confirmed)), sorted(set(candidate))


def _write_target_open_ports_artifacts(
    target_dir: Path,
    target: str,
    confirmed_open_ports: list[int],
    candidate_open_ports: list[int],
    port_votes: dict[str, int],
    min_confirmations: int = 2,
    *,
    target_type: str = "domain",
    target_source: str = "",
    mapped_domains: list[str] | None = None,
) -> tuple[Path, Path, Path, Path]:
    confirmed_payload = {
        "target": target,
        "target_type": target_type,
        "target_source": target_source,
        "mapped_domains": mapped_domains or [],
        "open_ports": confirmed_open_ports,
        "open_ports_count": len(confirmed_open_ports),
        "confirmation_threshold": min_confirmations,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    candidate_payload = {
        "target": target,
        "target_type": target_type,
        "target_source": target_source,
        "mapped_domains": mapped_domains or [],
        "candidate_open_ports": candidate_open_ports,
        "candidate_open_ports_count": len(candidate_open_ports),
        "confirmation_threshold": min_confirmations,
        "open_port_votes": port_votes,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    confirmed_json_path = target_dir / "open_ports.json"
    confirmed_txt_path = target_dir / "open_ports.txt"
    candidate_json_path = target_dir / "candidate_open_ports.json"
    candidate_txt_path = target_dir / "candidate_open_ports.txt"

    confirmed_json_path.write_text(
        json.dumps(confirmed_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    confirmed_txt_path.write_text(
        f"{target};{','.join(str(port) for port in confirmed_open_ports)}\n",
        encoding="utf-8",
    )
    candidate_json_path.write_text(
        json.dumps(candidate_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    candidate_txt_path.write_text(
        f"{target};{','.join(str(port) for port in candidate_open_ports)}\n",
        encoding="utf-8",
    )

    return (
        confirmed_json_path,
        confirmed_txt_path,
        candidate_json_path,
        candidate_txt_path,
    )


def _build_ip_summary_items(
    results: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    confirmed_items: list[dict[str, Any]] = []
    candidate_items: list[dict[str, Any]] = []

    for result in results:
        target = result.get("target", "")
        mapped_domains = result.get("mapped_domains", []) or []
        confirmed_open_ports = result.get("open_ports", []) or []
        candidate_open_ports = result.get("candidate_open_ports", []) or []

        confirmed_items.append(
            {
                "target": target,
                "target_type": "ipv4",
                "target_source": result.get("target_source", ""),
                "mapped_domains": mapped_domains,
                "status": result.get("status", ""),
                "open_ports": confirmed_open_ports,
                "open_ports_count": len(confirmed_open_ports),
                "suspicious_attempts_count": result.get("suspicious_attempts_count", 0),
            }
        )
        candidate_items.append(
            {
                "target": target,
                "target_type": "ipv4",
                "target_source": result.get("target_source", ""),
                "mapped_domains": mapped_domains,
                "status": result.get("status", ""),
                "candidate_open_ports": candidate_open_ports,
                "candidate_open_ports_count": len(candidate_open_ports),
                "open_port_votes": result.get("open_port_votes", {}),
                "suspicious_attempts_count": result.get("suspicious_attempts_count", 0),
            }
        )

    return confirmed_items, candidate_items


def _build_domain_summary_items(
    results: list[dict[str, Any]],
    inventory: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ip_result_map = {
        _normalize_host_key(result.get("target")): result
        for result in results
        if _normalize_host_key(result.get("target"))
    }

    confirmed_items: list[dict[str, Any]] = []
    candidate_items: list[dict[str, Any]] = []

    for domain in inventory.get("selected_domains", []):
        mapped_ips = inventory.get("domains", {}).get(domain, []) or []
        open_ports_ip_map: dict[str, list[int]] = {}
        candidate_ports_ip_map: dict[str, list[int]] = {}
        domain_status = "unresolved" if not mapped_ips else "failed"
        suspicious_attempts_count = 0

        for ip in mapped_ips:
            result = ip_result_map.get(_normalize_host_key(ip))
            if not result:
                continue

            confirmed_ports = result.get("open_ports", []) or []
            candidate_ports = result.get("candidate_open_ports", []) or []
            if confirmed_ports:
                open_ports_ip_map[ip] = confirmed_ports
            if candidate_ports:
                candidate_ports_ip_map[ip] = candidate_ports

            suspicious_attempts_count += int(
                result.get("suspicious_attempts_count", 0) or 0
            )

            result_status = str(result.get("status") or "").lower()
            if result_status == "ok":
                domain_status = "ok"
            elif result_status == "partial" and domain_status != "ok":
                domain_status = "partial"
            elif result_status in {"failed", "error"} and domain_status == "failed":
                domain_status = result_status

        confirmed_open_ports = sorted(
            {int(port) for ports in open_ports_ip_map.values() for port in ports}
        )
        candidate_open_ports = sorted(
            {
                int(port)
                for ports in candidate_ports_ip_map.values()
                for port in ports
                if int(port) not in confirmed_open_ports
            }
        )

        confirmed_items.append(
            {
                "target": domain,
                "target_type": "domain",
                "source": "derived_from_ip_summary",
                "status": domain_status,
                "mapped_ips": mapped_ips,
                "open_ports": confirmed_open_ports,
                "open_ports_count": len(confirmed_open_ports),
                "open_ports_ip_map": open_ports_ip_map,
                "suspicious_attempts_count": suspicious_attempts_count,
            }
        )
        candidate_items.append(
            {
                "target": domain,
                "target_type": "domain",
                "source": "derived_from_ip_summary",
                "status": domain_status,
                "mapped_ips": mapped_ips,
                "candidate_open_ports": candidate_open_ports,
                "candidate_open_ports_count": len(candidate_open_ports),
                "candidate_open_ports_ip_map": candidate_ports_ip_map,
                "suspicious_attempts_count": suspicious_attempts_count,
            }
        )

    return confirmed_items, candidate_items


def _write_summary_pair(
    *,
    confirmed_items: list[dict[str, Any]],
    candidate_items: list[dict[str, Any]],
    confirmed_json: Path,
    confirmed_txt: Path,
    candidate_json: Path,
    candidate_txt: Path,
    confirmed_key: str,
    candidate_key: str,
) -> tuple[Path, Path, Path, Path]:
    confirmed_lines = [
        f"{item.get('target', '')};{','.join(str(port) for port in item.get(confirmed_key, []) or [])}"
        for item in confirmed_items
    ]
    candidate_lines = [
        f"{item.get('target', '')};{','.join(str(port) for port in item.get(candidate_key, []) or [])}"
        for item in candidate_items
    ]

    confirmed_json.write_text(
        json.dumps(confirmed_items, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    confirmed_txt.write_text("\n".join(confirmed_lines) + "\n", encoding="utf-8")
    candidate_json.write_text(
        json.dumps(candidate_items, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    candidate_txt.write_text("\n".join(candidate_lines) + "\n", encoding="utf-8")

    return confirmed_json, confirmed_txt, candidate_json, candidate_txt


def _write_open_ports_ip_summary(
    results: list[dict[str, Any]],
) -> tuple[Path, Path, Path, Path]:
    confirmed_items, candidate_items = _build_ip_summary_items(results)

    confirmed_json = _recon_dir() / "open_ports_ip_summary.json"
    confirmed_txt = _recon_dir() / "open_ports_ip_summary.txt"
    candidate_json = _recon_dir() / "candidate_open_ports_ip_summary.json"
    candidate_txt = _recon_dir() / "candidate_open_ports_ip_summary.txt"

    confirmed_lines = []
    for item in confirmed_items:
        mapped_domains = ",".join(item.get("mapped_domains", []) or [])
        ports = ",".join(str(port) for port in item.get("open_ports", []) or [])
        confirmed_lines.append(f"{item.get('target', '')};{ports};{mapped_domains}")

    candidate_lines = []
    for item in candidate_items:
        mapped_domains = ",".join(item.get("mapped_domains", []) or [])
        ports = ",".join(
            str(port) for port in item.get("candidate_open_ports", []) or []
        )
        candidate_lines.append(f"{item.get('target', '')};{ports};{mapped_domains}")

    confirmed_json.write_text(
        json.dumps(confirmed_items, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    confirmed_txt.write_text("\n".join(confirmed_lines) + "\n", encoding="utf-8")
    candidate_json.write_text(
        json.dumps(candidate_items, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    candidate_txt.write_text("\n".join(candidate_lines) + "\n", encoding="utf-8")

    return (
        confirmed_json,
        confirmed_txt,
        candidate_json,
        candidate_txt,
    )


def _write_open_ports_summary(
    results: list[dict[str, Any]],
    inventory: dict[str, Any],
) -> tuple[Path, Path, Path, Path]:
    confirmed_items, candidate_items = _build_domain_summary_items(results, inventory)
    return _write_summary_pair(
        confirmed_items=confirmed_items,
        candidate_items=candidate_items,
        confirmed_json=_recon_dir() / "open_ports_summary.json",
        confirmed_txt=_recon_dir() / "open_ports_summary.txt",
        candidate_json=_recon_dir() / "candidate_open_ports_summary.json",
        candidate_txt=_recon_dir() / "candidate_open_ports_summary.txt",
        confirmed_key="open_ports",
        candidate_key="candidate_open_ports",
    )


def _append_attempt_log(
    sections: list[str],
    title: str,
    proxy: dict[str, Any],
    content: str,
) -> None:
    sections.append(title)
    sections.append(f"proxy={proxy['id']} {proxy['host']}:{proxy['port']}")
    sections.append(content or "")
    sections.append("\n" + ("=" * 120) + "\n")


def _run_proxied_attempt(
    *,
    attempt_no: int,
    target: str,
    ports: str,
    proxy: dict[str, Any],
    settings: dict[str, Any],
    proxychains_bin: str,
    nmap_bin: str,
    target_dir: Path,
    timeout_sec: float,
) -> dict[str, Any]:
    selected_proxy = {
        "id": proxy["id"],
        "type": proxy["type"],
        "host": proxy["host"],
        "port": proxy["port"],
    }

    proxychains_conf = _write_temp_proxychains_config(proxy, settings)
    attempt_xml_path = target_dir / f".scan_attempt_{attempt_no}.xml"
    if attempt_xml_path.exists():
        attempt_xml_path.unlink()

    command = _build_proxied_nmap_command(
        proxychains_bin=proxychains_bin,
        proxychains_conf=proxychains_conf,
        nmap_bin=nmap_bin,
        ports=ports,
        target=target,
        xml_path=attempt_xml_path,
    )

    attempt_started = datetime.now().isoformat(timespec="seconds")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )

        stdout_text = _process_output_to_text(result.stdout)
        stderr_text = _process_output_to_text(result.stderr)
        retryable = _is_retryable_proxy_error(
            result.returncode, stdout_text, stderr_text
        )
        attempt_ports_status = _merge_ports_status(
            _merge_ports_status(
                _parse_ports_status_from_stdout(stdout_text),
                _parse_open_ports_from_proxychains_stderr(stderr_text),
            ),
            _parse_ports_status_from_xml(attempt_xml_path),
        )
        attempt_success = (
            bool(attempt_ports_status)
            or (
                "nmap scan report for" in stdout_text.lower()
                and "nmap done:" in stdout_text.lower()
            )
            or _stderr_has_target_hits(stderr_text)
        )
        broken_proxy = _stderr_has_broken_proxy_timeout(stderr_text)

        if broken_proxy:
            retryable = True

        if attempt_success:
            retryable = False

        if result.returncode not in (None, 0) and not attempt_success:
            retryable = True

        if (
            not attempt_success
            and not broken_proxy
            and "warning: duplicate port number" in stderr_text.lower()
        ):
            retryable = False

        xml_text = ""
        if attempt_success and attempt_xml_path.exists():
            xml_text = attempt_xml_path.read_text(encoding="utf-8", errors="ignore")

        return {
            "attempt": attempt_no,
            "target": target,
            "proxy": selected_proxy,
            "started_at": attempt_started,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "return_code": result.returncode,
            "retryable_proxy_error": retryable,
            "status": "ok" if attempt_success else "error",
            "ports_status": attempt_ports_status,
            "command": command,
            "stdout_text": stdout_text,
            "stderr_text": stderr_text,
            "success": attempt_success,
            "xml_text": xml_text,
        }
    except subprocess.TimeoutExpired as exc:
        stdout_text = _process_output_to_text(exc.stdout)
        stderr_text = _process_output_to_text(exc.stderr)
        attempt_ports_status = _merge_ports_status(
            _parse_ports_status_from_stdout(stdout_text),
            _parse_open_ports_from_proxychains_stderr(stderr_text),
        )
        attempt_success = bool(attempt_ports_status) or _stderr_has_target_hits(
            stderr_text
        )

        return {
            "attempt": attempt_no,
            "target": target,
            "proxy": selected_proxy,
            "started_at": attempt_started,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "return_code": None,
            "retryable_proxy_error": not attempt_success,
            "status": "timeout" if not attempt_success else "ok",
            "ports_status": attempt_ports_status,
            "error": f"TimeoutExpired after {timeout_sec} seconds",
            "command": command,
            "stdout_text": stdout_text,
            "stderr_text": stderr_text or f"TimeoutExpired after {timeout_sec} seconds",
            "success": attempt_success,
            "xml_text": "",
        }
    except Exception as exc:
        return {
            "attempt": attempt_no,
            "target": target,
            "proxy": selected_proxy,
            "started_at": attempt_started,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "return_code": None,
            "retryable_proxy_error": True,
            "status": "exception",
            "error": f"{type(exc).__name__}: {exc}",
            "command": command,
            "stdout_text": "",
            "stderr_text": f"{type(exc).__name__}: {exc}",
            "success": False,
            "ports_status": {},
            "xml_text": "",
        }
    finally:
        if attempt_xml_path.exists():
            attempt_xml_path.unlink(missing_ok=True)
        if proxychains_conf.exists():
            try:
                proxychains_conf.unlink()
            except OSError as exc:
                console.print(
                    f"[yellow]Warning:[/yellow] failed to remove temp proxychains "
                    f"config {proxychains_conf}: {exc}"
                )


def _ensure_python_nmap() -> bool:
    if nmap is None:
        console.print(
            "[red]Missing dependency:[/red] python-nmap. "
            "Install it before using OS/Web scan profiles."
        )
        input("Enter...")
        return False
    return True


def _scan_with_fallback(scanner, target: str, args: str):
    try:
        scanner.scan(target, arguments=args)
        return args, scanner.get_nmap_last_output()
    except Exception as e:
        if "-sS" in args:
            args2 = args.replace("-sS", "-sT")
            try:
                scanner.scan(target, arguments=args2)
                return args2, scanner.get_nmap_last_output()
            except Exception:
                raise e
        raise e


def _extract_host(host: str, host_info: dict, target: str):
    os_matches = []
    for m in host_info.get("osmatch", []) or []:
        os_matches.append(
            {
                "name": m.get("name", ""),
                "accuracy": m.get("accuracy", ""),
                "line": m.get("line", ""),
            }
        )

    os_classes = []
    for c in host_info.get("osclass", []) or []:
        os_classes.append(
            {
                "type": c.get("type", ""),
                "vendor": c.get("vendor", ""),
                "osfamily": c.get("osfamily", ""),
                "osgen": c.get("osgen", ""),
                "accuracy": c.get("accuracy", ""),
                "cpe": c.get("cpe", []),
            }
        )

    hostnames = []
    for hn in host_info.get("hostnames", []) or []:
        if isinstance(hn, dict):
            hostnames.append(
                {
                    "name": hn.get("name", ""),
                    "type": hn.get("type", ""),
                }
            )
        else:
            hostnames.append({"name": str(hn), "type": ""})

    ports = []
    tcp = host_info.get("tcp", {}) or {}
    for port in sorted(tcp.keys()):
        pinfo = tcp[port] or {}
        service = pinfo.get("name", "")
        product = pinfo.get("product", "")
        version = pinfo.get("version", "")
        extrainfo = pinfo.get("extrainfo", "")
        cpe = pinfo.get("cpe", "")
        scripts_raw = pinfo.get("script", {}) or {}
        scripts = {}
        for sname, sout in scripts_raw.items():
            if isinstance(sout, bytes):
                scripts[sname] = _decode_bytes(sout)
            else:
                scripts[sname] = str(sout)

        ports.append(
            {
                "port": int(port),
                "protocol": "tcp",
                "state": pinfo.get("state", ""),
                "reason": pinfo.get("reason", ""),
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": cpe,
                "tunnel": pinfo.get("tunnel", ""),
                "scripts": scripts,
            }
        )

    return {
        "target": target,
        "host": host,
        "ip": host_info.get("addresses", {}).get("ipv4", host),
        "status": host_info.get("status", {}).get("state", ""),
        "hostnames": hostnames,
        "uptime": host_info.get("uptime", {}) or {},
        "os": {
            "matches": os_matches,
            "classes": os_classes,
        },
        "ports": ports,
    }


def _render_txt(report: dict) -> str:
    lines = []
    lines.append(f"Scan: {report.get('scan_name', '')}")
    lines.append(f"Timestamp: {report.get('timestamp', '')}")
    lines.append(f"Requested arguments: {report.get('arguments', '')}")
    lines.append(f"Targets: {', '.join(report.get('targets', []))}")
    lines.append("=" * 80)
    lines.append("")

    for h in report.get("hosts", []):
        lines.append(f"Nmap scan report for {h.get('target')} ({h.get('ip')})")
        target_meta = (report.get("target_results", {}) or {}).get(h.get("target"), {})
        used_args = target_meta.get("arguments", "")
        if used_args:
            lines.append(f"Used arguments: {used_args}")
        if h.get("hostnames"):
            hostnames = ", ".join(
                x.get("name", "") for x in h["hostnames"] if x.get("name")
            )
            if hostnames:
                lines.append(f"Hostnames: {hostnames}")
        lines.append(f"Status: {h.get('status', '')}")
        os_matches = h.get("os", {}).get("matches", []) or []
        if os_matches:
            best = os_matches[0]
            lines.append(
                f"OS guess: {best.get('name', '')} "
                f"(accuracy {best.get('accuracy', '')})"
            )
        lines.append("")

        ports = h.get("ports", []) or []
        if ports:
            lines.append("PORT    STATE  SERVICE            VERSION")
            lines.append("-" * 80)
            for port in ports:
                ver = " ".join(
                    x
                    for x in [
                        port.get("product", ""),
                        port.get("version", ""),
                        f"({port.get('extrainfo', '')})"
                        if port.get("extrainfo")
                        else "",
                    ]
                    if x
                ).strip()
                lines.append(
                    f"{str(port.get('port')).ljust(5)}/tcp "
                    f"{str(port.get('state', '')).ljust(6)} "
                    f"{str(port.get('service', '')).ljust(18)} "
                    f"{_safe_str(ver, 48)}"
                )

                scripts = port.get("scripts", {}) or {}
                if scripts:
                    for script_name, script_out in scripts.items():
                        lines.append(f"  |_{script_name}: {_safe_str(script_out, 220)}")
        else:
            lines.append("No TCP ports found in results.")

        lines.append("")
        lines.append("=" * 80)
        lines.append("")

    errors = report.get("errors", []) or []
    if errors:
        lines.append("Target errors")
        lines.append("-" * 80)
        for error_item in errors:
            lines.append(
                f"{error_item.get('target', '')}: "
                f"{_safe_str(error_item.get('error', ''), 220)}"
            )
        lines.append("")

    return "\n".join(lines)


def _run_scan(domains: list[str], scan_name: str, nmap_args: str):
    if nmap is None:
        raise RuntimeError("python-nmap is not installed")

    report = {
        "scan_name": scan_name,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "arguments": nmap_args,
        "targets": domains,
        "hosts": [],
        "raw_outputs": {},
        "target_results": {},
        "errors": [],
    }

    for domain in domains:
        console.print(f"[yellow]→ {scan_name}: {domain}[/yellow]")

        scanner = nmap.PortScanner()
        try:
            used_args, raw_out = _scan_with_fallback(scanner, domain, nmap_args)

            if isinstance(raw_out, bytes):
                raw_out = _decode_bytes(raw_out)
            report["raw_outputs"][domain] = raw_out or ""

            scan_block = scanner._scan_result.get("scan", {}) or {}
            report["target_results"][domain] = {
                "status": "ok",
                "arguments": used_args,
                "host_count": len(scan_block),
                "error": "",
            }

            for host, host_info in scan_block.items():
                report["hosts"].append(_extract_host(host, host_info or {}, domain))
        except Exception as exc:
            error_text = f"{type(exc).__name__}: {exc}"
            console.print(f"[red]Nmap error for {domain}:[/red] {error_text}")
            report["raw_outputs"][domain] = f"ERROR: {error_text}"
            report["target_results"][domain] = {
                "status": "error",
                "arguments": nmap_args,
                "host_count": 0,
                "error": error_text,
            }
            report["errors"].append(
                {
                    "target": domain,
                    "arguments": nmap_args,
                    "error": error_text,
                }
            )

    return report


def _save_report_artifacts(scan_name: str, report: dict):
    json_file, txt_file, raw_file = _scan_files(scan_name)

    safe_report = _json_safe(report)
    json_file.write_text(
        json.dumps(safe_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    txt_file.write_text(_render_txt(report), encoding="utf-8")

    raw_lines = []
    for target in report.get("targets", []):
        raw_lines.append(f"### RAW OUTPUT: {target}")
        raw_lines.append((report.get("raw_outputs", {}) or {}).get(target, ""))
        raw_lines.append("\n" + ("=" * 120) + "\n")
    raw_file.write_text("\n".join(raw_lines), encoding="utf-8")

    return json_file, txt_file, raw_file


def _choose_scope_targets() -> list[str]:
    domains = get_scope_domains()
    if not domains:
        return []

    console.print("[green]Scan first domain or all?[/green]")
    selection = Prompt.ask(
        "[green]Choose[/green]", choices=["first", "all"], default="first"
    )

    if selection == "first":
        return [domains[0]]
    return domains


def _run_single_proxied_target_scan(
    *,
    target: str,
    ports: str,
    selector: ProxySelector,
    settings: dict[str, Any],
    proxychains_bin: str,
    nmap_bin: str,
    mapped_domains: list[str] | None = None,
    target_source: str = "",
    target_type: str = "domain",
) -> dict[str, Any]:
    target_dir = _target_scan_dir(target)
    xml_path = target_dir / "scan.xml"
    stdout_path = target_dir / "stdout.txt"
    stderr_path = target_dir / "stderr.txt"
    meta_path = target_dir / "meta.json"

    if xml_path.exists():
        xml_path.unlink()

    started_at = datetime.now().isoformat(timespec="seconds")
    strategy = settings["selection"]["strategy"]
    required_successes = int(settings["scan"]["successful_attempts_required"])
    timeout_sec = float(settings["scan"]["timeout_sec"])

    attempts: list[dict[str, Any]] = []
    stdout_sections: list[str] = []
    stderr_sections: list[str] = []
    used_proxy_ids: set[str] = set()
    selected_proxy: dict[str, Any] | None = None
    last_command: list[str] = []
    final_status = "failed"
    final_return_code: int | None = None
    ports_status: dict[str, str] = {}
    successful_attempts = 0
    failed_retries = 0
    successful_proxies: list[dict[str, Any]] = []
    attempt_no = 0

    while successful_attempts < required_successes:
        remaining_proxies = len(selector.proxies) - len(used_proxy_ids)
        if remaining_proxies <= 0:
            attempts.append(
                {
                    "attempt": attempt_no + 1,
                    "status": "no_proxy_available",
                    "target": target,
                    "error": "No alive proxies left for selection",
                    "started_at": datetime.now().isoformat(timespec="seconds"),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                }
            )
            break

        needed_successes = required_successes - successful_attempts
        batch_size = min(needed_successes, remaining_proxies)
        batch_proxies: list[tuple[int, dict[str, Any]]] = []

        for _ in range(batch_size):
            attempt_no += 1
            try:
                proxy = selector.pick(exclude_ids=used_proxy_ids)
            except ValueError:
                break

            used_proxy_ids.add(proxy["id"])
            batch_proxies.append((attempt_no, proxy))

            console.print(
                f"[yellow]→ Proxied ports scan[/yellow] {target} "
                f"via {proxy['id']} ({proxy['host']}:{proxy['port']}) "
                f"[dim]success {successful_attempts}/{required_successes} | "
                f"fails {failed_retries} | used {len(used_proxy_ids)}/"
                f"{len(selector.proxies)}[/dim]"
            )

        if not batch_proxies:
            break

        batch_results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=len(batch_proxies)) as executor:
            future_map = {
                executor.submit(
                    _run_proxied_attempt,
                    attempt_no=batched_attempt_no,
                    target=target,
                    ports=ports,
                    proxy=proxy,
                    settings=settings,
                    proxychains_bin=proxychains_bin,
                    nmap_bin=nmap_bin,
                    target_dir=target_dir,
                    timeout_sec=timeout_sec,
                ): batched_attempt_no
                for batched_attempt_no, proxy in batch_proxies
            }

            for future in as_completed(future_map):
                batch_results.append(future.result())

        for result in sorted(batch_results, key=lambda item: item["attempt"]):
            proxy = result["proxy"]
            _append_attempt_log(
                stdout_sections,
                f"### ATTEMPT {result['attempt']} STDOUT",
                proxy,
                result.get("stdout_text", ""),
            )
            _append_attempt_log(
                stderr_sections,
                f"### ATTEMPT {result['attempt']} STDERR",
                proxy,
                result.get("stderr_text", ""),
            )

            attempts.append(
                {
                    key: value
                    for key, value in result.items()
                    if key
                    not in {
                        "stdout_text",
                        "stderr_text",
                        "success",
                        "xml_text",
                    }
                }
            )

            last_command = result.get("command") or last_command
            if result.get("return_code") is not None or final_return_code is None:
                final_return_code = result.get("return_code")

            if result.get("success"):
                successful_attempts += 1
                selected_proxy = dict(proxy)
                successful_proxies.append(dict(proxy))
                ports_status = _merge_ports_status(
                    ports_status, result.get("ports_status") or {}
                )
                if result.get("xml_text"):
                    xml_path.write_text(result["xml_text"], encoding="utf-8")
            else:
                failed_retries += 1

        if successful_attempts >= required_successes:
            final_status = "ok"
            break

    finished_at = datetime.now().isoformat(timespec="seconds")

    if successful_attempts == 0 and not xml_path.exists():
        xml_path.write_text("", encoding="utf-8")
    elif successful_attempts > 0 and final_status != "ok":
        final_status = "partial"

    stdout_path.write_text("\n".join(stdout_sections), encoding="utf-8")
    stderr_path.write_text("\n".join(stderr_sections), encoding="utf-8")
    total_ports = len([port for port in str(ports).split(",") if port.strip()])
    suspicious_attempts = _detect_suspicious_attempts(attempts, total_ports)
    suspicious_attempt_ids = {
        int(item["attempt"])
        for item in suspicious_attempts
        if item.get("attempt") is not None
    }
    for attempt in attempts:
        attempt_no_value = int(attempt.get("attempt") or 0)
        attempt["suspicious"] = attempt_no_value in suspicious_attempt_ids

    raw_open_port_votes = _build_open_port_votes(attempts)
    open_port_votes = _build_open_port_votes_filtered(attempts, suspicious_attempt_ids)
    confirmation_threshold = _get_open_port_confirmation_threshold(required_successes)
    confirmed_open_ports, candidate_open_ports = _classify_open_ports(
        open_port_votes, min_confirmations=confirmation_threshold
    )
    confirmed_ports_status = {str(port): "open" for port in confirmed_open_ports}
    candidate_ports_status = {str(port): "open" for port in candidate_open_ports}
    (
        open_ports_json_path,
        open_ports_txt_path,
        candidate_open_ports_json_path,
        candidate_open_ports_txt_path,
    ) = _write_target_open_ports_artifacts(
        target_dir,
        target,
        confirmed_open_ports,
        candidate_open_ports,
        open_port_votes,
        min_confirmations=confirmation_threshold,
        target_type=target_type,
        target_source=target_source,
        mapped_domains=mapped_domains,
    )

    meta = {
        "target": target,
        "target_type": target_type,
        "target_source": target_source,
        "mapped_domains": mapped_domains or [],
        "ports": ports,
        "ports_status": confirmed_ports_status,
        "open_ports": confirmed_open_ports,
        "open_ports_count": len(confirmed_open_ports),
        "candidate_ports_status": candidate_ports_status,
        "candidate_open_ports": candidate_open_ports,
        "candidate_open_ports_count": len(candidate_open_ports),
        "open_port_votes": open_port_votes,
        "raw_open_port_votes": raw_open_port_votes,
        "open_port_confirmation_threshold": confirmation_threshold,
        "suspicious_attempts": suspicious_attempts,
        "suspicious_attempts_count": len(suspicious_attempts),
        "selected_proxy": selected_proxy,
        "selected_proxies": successful_proxies,
        "strategy": strategy,
        "started_at": started_at,
        "finished_at": finished_at,
        "return_code": final_return_code,
        "retries": failed_retries,
        "successful_attempts_required": required_successes,
        "successful_attempts": successful_attempts,
        "command": last_command,
        "mode": "proxied_socks5_connect",
        "status": final_status,
        "attempts": attempts,
    }

    meta_path.write_text(
        json.dumps(_json_safe(meta), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return {
        **meta,
        "scan_dir": target_dir,
        "scan_xml": xml_path,
        "stdout_txt": stdout_path,
        "stderr_txt": stderr_path,
        "meta_json": meta_path,
        "open_ports_json": open_ports_json_path,
        "open_ports_txt": open_ports_txt_path,
        "candidate_open_ports_json": candidate_open_ports_json_path,
        "candidate_open_ports_txt": candidate_open_ports_txt_path,
    }


def run_proxy_pool_check():
    try:
        check_proxy_pool()
    except Exception as exc:
        console.print(f"[red]Proxy pool error:[/red] {exc}")
    input("Enter...")


def run_nmap_web():
    if not _ensure_python_nmap():
        return

    domains = get_scope_domains()
    if not domains:
        console.print("[red]Scope domains пуст. Добавьте домены в проект.[/red]")
        input("Enter...")
        return

    web_scripts = ",".join(
        [
            "http-title",
            "http-server-header",
            "http-headers",
            "http-methods",
            "ssl-cert",
            "ssl-enum-ciphers",
        ]
    )

    args = (
        f"-Pn -T3 -sS -sV --version-all -O --osscan-guess "
        f"-p 80,443 --script {web_scripts}"
    )

    console.rule("[cyan]Nmap: Web profile (80/443)[/cyan]")
    report = _run_scan(domains, "nmap_web", args)
    json_file, txt_file, raw_file = _save_report_artifacts("nmap_web", report)

    console.print(
        f"[green]Saved:[/green] {json_file.name}, {txt_file.name}, {raw_file.name}"
    )
    if report.get("errors"):
        console.print(f"[yellow]Targets with errors:[/yellow] {len(report['errors'])}")
    input("Enter...")


def run_nmap_web_vuln():
    if not _ensure_python_nmap():
        return

    domains = get_scope_domains()
    if not domains:
        console.print("[red]Scope domains пуст. Добавьте домены в проект.[/red]")
        input("Enter...")
        return

    vuln_scripts = ",".join(
        [
            "http-vuln-*",
            "http-enum",
            "http-headers",
            "http-methods",
            "ssl-cert",
            "ssl-enum-ciphers",
            "ssl-heartbleed",
        ]
    )

    args = (
        f"-Pn -T3 -sS -sV --version-all -p 80,443 --script {vuln_scripts} "
        f"--script-timeout 25s"
    )

    console.rule("[cyan]Nmap: Web vuln profile (80/443)[/cyan]")
    report = _run_scan(domains, "nmap_web_vuln", args)
    json_file, txt_file, raw_file = _save_report_artifacts("nmap_web_vuln", report)

    console.print(
        f"[green]Saved:[/green] {json_file.name}, {txt_file.name}, {raw_file.name}"
    )
    if report.get("errors"):
        console.print(f"[yellow]Targets with errors:[/yellow] {len(report['errors'])}")
    input("Enter...")


def run_nmap_osp():
    if not _ensure_python_nmap():
        return

    domains = get_scope_domains()
    if not domains:
        console.print("[red]Scope domains пуст. Добавьте домены в проект.[/red]")
        input("Enter...")
        return

    args = "-A -T3 -sS -sV -O -Pn"

    console.rule("[cyan]Nmap: OS/Services/Ports[/cyan]")
    report = _run_scan(domains, "nmap_osp", args)
    json_file, txt_file, raw_file = _save_report_artifacts("nmap_osp", report)

    console.print(
        f"[green]Saved:[/green] {json_file.name}, {txt_file.name}, {raw_file.name}"
    )
    if report.get("errors"):
        console.print(f"[yellow]Targets with errors:[/yellow] {len(report['errors'])}")
    input("Enter...")


def run_nmap_ports():
    selected_domains = _choose_scope_targets()
    scope_ips = _get_scope_ipv4s()

    if not selected_domains and not scope_ips:
        console.print("[red]Scope domains пуст. Добавьте домены в проект.[/red]")
        input("Enter...")
        return

    console.rule("[cyan]Proxied TCP connect scan[/cyan]")
    console.print(
        "[yellow]Proxied mode supports only TCP connect scan (-sT). "
        "SYN/UDP/OS detection are disabled by design.[/yellow]"
    )

    try:
        settings = load_proxy_settings()
    except Exception as exc:
        console.print(
            f"[red]Proxy config error:[/red] {exc}\n"
            f"[dim]Config path:[/dim] {proxy_config_path()}"
        )
        input("Enter...")
        return

    alive_proxies = load_alive_proxies()
    if not alive_proxies:
        console.print(
            "[red]Alive proxy pool is empty.[/red] "
            "Run [bold]Check proxy pool[/bold] first."
        )
        input("Enter...")
        return

    proxychains_bin = _find_proxychains_binary()
    if not proxychains_bin:
        console.print(
            "[red]proxychains-ng is not installed or not found in PATH.[/red]\n"
            "[dim]Expected binary:[/dim] proxychains4 or proxychains"
        )
        input("Enter...")
        return

    nmap_bin = _find_nmap_binary()
    if not nmap_bin:
        console.print("[red]nmap binary not found in PATH.[/red]")
        input("Enter...")
        return

    inventory = _build_ipv4_scan_inventory(selected_domains)
    inventory_json_path, inventory_txt_path = _write_domain_ip_inventory(inventory)
    targets = inventory.get("unique_ipv4_targets", []) or []
    if not targets:
        console.print(
            "[red]Не удалось собрать IPv4 targets для сканирования.[/red]\n"
            "[dim]Проверь scope.domains / scope.ips и текущий DNS-resolve.[/dim]"
        )
        console.print(f"[dim]Inventory:[/dim] {inventory_json_path}")
        input("Enter...")
        return

    selector = ProxySelector(
        proxies=alive_proxies,
        strategy=settings["selection"]["strategy"],
    )

    console.print(
        f"[dim]Selected domains:[/dim] {len(inventory.get('selected_domains', []))}"
    )
    console.print(
        f"[dim]Standalone scope.ips:[/dim] "
        f"{len(inventory.get('standalone_scope_ips', []))}"
    )
    console.print(f"[dim]Unique IPv4 targets:[/dim] {len(targets)}")
    if inventory.get("unresolved_domains"):
        console.print(
            f"[dim]Unresolved domains:[/dim] "
            f"{len(inventory.get('unresolved_domains', []))}"
        )
    console.print(f"[dim]Inventory JSON:[/dim] {inventory_json_path}")
    console.print(f"[dim]Inventory TXT:[/dim] {inventory_txt_path}")
    console.print(f"[dim]Ports count:[/dim] {len(POPULAR_TCP_PORTS.split(','))}")
    console.print(f"[dim]Strategy:[/dim] {settings['selection']['strategy']}")
    console.print(
        f"[dim]Successful attempts required:[/dim] "
        f"{settings['scan']['successful_attempts_required']}"
    )
    console.print(f"[dim]Alive proxies available:[/dim] {len(alive_proxies)}")
    console.print(
        "[dim]IP targets are scanned once per unique IPv4. "
        "Domain-level open ports are derived later via the frozen domain->IP map. "
        "Attempts are launched in parallel batches.[/dim]"
    )

    results = []
    for target in targets:
        target_meta = inventory.get("ip_targets", {}).get(target, {}) or {}
        mapped_domains = target_meta.get("mapped_domains", []) or []
        target_source = ",".join(target_meta.get("sources", []) or [])
        result = _run_single_proxied_target_scan(
            target=target,
            ports=POPULAR_TCP_PORTS,
            selector=selector,
            settings=settings,
            proxychains_bin=proxychains_bin,
            nmap_bin=nmap_bin,
            mapped_domains=mapped_domains,
            target_source=target_source,
            target_type="ipv4",
        )
        results.append(result)
        console.print(
            f"[green]Saved:[/green] {result['scan_dir']} "
            f"[dim]status={result['status']} | "
            f"successful={result['successful_attempts']}/"
            f"{result['successful_attempts_required']} | "
            f"open_ports={result['open_ports_count']} | "
            f"suspicious={result['suspicious_attempts_count']}[/dim]"
        )

    (
        ip_summary_json,
        ip_summary_txt,
        ip_candidate_summary_json,
        ip_candidate_summary_txt,
    ) = _write_open_ports_ip_summary(results)
    (
        summary_json,
        summary_txt,
        candidate_summary_json,
        candidate_summary_txt,
    ) = _write_open_ports_summary(results, inventory)
    ok_count = sum(1 for result in results if result.get("status") == "ok")
    console.print(f"[green]Successful targets:[/green] {ok_count}/{len(results)}")
    console.print(f"[green]IP open ports summary:[/green] {ip_summary_json}")
    console.print(f"[green]IP open ports list:[/green] {ip_summary_txt}")
    console.print(f"[green]IP candidate summary:[/green] {ip_candidate_summary_json}")
    console.print(f"[green]IP candidate list:[/green] {ip_candidate_summary_txt}")
    console.print(f"[green]Open ports summary:[/green] {summary_json}")
    console.print(f"[green]Open ports list:[/green] {summary_txt}")
    console.print(f"[green]Candidate ports summary:[/green] {candidate_summary_json}")
    console.print(f"[green]Candidate ports list:[/green] {candidate_summary_txt}")
    input("Enter...")


def show_nmap_results():
    files = _latest_nmap_artifacts()
    if not files:
        console.print("[yellow]Результатов пока нет[/yellow]")
        input("Enter...")
        return

    base = _recon_dir()
    console.rule("[bold cyan]Nmap Results[/bold cyan]")
    for path in files[:20]:
        try:
            label = path.relative_to(base).as_posix()
        except Exception:
            label = path.name
        console.print(label)

    if len(files) > 20:
        console.print("[dim]... (показаны последние 20 файлов)[/dim]")

    input("Enter...")


def nmap_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold cyan]Recon / Nmap[/bold cyan]")

        console.print(
            "*[bold cyan] Recon / Nmap[/bold cyan]\n"
            " * [1] OS/Services/Ports\n"
            " * [2] Web profile (80/443)\n"
            " * [3] Web vuln profile (80/443)\n"
            "*[bold cyan] Proxy mode[/bold cyan]\n"
            " * [4] Check proxy pool\n"
            " * [5] Proxied TCP connect scan\n"
            "*[bold cyan] Results[/bold cyan]\n"
            " * [6] Show results\n"
            "* [0] [bold red]Back[/bold red]"
        )
        console.print(
            "[yellow]Proxied mode supports only TCP connect scan (-sT). "
            "SYN/UDP/OS detection are disabled by design.[/yellow]"
        )

        choice = Prompt.ask("Enter", choices=["1", "2", "3", "4", "5", "6", "0"])

        if choice == "1":
            run_nmap_osp()
        elif choice == "2":
            run_nmap_web()
        elif choice == "3":
            run_nmap_web_vuln()
        elif choice == "4":
            run_proxy_pool_check()
        elif choice == "5":
            run_nmap_ports()
        elif choice == "6":
            show_nmap_results()
        elif choice == "0":
            break
