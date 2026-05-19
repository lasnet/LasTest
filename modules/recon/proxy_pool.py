from __future__ import annotations

import copy
import ipaddress
import json
import random
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from core.config import load_yaml

console = Console()

ALLOWED_PROXY_STRATEGIES = {"first_alive", "round_robin", "random"}

DEFAULT_PROXY_CONFIG: dict[str, Any] = {
    "healthcheck": {
        "target_host": "1.1.1.1",
        "target_port": 443,
        "timeout_sec": 3,
        "negative_check_enabled": True,
        "closed_target_host": "1.1.1.1",
        "closed_target_port": 65535,
    },
    "selection": {
        "strategy": "round_robin",
    },
    "scan": {
        "successful_attempts_required": 3,
        "max_retries_per_target": 3,
        "timeout_sec": 240,
    },
    "proxychains": {
        "proxy_dns": True,
        "tcp_connect_time_out_ms": 8000,
        "tcp_read_time_out_ms": 15000,
    },
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def proxy_source_path() -> Path:
    return Path(__file__).resolve().parent / "worldlist" / "socks5.txt"


def proxy_config_path() -> Path:
    return _repo_root() / "config" / "proxies.yaml"


def _shared_proxy_cache_dir() -> Path:
    path = proxy_source_path().parent
    path.mkdir(parents=True, exist_ok=True)
    return path


def proxies_alive_path() -> Path:
    return _shared_proxy_cache_dir() / "proxies_alive.json"


def proxies_failed_path() -> Path:
    return _shared_proxy_cache_dir() / "proxies_failed.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _merge_dicts(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _require_dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a mapping")
    return value


def _require_port(value: Any, path: str) -> int:
    try:
        port = int(value)
    except Exception as exc:
        raise ValueError(f"{path} must be an integer") from exc

    if port < 1 or port > 65535:
        raise ValueError(f"{path} must be in range 1..65535")
    return port


def _require_positive_number(value: Any, path: str) -> float:
    try:
        number = float(value)
    except Exception as exc:
        raise ValueError(f"{path} must be numeric") from exc

    if number <= 0:
        raise ValueError(f"{path} must be > 0")
    return number


def load_proxy_settings() -> dict[str, Any]:
    config_path = proxy_config_path()
    raw = load_yaml(config_path) if config_path.exists() else {}

    if raw and not isinstance(raw, dict):
        raise ValueError("config/proxies.yaml must contain a YAML mapping")

    config = _merge_dicts(DEFAULT_PROXY_CONFIG, raw or {})

    healthcheck = _require_dict(config.get("healthcheck"), "healthcheck")
    target_host = str(healthcheck.get("target_host", "")).strip()
    if not target_host:
        raise ValueError("healthcheck.target_host must be a non-empty string")
    healthcheck["target_host"] = target_host
    healthcheck["target_port"] = _require_port(
        healthcheck.get("target_port"), "healthcheck.target_port"
    )
    healthcheck["timeout_sec"] = _require_positive_number(
        healthcheck.get("timeout_sec"), "healthcheck.timeout_sec"
    )
    healthcheck["negative_check_enabled"] = bool(
        healthcheck.get("negative_check_enabled", True)
    )
    closed_target_host = str(healthcheck.get("closed_target_host", "")).strip()
    if not closed_target_host:
        raise ValueError("healthcheck.closed_target_host must be a non-empty string")
    healthcheck["closed_target_host"] = closed_target_host
    healthcheck["closed_target_port"] = _require_port(
        healthcheck.get("closed_target_port"), "healthcheck.closed_target_port"
    )

    selection = _require_dict(config.get("selection"), "selection")
    strategy = str(selection.get("strategy", "")).strip().lower()
    if strategy not in ALLOWED_PROXY_STRATEGIES:
        raise ValueError(
            "selection.strategy must be one of: "
            + ", ".join(sorted(ALLOWED_PROXY_STRATEGIES))
        )
    selection["strategy"] = strategy

    scan = _require_dict(config.get("scan"), "scan")
    successful_attempts_required = int(scan.get("successful_attempts_required", 3))
    if successful_attempts_required < 1 or successful_attempts_required > 10:
        raise ValueError("scan.successful_attempts_required must be between 1 and 10")
    scan["successful_attempts_required"] = successful_attempts_required

    retries = int(scan.get("max_retries_per_target", 3))
    if retries < 0 or retries > 20:
        raise ValueError("scan.max_retries_per_target must be between 0 and 20")
    scan["max_retries_per_target"] = retries
    scan["timeout_sec"] = _require_positive_number(
        scan.get("timeout_sec"), "scan.timeout_sec"
    )

    proxychains = _require_dict(config.get("proxychains"), "proxychains")
    proxychains["proxy_dns"] = bool(proxychains.get("proxy_dns", True))
    proxychains["tcp_connect_time_out_ms"] = int(
        _require_positive_number(
            proxychains.get("tcp_connect_time_out_ms"),
            "proxychains.tcp_connect_time_out_ms",
        )
    )
    proxychains["tcp_read_time_out_ms"] = int(
        _require_positive_number(
            proxychains.get("tcp_read_time_out_ms"),
            "proxychains.tcp_read_time_out_ms",
        )
    )

    return config


def _parse_proxy_line(line: str) -> tuple[str, int]:
    raw = str(line).strip()
    if not raw:
        raise ValueError("empty proxy line")

    if "://" in raw:
        raise ValueError("proxy line must be in host:port format without scheme")

    if ":" not in raw:
        raise ValueError("proxy line must be in host:port format")

    host, port_raw = raw.rsplit(":", 1)
    host = host.strip()
    if not host:
        raise ValueError("proxy host is empty")
    if any(ch.isspace() for ch in host):
        raise ValueError("proxy host contains whitespace")

    port = _require_port(port_raw, "proxy port")
    return host, port


def load_proxy_candidates() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = proxy_source_path()
    if not path.exists():
        raise FileNotFoundError(f"Proxy list not found: {path}")

    alive_candidates: list[dict[str, Any]] = []
    invalid_entries: list[dict[str, Any]] = []
    next_id = 1

    for line_no, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            host, port = _parse_proxy_line(line)
        except ValueError as exc:
            invalid_entries.append(
                {
                    "id": f"invalid_{line_no}",
                    "type": "socks5",
                    "host": "",
                    "port": 0,
                    "error": str(exc),
                    "source_line": line,
                    "checked_at": _utc_now_iso(),
                }
            )
            continue

        alive_candidates.append(
            {
                "id": f"pivot{next_id}",
                "type": "socks5",
                "host": host,
                "port": port,
            }
        )
        next_id += 1

    return alive_candidates, invalid_entries


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF from proxy")
        data += chunk
    return data


def _build_socks5_request(target_host: str, target_port: int) -> bytes:
    try:
        ip_obj = ipaddress.ip_address(target_host)
        if ip_obj.version == 4:
            return b"\x05\x01\x00\x01" + ip_obj.packed + target_port.to_bytes(2, "big")
        return b"\x05\x01\x00\x04" + ip_obj.packed + target_port.to_bytes(2, "big")
    except ValueError:
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("healthcheck target_host is too long for SOCKS5")
        return (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + target_port.to_bytes(2, "big")
        )


def _socks5_reply_text(code: int) -> str:
    mapping = {
        0x00: "succeeded",
        0x01: "general SOCKS server failure",
        0x02: "connection not allowed by ruleset",
        0x03: "network unreachable",
        0x04: "host unreachable",
        0x05: "connection refused",
        0x06: "TTL expired",
        0x07: "command not supported",
        0x08: "address type not supported",
    }
    return mapping.get(code, f"unknown reply code {code}")


def _probe_socks5_connect(
    proxy: dict[str, Any],
    target_host: str,
    target_port: int,
    timeout_sec: float,
) -> dict[str, Any]:
    started = time.perf_counter()
    with socket.create_connection(
        (proxy["host"], int(proxy["port"])), timeout=timeout_sec
    ) as sock:
        sock.settimeout(timeout_sec)

        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting[0] != 0x05:
            raise RuntimeError("invalid SOCKS5 version in greeting reply")
        if greeting[1] != 0x00:
            raise RuntimeError("SOCKS5 proxy requires unsupported authentication")

        sock.sendall(_build_socks5_request(target_host, target_port))
        header = _recv_exact(sock, 4)
        if header[0] != 0x05:
            raise RuntimeError("invalid SOCKS5 version in connect reply")
        reply_code = header[1]

        latency_ms = int((time.perf_counter() - started) * 1000)
        if reply_code != 0x00:
            return {
                "success": False,
                "reply_code": reply_code,
                "latency_ms": latency_ms,
                "message": _socks5_reply_text(reply_code),
            }

        atyp = header[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        else:
            raise RuntimeError(f"unsupported bind address type {atyp}")

    return {
        "success": True,
        "reply_code": reply_code,
        "latency_ms": latency_ms,
        "message": "succeeded",
    }


def measure_proxy_latency(
    proxy: dict[str, Any],
    target_host: str,
    target_port: int,
    timeout_sec: float,
) -> int:
    result = _probe_socks5_connect(
        proxy=proxy,
        target_host=target_host,
        target_port=target_port,
        timeout_sec=timeout_sec,
    )
    if not result["success"]:
        raise RuntimeError(str(result["message"]))
    return int(result["latency_ms"])


def passes_negative_proxy_check(
    proxy: dict[str, Any],
    target_host: str,
    target_port: int,
    timeout_sec: float,
) -> tuple[bool, str]:
    try:
        result = _probe_socks5_connect(
            proxy=proxy,
            target_host=target_host,
            target_port=target_port,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return True, f"{type(exc).__name__}: {exc}"

    if result["success"]:
        return (
            False,
            f"negative check unexpectedly succeeded for {target_host}:{target_port}",
        )

    return True, str(result["message"])


def save_proxy_check_results(
    alive: list[dict[str, Any]],
    failed: list[dict[str, Any]],
) -> tuple[Path, Path]:
    alive_path = proxies_alive_path()
    failed_path = proxies_failed_path()

    alive_path.write_text(
        json.dumps(alive, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    failed_path.write_text(
        json.dumps(failed, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return alive_path, failed_path


def check_proxy_pool() -> dict[str, Any]:
    config = load_proxy_settings()
    proxies, invalid_entries = load_proxy_candidates()

    if not proxies and not invalid_entries:
        raise RuntimeError("Proxy list is empty")

    healthcheck = config["healthcheck"]
    alive: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = list(invalid_entries)

    console.rule("[bold cyan]SOCKS5 proxy pool[/bold cyan]")
    console.print(
        "[dim]Health-check:[/dim] "
        f"{healthcheck['target_host']}:{healthcheck['target_port']}"
    )
    if healthcheck["negative_check_enabled"]:
        console.print(
            "[dim]Negative check:[/dim] "
            f"{healthcheck['closed_target_host']}:{healthcheck['closed_target_port']}"
        )

    for proxy in proxies:
        label = f"{proxy['id']} {proxy['host']}:{proxy['port']}"
        console.print(f"[yellow]→ Check proxy[/yellow] {label}")

        try:
            latency_ms = measure_proxy_latency(
                proxy=proxy,
                target_host=healthcheck["target_host"],
                target_port=int(healthcheck["target_port"]),
                timeout_sec=float(healthcheck["timeout_sec"]),
            )
            negative_check_message = ""
            if healthcheck["negative_check_enabled"]:
                negative_ok, negative_check_message = passes_negative_proxy_check(
                    proxy=proxy,
                    target_host=healthcheck["closed_target_host"],
                    target_port=int(healthcheck["closed_target_port"]),
                    timeout_sec=float(healthcheck["timeout_sec"]),
                )
                if not negative_ok:
                    raise RuntimeError(negative_check_message)

            alive.append(
                {
                    "id": proxy["id"],
                    "type": proxy["type"],
                    "host": proxy["host"],
                    "port": proxy["port"],
                    "latency_ms": latency_ms,
                    "negative_check_enabled": healthcheck["negative_check_enabled"],
                    "negative_check_note": negative_check_message,
                    "checked_at": _utc_now_iso(),
                }
            )
            console.print(f"[green][+][/green] {proxy['id']} alive ({latency_ms} ms)")
        except Exception as exc:
            failed.append(
                {
                    "id": proxy["id"],
                    "type": proxy["type"],
                    "host": proxy["host"],
                    "port": proxy["port"],
                    "error": f"{type(exc).__name__}: {exc}",
                    "checked_at": _utc_now_iso(),
                }
            )
            console.print(f"[red][-][/red] {proxy['id']} failed: {exc}")

    alive_path, failed_path = save_proxy_check_results(alive, failed)

    console.print(f"[green]Alive proxies:[/green] {len(alive)}")
    console.print(f"[yellow]Failed proxies:[/yellow] {len(failed)}")
    console.print(f"[dim]Saved alive:[/dim] {alive_path}")
    console.print(f"[dim]Saved failed:[/dim] {failed_path}")

    return {
        "config": config,
        "alive": alive,
        "failed": failed,
        "alive_path": alive_path,
        "failed_path": failed_path,
    }


def load_alive_proxies() -> list[dict[str, Any]]:
    path = proxies_alive_path()
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    proxies: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        proxy_id = str(item.get("id", "")).strip()
        host = str(item.get("host", "")).strip()
        if not proxy_id or not host:
            continue
        try:
            port = _require_port(item.get("port"), "proxy port")
        except ValueError:
            continue

        proxies.append(
            {
                "id": proxy_id,
                "type": "socks5",
                "host": host,
                "port": port,
                "latency_ms": item.get("latency_ms"),
                "checked_at": item.get("checked_at"),
            }
        )

    return proxies


class ProxySelector:
    """Select the next alive proxy for a target scan attempt.

    Strategies:
    - first_alive: always pick the first non-excluded proxy from the alive list.
    - round_robin: rotate across the alive list so attempts are distributed.
    - random: pick any non-excluded alive proxy at random.
    """

    def __init__(self, proxies: list[dict[str, Any]], strategy: str):
        if not proxies:
            raise ValueError("ProxySelector requires at least one alive proxy")
        if strategy not in ALLOWED_PROXY_STRATEGIES:
            raise ValueError(
                "Unsupported proxy strategy: "
                f"{strategy}. Allowed: {', '.join(sorted(ALLOWED_PROXY_STRATEGIES))}"
            )

        self.proxies = [dict(proxy) for proxy in proxies]
        self.strategy = strategy
        self._rr_index = 0
        self._random = random.SystemRandom()

    def pick(self, exclude_ids: set[str] | None = None) -> dict[str, Any]:
        excluded = exclude_ids or set()
        available = [p for p in self.proxies if p["id"] not in excluded]
        if not available:
            raise ValueError("No alive proxies left for selection")

        if self.strategy == "first_alive":
            return dict(available[0])

        if self.strategy == "random":
            return dict(self._random.choice(available))

        total = len(self.proxies)
        for offset in range(total):
            idx = (self._rr_index + offset) % total
            candidate = self.proxies[idx]
            if candidate["id"] in excluded:
                continue
            self._rr_index = (idx + 1) % total
            return dict(candidate)

        raise ValueError("No alive proxies left for round-robin selection")
