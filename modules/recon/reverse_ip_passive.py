from __future__ import annotations

import json
import re
import time
import ipaddress
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

import requests

from core.project_context import project_context
from core.user_config import load_user_config, get_api
from modules.recon.storage import save_subdomains
from rich.console import Console

console = Console()


# ----------------------------
# Paths
# ----------------------------


def _recon_dir() -> Path:
    out = project_context.path / "recon" / "subdomains"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _cache_dir(out_dir: Path) -> Path:
    p = out_dir / "passive_reverseip_cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ----------------------------
# Utils
# ----------------------------

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)


def _dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def get_scope_ips() -> list[str]:
    ips = project_context.get("scope", "ips", default=[])
    cleaned: list[str] = []
    for ip in ips:
        if not ip:
            continue
        s = str(ip).strip()
        if s:
            cleaned.append(s)
    return _dedupe_keep_order(cleaned)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _clean_domain(s: str) -> Optional[str]:
    """
    Возвращает нормализованный домен или None.
    Важно: фильтруем IP-адреса, чтобы они не попадали в scope.domains.
    """
    if not s:
        return None

    s = str(s).strip().lower()

    # убрать завершающую точку
    if s.endswith("."):
        s = s[:-1]

    # wildcard
    if s.startswith("*."):
        s = s[2:]

    # быстрые отсеки
    if " " in s or "\t" in s or "\n" in s:
        return None

    # критично: не пускаем IP
    if _is_ip(s):
        return None

    # домен должен матчиться regex (и иметь tld, а не просто 1.2.3.4)
    if not DOMAIN_RE.fullmatch(s):
        return None

    return s


def _extract_domains_from_any(obj: Any) -> Set[str]:
    """
    Best-effort: вытаскиваем домены из любых строк внутри JSON.
    При этом _clean_domain() уже не пропускает IP.
    """
    found: Set[str] = set()

    def walk(x: Any):
        if x is None:
            return
        if isinstance(x, str):
            cand = _clean_domain(x)
            if cand:
                found.add(cand)

            # иногда SAN приходит строкой вида "DNS:a, DNS:b"
            if "dns:" in x.lower():
                parts = re.split(r"[,;]", x)
                for p in parts:
                    p = re.sub(r"(?i)^dns:\s*", "", p.strip())
                    cand2 = _clean_domain(p)
                    if cand2:
                        found.add(cand2)
            return

        if isinstance(x, dict):
            for v in x.values():
                walk(v)
            return

        if isinstance(x, list):
            for v in x:
                walk(v)
            return

    walk(obj)
    return found


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _request_with_backoff(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    max_retries: int = 5,
    min_sleep: float = 1.0,
) -> requests.Response:
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)

            if resp.status_code in (429, 502, 503, 504):
                sleep_s = max(min_sleep, 2 ** (attempt - 1))
                console.print(
                    f"[yellow]{resp.status_code} from API, retry in {sleep_s:.1f}s...[/yellow]"
                )
                time.sleep(sleep_s)
                continue

            return resp
        except Exception as e:
            last_exc = e
            sleep_s = max(min_sleep, 2 ** (attempt - 1))
            console.print(
                f"[yellow]Request error, retry in {sleep_s:.1f}s... ({e})[/yellow]"
            )
            time.sleep(sleep_s)

    raise RuntimeError(f"API request failed after retries: {url}") from last_exc


def _resolves_to_ip(domain: str, ip: str) -> bool:
    """
    Проверяем, что domain сейчас резолвится в ip (A record).
    """
    try:
        r = subprocess.run(
            ["dig", "+short", domain, "A"], capture_output=True, text=True, timeout=8
        )
        return ip in (r.stdout or "").split()
    except Exception:
        return False


# ----------------------------
# Providers
# ----------------------------


def shodan_internetdb_domains(ip: str, out_dir: Path, use_cache: bool) -> Set[str]:
    """
    Бесплатный Shodan InternetDB: https://internetdb.shodan.io/<ip>
    Возвращает hostnames/ports/cpes/vulns и т.д.
    """
    cache = _cache_dir(out_dir) / f"internetdb_{ip}.json"
    if use_cache and cache.exists():
        data = json.loads(cache.read_text(encoding="utf-8"))
    else:
        url = f"https://internetdb.shodan.io/{ip}"
        resp = _request_with_backoff(url)
        if resp.status_code != 200:
            data = {"_error": True, "status_code": resp.status_code, "text": resp.text}
        else:
            data = resp.json()
        _write_json(cache, data)

    out: Set[str] = set()
    if isinstance(data, dict) and isinstance(data.get("hostnames"), list):
        for x in data["hostnames"]:
            d = _clean_domain(str(x))
            if d:
                out.add(d)

    # extra (на случай, если что-то полезное спрятано в других полях)
    out |= _extract_domains_from_any(data)
    return out


def censys_platform_domains(
    ip: str, token: str, out_dir: Path, use_cache: bool
) -> Set[str]:
    """
    Censys Platform API v3 host asset:
    GET https://api.platform.censys.io/v3/global/asset/host/<ip>
    Auth: Bearer <PAT>
    """
    cache = _cache_dir(out_dir) / f"censys_platform_{ip}.json"
    if use_cache and cache.exists():
        data = json.loads(cache.read_text(encoding="utf-8"))
    else:
        url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
        headers = {"authorization": f"Bearer {token}", "accept": "application/json"}
        resp = _request_with_backoff(url, headers=headers)
        if resp.status_code != 200:
            data = {"_error": True, "status_code": resp.status_code, "text": resp.text}
        else:
            data = resp.json()
        _write_json(cache, data)

    out: Set[str] = set()

    # приоритет: dns.names
    try:
        names = (
            data.get("result", {}).get("resource", {}).get("dns", {}).get("names", [])
        )
        if isinstance(names, list):
            for x in names:
                d = _clean_domain(str(x))
                if d:
                    out.add(d)
    except Exception:
        pass

    # плюс best-effort по resource (TLS SAN/CN, Location и т.п.)
    resource = (
        data.get("result", {}).get("resource") if isinstance(data, dict) else None
    )
    if resource is not None:
        out |= _extract_domains_from_any(resource)

    return out


# ----------------------------
# Main entry
# ----------------------------


def run_reverse_ip_passive() -> None:
    out_dir = _recon_dir()

    ips = get_scope_ips()
    if not ips:
        console.print("[yellow]В scope.ips пусто — нечего искать.[/yellow]")
        input("Enter...")
        return

    conf = load_user_config()
    censys_token = get_api(conf, "apis", "censys", "personal_access_token")

    # Shodan InternetDB ключ не нужен — просто включим его всегда
    use_cache = True
    verify = True
    per_ip_delay = 2

    console.rule(
        "[cyan]Passive Reverse IP (Shodan InternetDB + Censys Platform)[/cyan]"
    )
    console.print(f"[green]IP в scope:[/green] {len(ips)}")
    console.print(f"[dim]Cache dir:[/dim] {_cache_dir(out_dir)}")

    all_found: Set[str] = set()
    shodan_found: Set[str] = set()
    censys_found: Set[str] = set()

    for idx, ip in enumerate(ips, start=1):
        console.print(f"\n[cyan]{idx}/{len(ips)}[/cyan] IP: [bold]{ip}[/bold]")

        # 1) Shodan InternetDB (free)
        s_domains = shodan_internetdb_domains(ip, out_dir, use_cache=use_cache)
        if verify and s_domains:
            s_domains = {d for d in s_domains if _resolves_to_ip(d, ip)}
        console.print(f"[green]Shodan InternetDB found:[/green] {len(s_domains)}")
        shodan_found |= s_domains
        all_found |= s_domains

        # 2) Censys Platform (PAT)
        if censys_token:
            c_domains = censys_platform_domains(
                ip, censys_token, out_dir, use_cache=use_cache
            )
            if verify and c_domains:
                c_domains = {d for d in c_domains if _resolves_to_ip(d, ip)}
            console.print(f"[green]Censys Platform found:[/green] {len(c_domains)}")
            censys_found |= c_domains
            all_found |= c_domains
        else:
            console.print(
                "[yellow]Censys token не найден в user config — пропускаю Censys.[/yellow]"
            )

        if per_ip_delay > 0 and idx != len(ips):
            time.sleep(per_ip_delay)

    # сохраняем по источникам
    if shodan_found:
        save_subdomains(shodan_found, source="shodan_internetdb_reverse_ip")
    if censys_found:
        save_subdomains(censys_found, source="censys_platform_reverse_ip")

    # отчет
    report = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ip_count": len(ips),
        "found_total": len(all_found),
        "found_shodan": len(shodan_found),
        "found_censys": len(censys_found),
        "all": sorted(all_found),
        "shodan": sorted(shodan_found),
        "censys": sorted(censys_found),
    }

    report_json = out_dir / "passive_reverseip_report.json"
    report_txt = out_dir / "passive_reverseip_report.txt"
    _write_json(report_json, report)
    report_txt.write_text("\n".join(sorted(all_found)) + "\n", encoding="utf-8")

    console.rule("[green]Done[/green]")
    console.print(f"[cyan]Found total:[/cyan] {len(all_found)}")
    console.print(f"[cyan]Report JSON:[/cyan] {report_json}")
    console.print(f"[cyan]Report TXT:[/cyan] {report_txt}")
