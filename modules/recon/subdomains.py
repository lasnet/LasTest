import subprocess
import json
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from rich.console import Console
from core.project_context import project_context
from core.user_config import get_api, load_user_config
from rich.prompt import Prompt, Confirm
from core.utils import require_project
import re
from functools import lru_cache
from modules.recon.storage import save_subdomains
from modules.recon.storage import save_scope_ips
from modules.recon.revdns_subdomains import run_revdns_subdomains_from_scope_ips
from modules.recon.reverse_ip_passive import run_reverse_ip_passive
from modules.recon.ip_name_enrich import run_ip_name_enrich

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None


# fot nslookup subdomains by save
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# _IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Optional findomain tokens should be provided through environment variables.
# findomain -t 9958258.ru -q

console = Console()


def _build_findomain_env() -> dict[str, str]:
    env = os.environ.copy()
    conf = load_user_config()

    findomain_vt_token = str(
        env.get("findomain_virustotal_token")
        or get_api(conf, "apis", "findomain", "virustotal_token", default="")
        or ""
    ).strip()

    if findomain_vt_token:
        env["findomain_virustotal_token"] = findomain_vt_token

    return env


def _get_first_scope_domain() -> str | None:
    domains = get_scope_domains()
    if not domains:
        return None
    return domains[0]


def _wordlists_dir() -> Path:
    return Path(__file__).resolve().parent / "worldlist"


def _load_wordlist_lines(wordlist: Path) -> list[str]:
    return [
        line.strip()
        for line in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]


def _split_wordlist(lines: list[str], chunks: int) -> list[list[str]]:
    if not lines:
        return []

    chunks = max(1, min(chunks, len(lines)))
    chunk_size = (len(lines) + chunks - 1) // chunks
    return [lines[i : i + chunk_size] for i in range(0, len(lines), chunk_size)]


def _write_temp_wordlist_chunk(lines: list[str]) -> Path:
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as temp_file:
        temp_file.write("\n".join(lines) + "\n")
        return Path(temp_file.name)


def _collect_dnsmap_output(stdout: str) -> set[str]:
    found = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line:
            found.add(line)
    return found


def _run_dnsmap_single(domain: str, wordlist_path: Path) -> tuple[set[str], str, int]:
    cmd = ["dnsmap", domain, "-w", str(wordlist_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return (
        _collect_dnsmap_output(result.stdout),
        (result.stderr or ""),
        result.returncode,
    )


def _run_dnsmap_parallel_chunks(
    domain: str, wordlist_path: Path, workers: int, debug: bool = False
) -> set[str]:
    lines = _load_wordlist_lines(wordlist_path)
    if not lines:
        return set()

    if workers <= 1 or len(lines) < 100:
        found, _, _ = _run_dnsmap_single(domain, wordlist_path)
        return found

    chunks = _split_wordlist(lines, workers)
    temp_paths = [_write_temp_wordlist_chunk(chunk) for chunk in chunks]
    output: set[str] = set()

    try:
        with ThreadPoolExecutor(max_workers=min(workers, len(temp_paths))) as executor:
            futures = {
                executor.submit(_run_dnsmap_single, domain, temp_path): idx
                for idx, temp_path in enumerate(temp_paths, start=1)
            }

            total = len(futures)
            for future in as_completed(futures):
                idx = futures[future]
                found, stderr, returncode = future.result()
                output.update(found)

                if debug:
                    console.print(
                        f"[dim]dnsmap chunk {idx}/{total} finished "
                        f"(found={len(found)}, rc={returncode})[/dim]"
                    )
                    if stderr.strip():
                        console.print(
                            f"[dim]dnsmap chunk {idx}/{total} stderr captured[/dim]"
                        )

        return output
    finally:
        for temp_path in temp_paths:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


def _run_dnsmap_for_domain(
    domain: str, wordlist_path: Path, workers: int, debug: bool = False
) -> set[str]:
    if debug:
        console.print(f"[yellow]→ {domain}[/yellow]")

    if workers <= 1:
        found, stderr, returncode = _run_dnsmap_single(domain, wordlist_path)
        if debug:
            console.print(
                f"[dim]dnsmap single finished (rc={returncode}, found={len(found)})[/dim]"
            )
            if stderr.strip():
                console.print("[dim]dnsmap stderr captured[/dim]")
        return found

    return _run_dnsmap_parallel_chunks(
        domain, wordlist_path, workers=workers, debug=debug
    )


def _print_stage_timing(label: str, seconds: float) -> None:
    console.print(f"[dim]{label}:[/dim] {seconds:.2f}s")


def _build_dns_resolver(timeout: float = 3.0, lifetime: float = 3.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def _resolve_host_records(
    hostname: str, include_aaaa: bool = False
) -> tuple[str, set[str]]:
    hostname = hostname.strip().rstrip(".").lower()
    if not hostname:
        return "", set()

    if dns is None:
        return hostname, set()

    ips: set[str] = set()
    resolver = _build_dns_resolver()
    record_types = ["A", "AAAA"] if include_aaaa else ["A"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
            if answers is None:
                continue

            for rdata in answers:
                if rtype == "A":
                    ips.add(str(rdata.address))
                elif rtype == "AAAA":
                    ips.add(str(rdata.address))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        except Exception:
            continue

    return hostname, ips


def _batch_verify_hosts(
    hosts: set[str], include_aaaa: bool = False, max_workers: int = 50
) -> set[str]:
    if not hosts:
        return set()

    if dns is None:
        console.print(
            "[yellow]dnspython не установлен, использую старую nslookup-валидацию.[/yellow]"
        )
        verified = {host for host in hosts if dns_has_ip_nslookup(host)}
        return verified

    verified: set[str] = set()
    all_ips: set[str] = set()
    workers = min(max_workers, max(4, len(hosts)))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_resolve_host_records, host, include_aaaa): host
            for host in hosts
        }
        for future in as_completed(futures):
            host, ips = future.result()
            if ips:
                verified.add(host)
                all_ips.update(ips)

    if all_ips:
        save_scope_ips(sorted(all_ips), source="dns_batch_verify")

    return verified


def _extract_ips_from_nslookup(text: str) -> set[str]:
    """
    Пытаемся вытащить IP именно из секции ответа по 'Name:' (чтобы не захватить IP DNS-сервера).
    Если секции нет — вернём пусто (тогда обработаем это выше/снаружи).
    """
    lines = [ln.strip() for ln in text.splitlines()]
    # Ищем строку вида "Name:" (Linux/macOS) или "Name:" (Windows)
    try:
        name_idx = next(
            i for i, ln in enumerate(lines) if ln.lower().startswith("name:")
        )
    except StopIteration:
        return set()

    ips: set[str] = set()
    # После Name: обычно идут строки Address/Addresses
    for ln in lines[name_idx + 1 :]:
        if not ln:
            break
        # вытащим все IP из строк секции
        ips.update(_IPV4_RE.findall(ln))
    #        ips.update([m for m in _IPV6_RE.findall(ln) if m and m != ":"])

    return ips


@lru_cache(maxsize=200_000)
def dns_has_ip_nslookup(hostname: str, timeout_sec: int = 3) -> bool:
    hostname = hostname.strip().rstrip(".")
    if not hostname:
        return False

    try:
        for rtype in ("A", "AAAA"):
            p = subprocess.run(
                ["nslookup", "-type=" + rtype, hostname],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            out = (p.stdout or "") + "\n" + (p.stderr or "")
            low = out.lower()

            if any(
                x in low
                for x in (
                    "nxdomain",
                    "non-existent domain",
                    "server can't find",
                    "no answer",
                    "no records",
                    "not found",
                )
            ):
                continue

            ips = _extract_ips_from_nslookup(out)
            if ips:
                save_scope_ips(ips)
                return True

        return False

    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _recon_dir():
    path = project_context.path / "recon" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path


# SCOPE DOMAIN LIST
def get_scope_domains():
    domains = project_context.get("scope", "domains", default=[])
    return domains if domains else []


# RUN SUBFINDER
def run_subfinder():
    console.print("[green]Scan first domain or all?[/green]")
    sel_domains = Prompt.ask(
        "[green]Choose[/green]", choices=["first", "all"], default="first"
    )

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "subfinder_raw.txt"

    if sel_domains == "first":
        domains = _get_first_scope_domain()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return

        console.rule("[cyan]subfinder[/cyan]")
        console.print(f"[yellow]→ {domains}[/yellow]")
        cmd = ["subfinder", "-d", domains, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    output.add(line)

    elif sel_domains == "all":
        domains = get_scope_domains()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return
        console.rule("[cyan]subfinder[/cyan]")
        for domain in domains:
            console.print(f"[yellow]→ {domain}[/yellow]")
            cmd = ["subfinder", "-d", domain, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line:
                        output.add(line)

    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")

    # checking for a DNS record
    verified = {d for d in output if dns_has_ip_nslookup(d)}
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="subfinder")
    console.print(f"[green]Found : {len(output)} subdomains[/green]")
    console.print(f"[green]Resolve : {len(verified)} subdomains[/green]")


# RUN SUBFINDER AIO
def run_subfinder_aio():
    domains = _get_first_scope_domain()
    if not domains:
        console.print("[red]Scope domains пуст. Добавьте домены в проект.[/red]")
        input("Enter...")
        return

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "subfinder_raw.txt"

    console.rule("[cyan]subfinder[/cyan]")

    console.print(f"[yellow]→ {domains}[/yellow]")
    cmd = ["subfinder", "-d", domains, "-silent"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                output.add(line)

    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")

    # checking for a DNS record
    verified = {d for d in output if dns_has_ip_nslookup(d)}
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="subfinder")
    console.print(f"[green]Found : {len(output)} subdomains[/green]")
    console.print(f"[green]Resolve : {len(verified)} subdomains[/green]")


# RUN FINDOMAIN
def run_findomain():
    env = _build_findomain_env()
    console.print("[green]Scan first domain or all?[/green]")
    sel_domains = Prompt.ask(
        "[green]Choose[/green]", choices=["first", "all"], default="first"
    )

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "findomain_raw.txt"

    if sel_domains == "first":
        domains = _get_first_scope_domain()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return

        console.rule("[cyan]findomain[/cyan]")
        console.print(f"[yellow]→ {domains}[/yellow]")
        cmd = ["findomain", "-t", domains, "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.stdout:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    output.add(line)

    elif sel_domains == "all":
        domains = get_scope_domains()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return
        console.rule("[cyan]findomain[/cyan]")
        for domain in domains:
            console.print(f"[yellow]→ {domain}[/yellow]")
            cmd = ["findomain", "-t", domain, "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if result.stdout:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line:
                        output.add(line)

    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")

    # checking for a DNS record
    verified = {d for d in output if dns_has_ip_nslookup(d)}
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="findomain")
    console.print(f"[green]Found : {len(output)} subdomains[/green]")
    console.print(f"[green]Resolve : {len(verified)} subdomains[/green]")


# RUN FINDOMAIN AIO
def run_findomain_aio():
    env = _build_findomain_env()
    domains = _get_first_scope_domain()
    if not domains:
        console.print("[red]Scope domains пуст.[/red]")
        input("Enter...")
        return

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "findomain_raw.txt"

    console.rule("[cyan]findomain[/cyan]")

    console.print(f"[yellow]→ {domains}[/yellow]")
    cmd = ["findomain", "-t", domains, "-q"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if result.stdout:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                output.add(line)

    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")

    # checking for a DNS record
    verified = {d for d in output if dns_has_ip_nslookup(d)}
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="findomain")
    console.print(f"[green]Found : {len(output)} subdomains[/green]")
    console.print(f"[green]Resolve : {len(verified)} subdomains[/green]")


# RUN DNSMAP
def run_dnsmap():
    #    domains = get_scope_domains()
    #    if not domains:
    #        console.print("[red]Scope domains пуст.[/red]")
    #        input("Enter...")
    #        return

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "dnsmap_raw.txt"
    wl_big = _wordlists_dir() / "wl_big.txt"
    wl_small = _wordlists_dir() / "wl_small.txt"
    wordlist = wl_small

    console.print("[green]Scan first domain or all?[/green]")
    sel_domains = Prompt.ask(
        "[green]Choose[/green]", choices=["first", "all"], default="first"
    )
    console.print(
        "* [bold cyan]Select WordList[/bold cyan]\n"
        " * [1] Big ~200 min 1 domain\n"
        " * [2] Small ~20 min 1 domain\n"
    )

    wordlist_mode = Prompt.ask("Select", choices=["1", "2"])

    if wordlist_mode == "1":
        wordlist = wl_big

    elif wordlist_mode == "2":
        wordlist = wl_small

    include_aaaa = Confirm.ask(
        "[yellow]Deep mode: also verify AAAA records?[/yellow]", default=False
    )
    chunk_mode = Confirm.ask("[yellow]Chunked dnsmap mode?[/yellow]", default=True)
    workers = 1
    if chunk_mode:
        workers = int(Prompt.ask("Workers (2-4 recommended)", default="4"))
        if workers < 1:
            workers = 1
        if workers > 4:
            workers = 4

    console.rule("[cyan]DNSMap[/cyan]")
    total_start = time.perf_counter()

    if sel_domains == "first":
        domains = _get_first_scope_domain()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return

        console.print("[cyan]Stage 1/4: prepare targets[/cyan]")
        console.print("[cyan]Stage 2/4: run dnsmap[/cyan]")
        brute_start = time.perf_counter()
        output.update(
            _run_dnsmap_for_domain(domains, wordlist, workers=workers, debug=True)
        )
        brute_elapsed = time.perf_counter() - brute_start

    elif sel_domains == "all":
        domains = get_scope_domains()
        if not domains:
            console.print("[red]Scope domains пуст.[/red]")
            input("Enter...")
            return
        console.print("[cyan]Stage 1/4: prepare targets[/cyan]")
        console.print("[cyan]Stage 2/4: run dnsmap[/cyan]")
        brute_start = time.perf_counter()
        for domain in domains:
            output.update(
                _run_dnsmap_for_domain(domain, wordlist, workers=workers, debug=True)
            )
        brute_elapsed = time.perf_counter() - brute_start

    console.print("[cyan]Stage 3/4: merge + dedupe[/cyan]")
    merge_start = time.perf_counter()
    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")
    merge_elapsed = time.perf_counter() - merge_start

    console.print("[cyan]Stage 4/4: verify DNS records[/cyan]")
    verify_start = time.perf_counter()
    verified = _batch_verify_hosts(output, include_aaaa=include_aaaa)
    verify_elapsed = time.perf_counter() - verify_start

    save_start = time.perf_counter()
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="dnsmap")
    save_elapsed = time.perf_counter() - save_start
    total_elapsed = time.perf_counter() - total_start

    console.print(f"[green]Found raw : {len(output)} subdomains[/green]")
    console.print(f"[green]Found : {len(verified)} subdomains[/green]")
    _print_stage_timing("dnsmap brute time", brute_elapsed)
    _print_stage_timing("merge time", merge_elapsed)
    _print_stage_timing("verify time", verify_elapsed)
    _print_stage_timing("save time", save_elapsed)
    _print_stage_timing("total time", total_elapsed)


# RUN DNSMAP AOI
def run_dnsmap_aio():
    domains = get_scope_domains()
    if not domains:
        console.print("[red]Scope domains пуст.[/red]")
        input("Enter...")
        return

    output = set()
    out_dir = _recon_dir()
    raw_file = out_dir / "dnsmap_raw.txt"
    wordlist = _wordlists_dir() / "wl_small.txt"
    workers = 4

    console.rule("[cyan]DNSMap[/cyan]")
    total_start = time.perf_counter()
    console.print("[cyan]Stage 1/4: prepare targets[/cyan]")
    console.print("[cyan]Stage 2/4: run dnsmap[/cyan]")
    brute_start = time.perf_counter()

    for domain in domains:
        output.update(
            _run_dnsmap_for_domain(domain, wordlist, workers=workers, debug=True)
        )

    brute_elapsed = time.perf_counter() - brute_start

    console.print("[cyan]Stage 3/4: merge + dedupe[/cyan]")
    merge_start = time.perf_counter()
    raw_file.write_text("\n".join(sorted(output)), encoding="utf-8")
    merge_elapsed = time.perf_counter() - merge_start

    console.print("[cyan]Stage 4/4: verify DNS records[/cyan]")
    verify_start = time.perf_counter()
    verified = _batch_verify_hosts(output, include_aaaa=False)
    verify_elapsed = time.perf_counter() - verify_start

    save_start = time.perf_counter()
    # save subdomains in scope.domains and subdomains.json
    save_subdomains(verified, source="dnsmap")
    save_elapsed = time.perf_counter() - save_start
    total_elapsed = time.perf_counter() - total_start

    console.print(f"[green]Found raw : {len(output)} subdomains[/green]")
    console.print(f"[green]Found : {len(verified)} subdomains[/green]")
    _print_stage_timing("dnsmap brute time", brute_elapsed)
    _print_stage_timing("merge time", merge_elapsed)
    _print_stage_timing("verify time", verify_elapsed)
    _print_stage_timing("save time", save_elapsed)
    _print_stage_timing("total time", total_elapsed)


# SHOW RESULTS
def show_results():
    json_file = _recon_dir() / "subdomains.json"
    if not json_file.exists():
        console.print("[red]Результатов пока нет[/red]")
        input("Enter...")
        return

    data = json.loads(json_file.read_text(encoding="utf-8"))
    console.rule("[green]Найденные поддомены[/green]")

    for d in data.get("all", []):
        console.print(d)

    console.print(f"\nВсего: {len(data.get('all', []))}")
    input("Enter...")


# MENU
def subdomains_menu():
    if not require_project():
        return

    while True:
        console.clear()
        console.rule("[bold cyan]Recon / Subdomains[/bold cyan]")

        console.print(
            "* [bold cyan]Recon / Subdomains menu[/bold cyan]\n"
            " * [1] Run DNSMap (WordList)\n"
            " * [2] Run Subfinder\n"
            " * [3] Run Findomain\n"
            " * [4] Run reverse DNS for IPs\n"
            " * [5] Enrich names found from IPs\n"
            " * [bold yellow][A] All in one[/bold yellow]\n"
            "* [bold cyan]Report[/bold cyan]\n"
            " * [01] Show results\n"
            "*[bold red] [0] Back[/bold red]\n"
        )

        choice = Prompt.ask("Choose", choices=["1", "2", "3", "4", "5", "A", "01", "0"])

        if choice == "1":
            run_dnsmap()
            input("Enter...")

        elif choice == "2":
            run_subfinder()
            input("Enter...")

        elif choice == "3":
            run_findomain()
            input("Enter...")

        elif choice == "4":
            run_revdns_subdomains_from_scope_ips()
            run_reverse_ip_passive()
            input("Enter...")

        elif choice == "5":
            run_ip_name_enrich()
            input("Enter...")

        elif choice == "A":
            run_dnsmap_aio()
            run_subfinder_aio()
            run_findomain_aio()
            #            run_revdns_subdomains_from_scope_ips()
            #            run_reverse_ip_passive()
            input("Enter...")

        elif choice == "01":
            show_results()

        elif choice == "0":
            break
