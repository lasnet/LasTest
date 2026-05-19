import json
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from core.project_context import project_context
from modules.recon.storage import merge_urls_into_all, save_urls_snapshot

console = Console()


DEFAULT_MATCH_CODES = "200,204,301,302,307,308"


def _json_dumps(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _wordlists_dir() -> Path:
    return Path(__file__).resolve().parent / "worldlist"


def _ffuf_dir() -> Path:
    p = project_context.path / "recon" / "ffuf"
    (p / "runs").mkdir(parents=True, exist_ok=True)
    return p


def _get_scope_domains() -> list[str]:
    return project_context.get("scope", "domains", default=[])


def _safe_name(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = s.replace("/", "_")
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s)
    return s[:120] or "target"


def run_ffuf_dirs():
    if not project_context.active:
        console.print("[red]Сначала открой проект[/red]")
        input("Enter...")
        return

    targets = _get_scope_domains()
    if not targets:
        console.print("[yellow]Scope domains пуст.[/yellow]")
        input("Enter...")
        return

    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        console.print("[red]ffuf не найден. Установи ffuf и повтори.[/red]")
        input("Enter...")
        return

    out_dir = _ffuf_dir()
    runs_dir = out_dir / "runs"
    discovered_all: list[str] = []

    console.rule("[bold cyan]Content discovery — ffuf[/bold cyan]")

    wordlist = _wordlists_dir() / "fav-wordlist.txt"
    if not Path(wordlist).exists():
        console.print(f"[red]Wordlist not found:[/red] {wordlist}")
        input("Enter...")
        return

    # Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,308)
    match_codes = Prompt.ask(
        "Match status codes (-mc)", default=DEFAULT_MATCH_CODES
    ).replace(" ", "")

    # Number of concurrent threads
    threads = int(Prompt.ask("Parallel requests (-t)", default="40"))
    # Rate of requests per second
    rate = int(Prompt.ask("Rate limit in sec (-rate)", default="20"))
    # HTTP request timeout in seconds
    timeout = int(Prompt.ask("HTTP timeout seconds (-timeout)", default="10"))

    #    # чтобы не убить прод: можно ограничить количество хостов
    #    limit_hosts = Prompt.ask("Limit hosts (0 = no limit)", default="0")
    #    try:
    #        limit_hosts_i = int(limit_hosts)
    #    except ValueError:
    #        limit_hosts_i = 0

    #    if limit_hosts_i > 0:
    #        targets = targets[:limit_hosts_i]

    ok = Confirm.ask(f"[yellow]Run ffuf for {len(targets)} hosts?[/yellow]")
    if not ok:
        return

    for base in targets:
        base = base.strip()
        if not base:
            continue

        # если вдруг попался hostname без схемы — добавим https
        if not base.startswith(("http://", "https://")):
            base = "https://" + base

        # нормализуем base, убираем завершающий /
        base = base.rstrip("/")

        url_template = f"{base}/FUZZ"

        safe = _safe_name(base)
        out_json = runs_dir / f"{safe}.json"

        cmd = [
            ffuf_path,
            "-u",
            url_template,
            "-w",
            str(wordlist),
            "-of",
            "json",
            "-o",
            str(out_json),
            "-t",
            str(threads),
            "-rate",
            str(rate),
            "-timeout",
            str(timeout),
            "-mc",
            match_codes,
            "-s",
        ]

        console.print(f"[cyan]→ ffuf[/cyan] {base}")
        res = subprocess.run(cmd, capture_output=True, text=True)

        if res.returncode != 0:
            console.print(f"[red]ffuf error for {base}[/red]")
            if res.stderr.strip():
                console.print(res.stderr[:2000])
            continue

        if not out_json.exists():
            continue

        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except Exception:
            continue

        results = data.get("results", [])
        for r in results:
            u = r.get("url")
            if u:
                discovered_all.append(u)

    # дедуп общий список
    discovered_all = sorted(set(discovered_all))

    # сохраняем агрегаты
    discovered_txt = out_dir / "discovered_urls.txt"
    summary_json = out_dir / "ffuf_summary.json"

    discovered_txt.write_text("\n".join(discovered_all), encoding="utf-8")
    summary_json.write_text(
        _json_dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "targets_count": len(targets),
                "found_count": len(discovered_all),
                "wordlist": str(wordlist),
                "match_codes": match_codes,
                "threads": threads,
                "rate": rate,
                "timeout": timeout,
            }
        ),
        encoding="utf-8",
    )

    # мерджим в общий пул URL
    snapshot = save_urls_snapshot(discovered_all, source="ffuf")
    before, after = merge_urls_into_all(discovered_all)

    # сохраняем в config (для истории)
    project_context.set(discovered_all, "recon", "urls", "ffuf")

    console.print(f"[green]ffuf найдено URL:[/green] {len(discovered_all)}")
    console.print(f"[green]all_urls.txt:[/green] {before} -> {after}")
    console.print(f"[dim]snapshot:[/dim] {snapshot}")
    input("Enter...")


def run_ffuf_dirs_aio():

    targets = _get_scope_domains()
    if not targets:
        console.print("[yellow]Scope domains пуст.[/yellow]")
        input("Enter...")
        return

    ffuf_path = shutil.which("ffuf")
    if not ffuf_path:
        console.print("[red]ffuf не найден. Установи ffuf и повтори.[/red]")
        input("Enter...")
        return

    out_dir = _ffuf_dir()
    runs_dir = out_dir / "runs"
    discovered_all: list[str] = []

    #    console.rule("[bold cyan]Content discovery — ffuf (dirs + extensions)[/bold cyan]")

    wordlist = _wordlists_dir() / "fav-wordlist.txt"
    if not Path(wordlist).exists():
        console.print(f"[red]Wordlist не найден:[/red] {wordlist}")
        input("Enter...")
        return

    exts = ".php"
    match_codes = DEFAULT_MATCH_CODES

    threads = 20
    rate = 20
    timeout = 10

    # чтобы не убить прод: можно ограничить количество хостов
    limit_hosts = 0
    try:
        limit_hosts_i = int(limit_hosts)
    except ValueError:
        limit_hosts_i = 0

    if limit_hosts_i > 0:
        targets = targets[:limit_hosts_i]

    for base in targets:
        base = base.strip()
        if not base:
            continue

        # если вдруг попался hostname без схемы — добавим https
        if not base.startswith(("http://", "https://")):
            base = "https://" + base

        # нормализуем base, убираем завершающий /
        base = base.rstrip("/")

        url_template = f"{base}/FUZZ"

        safe = _safe_name(base)
        out_json = runs_dir / f"{safe}.json"

        cmd = [
            ffuf_path,
            "-u",
            url_template,
            "-w",
            str(wordlist),
            "-of",
            "json",
            "-o",
            str(out_json),
            "-t",
            str(threads),
            "-rate",
            str(rate),
            "-timeout",
            str(timeout),
            "-mc",
            match_codes,
            "-s",
        ]

        # расширения
        if exts:
            cmd.extend(["-e", exts])

        console.print(f"[cyan]→ ffuf[/cyan] {base}")
        res = subprocess.run(cmd, capture_output=True, text=True)

        if res.returncode != 0:
            console.print(f"[red]ffuf error for {base}[/red]")
            if res.stderr.strip():
                console.print(res.stderr[:2000])
            continue

        if not out_json.exists():
            continue

        try:
            data = json.loads(out_json.read_text(encoding="utf-8"))
        except Exception:
            continue

        results = data.get("results", [])
        for r in results:
            u = r.get("url")
            if u:
                discovered_all.append(u)

    # дедуп общий список
    discovered_all = sorted(set(discovered_all))

    # сохраняем агрегаты
    discovered_txt = out_dir / "discovered_urls.txt"
    summary_json = out_dir / "ffuf_summary.json"

    discovered_txt.write_text("\n".join(discovered_all), encoding="utf-8")
    summary_json.write_text(
        _json_dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "targets_count": len(targets),
                "found_count": len(discovered_all),
                "wordlist": str(wordlist),
                "extensions": exts,
                "match_codes": match_codes,
                "threads": threads,
                "rate": rate,
                "timeout": timeout,
            }
        ),
        encoding="utf-8",
    )

    # мерджим в общий пул URL
    snapshot = save_urls_snapshot(discovered_all, source="ffuf")
    before, after = merge_urls_into_all(discovered_all)

    # сохраняем в config (для истории)
    project_context.set(discovered_all, "recon", "urls", "ffuf")

    console.print(f"[green]ffuf найдено URL:[/green] {len(discovered_all)}")
    console.print(f"[green]all_urls.txt:[/green] {before} -> {after}")
    console.print(f"[dim]snapshot:[/dim] {snapshot}")


def show_ffuf_results():
    if not project_context.active:
        console.print("[red]Сначала открой проект[/red]")
        input("Enter...")
        return

    out_dir = _ffuf_dir()
    summary = out_dir / "ffuf_summary.json"
    discovered = out_dir / "discovered_urls.txt"

    console.rule("[bold cyan]ffuf results[/bold cyan]")

    if summary.exists():
        console.print(summary.read_text(encoding="utf-8")[:2000])
    else:
        console.print("[yellow]Нет summary (ещё не запускали ffuf)[/yellow]")

    if discovered.exists():
        lines = [
            x for x in discovered.read_text(encoding="utf-8").splitlines() if x.strip()
        ]
        console.print(f"\n[green]URLs:[/green] {len(lines)}")
        for x in lines[:30]:
            console.print(f"- {x}")
        if len(lines) > 30:
            console.print("[dim]... (показаны первые 30)[/dim]")
    input("Enter...")


def ffuf_menu():
    if not project_context.active:
        console.print("[red]Сначала открой проект[/red]")
        input("Enter...")
        return

    while True:
        console.clear()
        console.rule("[bold cyan]Recon / Content discovery (ffuf)[/bold cyan]")

        console.print("[1] Run ffuf\n[2] Show results\n[0] Назад")

        choice = Prompt.ask("Select", choices=["1", "2", "0"])
        if choice == "1":
            run_ffuf_dirs()
        elif choice == "2":
            show_ffuf_results()
        elif choice == "0":
            break
