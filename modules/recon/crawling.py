import subprocess
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt

from core.project_context import project_context
from modules.recon.storage import merge_urls_into_all, save_urls_snapshot

console = Console()

"""COMMON_ENTRY_PATHS = [
    "/", "/app", "/apps", "/webapp", "/portal", "/internal", "/private", "/hidden", "/legacy",
     "/dev", "/development", "/staging", "/prod", "/public", "/uploads", "/files",
     "/assets", "/images", "/img", "/css", "/js", "/fonts", "/vendor", "/includes",
     "/cgi-bin", "/server-status", "/.well-known", "/wp-login.php", "/administrator",
     "/user/login", "/admin/login", "/nova", "/ssl", "/cert", "/certs", "/.pem", "/.crt",
     "/.key", "/security", "/secure", "/phpmyadmin", "/mysql", "/db", "/database", "/dba",
     "/pma", "/adminer", "/session", "/debug", "/phpinfo", "/test", "/testing", "/health",
     "/status", "/ping", "/.git", "/.git/config", "/.svn", "/backup", "/backups", "/old",
     "/new", "/tmp", "/temp", "/archive", "/www", "/web", "/src", "/source", "/api",
     "/v1", "/v2", "/graphql", "/rest", "/swagger", "/openapi", "/docs", "/documentation",
     "/config", "/configuration", "/env", "/.env", "/settings", "/manifest.json",
     "/sitemap.xml", "/sitemap", "/robots.txt", "/login", "/signin", "/auth", "/sso",
     "/oauth", "/logout", "/signout", "/register", "/signup", "/password",
     "/forgot-password", "/reset-password", "/2fa", "/admin", "/adminpanel",
     "/administrator", "/wp-admin", "/dashboard", "/login", "/controlpanel",
     "/manager", "/backend", "/cp"
]"""

COMMON_ENTRY_PATHS = ["/"]

def _get_scope_domains() -> list[str]:
    return project_context.get("scope", "domains", default=[])


def _build_seeds_from_domains(domains: list[str]) -> list[str]:
    seeds = []
    for d in domains:
        d = (d or "").strip()
        if not d:
            continue
        # чаще всего такие порталы на https
        for p in COMMON_ENTRY_PATHS:
            seeds.append(f"https://{d}{p}")
        # при желании можно добавить http:
        # for p in COMMON_ENTRY_PATHS:
        #     seeds.append(f"http://{d}{p}")
    return list(dict.fromkeys(seeds))


def _ensure_dir() -> Path:
    p = project_context.path / "recon" / "katana"
    p.mkdir(parents=True, exist_ok=True)
    return p

def _get_all_urls() -> list[str]:
    """
    Берём объединённый пул URL из recon/urls/all_urls.txt.
    Это общий raw-пул после passive discovery / ffuf / katana merge.
    """
    f = project_context.path / "recon" / "urls" / "all_urls.txt"
    if f.exists():
        return [line.strip() for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]

    return []

def run_katana():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    console.print(
        "[1] Targets: All urls - Hard Scan\n"
        "[2] Targets: All urls - Request Scan\n"
        "[3] Targets: Scope Domain - Hard Scan\n"
        "[4] Targets: Scope Domain - Request Scan\n"
    )
    target_mode = Prompt.ask("Select targets", choices=["1", "2", "3", "4"], default="1")

    targets = []
    if target_mode == "1":
#        targets = list(dict.fromkeys(_get_all_urls() + _get_scope_domains()))
        targets = list(dict.fromkeys(list(_get_all_urls()) + list(_get_scope_domains())))
        depth = 3
        js_crawl = "y"
        fx_crawl = "y"
        aff_crawl = "y"
        concurrency = 10
        if not targets:
            console.print("[yellow]Not urls and scope domain[/yellow]")
            input("Enter...")
            return

    elif target_mode == "2":
        targets = list(dict.fromkeys(_get_all_urls() + _get_scope_domains()))
        depth = Prompt.ask("Depth (глубина)", default="2")
        js_crawl = Prompt.ask("Aнализировать JavaScript? [y/n]", choices=["y", "n"], default="y") == "y"
        fx_crawl = Prompt.ask("Checking forms? [y/n]", choices=["y", "n"], default="y") == "y"
        aff_crawl = Prompt.ask("Enable automatic form filling? [y/n]", choices=["y", "n"], default="y") == "y"
        concurrency = Prompt.ask("Number of concurrent fetchers to use", default="10")
        if not targets:
            console.print("[yellow]Not urls and scope domain[/yellow]")
            input("Enter...")
            return

    elif target_mode == "3":
        domains = _get_scope_domains()
        depth = 3
        js_crawl = "y"
        fx_crawl = "y"
        aff_crawl = "y"
        concurrency = 10
        if not domains:
            console.print("[yellow]Scope domain is empty[/yellow]")
            input("Enter...")
            return
        targets = _build_seeds_from_domains(domains)
        if not targets:
            console.print("[yellow]No targets...[/yellow]")
            input("Enter...")
            return

    elif target_mode == "4":
        domains = _get_scope_domains()
        depth = Prompt.ask("Depth (глубина)", default="2")
        js_crawl = Prompt.ask("Aнализировать JavaScript? [y/n]", choices=["y", "n"], default="y") == "y"
        fx_crawl = Prompt.ask("Checking forms? [y/n]", choices=["y", "n"], default="y") == "y"
        aff_crawl = Prompt.ask("Enable automatic form filling? [y/n]", choices=["y", "n"], default="y") == "y"
        concurrency = Prompt.ask("Number of concurrent fetchers to use", default="10")
        if not domains:
            console.print("[yellow]Scope domain is empty[/yellow]")
            input("Enter...")
            return
        targets = _build_seeds_from_domains(domains)
        if not targets:
            console.print("[yellow]No targets...[/yellow]")
            input("Enter...")
            return

    # аккуратный лимит чтобы не улететь в бесконечность
    MAX_TARGETS = 3000
    if len(targets) > MAX_TARGETS:
        console.print(f"[yellow]Targets слишком много ({len(targets)}). Обрезаю до {MAX_TARGETS}.[/yellow]")
        targets = targets[:MAX_TARGETS]


    # Проверим наличие katana
    which = subprocess.run(["which", "katana"], capture_output=True, text=True)
    if which.returncode != 0 or not which.stdout.strip():
        console.print("[red]katana не найден. Установи его и повтори.[/red]")
        input("Enter...")
        return

    try:
        concurrency_i = int(concurrency)
        if concurrency_i < 10:
            concurrency_i = 10
    except ValueError:
        concurrency_i = 10

    try:
        depth_i = int(depth)
        if depth_i < 1:
            depth_i = 1
    except ValueError:
        depth_i = 2

    console.print("[red]***katana started scanning***[/red]")

    out_dir = _ensure_dir()
    targets_file = out_dir / "targets.txt"
    raw_out = out_dir / "katana_raw.txt"
    urls_out = out_dir / "katana_urls.txt"

    targets_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")

    cmd = [
        "katana",
        "-list", str(targets_file),
        "-d", str(depth_i),
        "-silent",
        "-nc",
        "-c", str(concurrency_i),
        "-s", "depth-first",
        "-o", str(raw_out),
    ]

    if js_crawl:
        cmd.append("-jc")
    if fx_crawl:
        cmd.append("-fx")
    if aff_crawl:
        cmd.append("-aff")

    start = datetime.now()
    res = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = (datetime.now() - start).total_seconds()

    if res.returncode != 0:
        console.print("[red]katana завершился с ошибкой[/red]")
        if res.stdout.strip():
            console.print("[yellow]stdout:[/yellow]")
            console.print(res.stdout[:2000])
        if res.stderr.strip():
            console.print("[yellow]stderr:[/yellow]")
            console.print(res.stderr[:2000])
        input("Enter...")
        return

    # katana пишет результат в raw_out (мы задали -o)
    if not raw_out.exists():
        console.print("[yellow]katana не создал output файл[/yellow]")
        input("Enter...")
        return

    urls = []
    for line in raw_out.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    urls = sorted(set(urls))
    urls_out.write_text("\n".join(urls), encoding="utf-8")

    # Сохраним в config.yaml (не руками — автоматически)
    project_context.set(urls, "recon", "urls", "katana")

    snapshot = save_urls_snapshot(urls, source="katana")
    before, after = merge_urls_into_all(urls)
    console.print(f"[green]katana urls:[/green] {len(urls)}  [dim]elapsed:[/dim] {elapsed:.1f}s")
    console.print(f"[green]all_urls.txt:[/green] {before} -> {after}")
    console.print(f"[dim]snapshot:[/dim] {snapshot}")

    input("Enter...")
    
def run_katana_aio():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    targets = list(dict.fromkeys(_get_all_urls() + _get_scope_domains()))
    if not targets:
        console.print("[yellow]Not urls and scope domain[/yellow]")
        input("Enter...")
        return

    # аккуратный лимит чтобы не улететь в бесконечность
    MAX_TARGETS = 3000
    if len(targets) > MAX_TARGETS:
        console.print(f"[yellow]Targets слишком много ({len(targets)}). Обрезаю до {MAX_TARGETS}.[/yellow]")
        targets = targets[:MAX_TARGETS]


    # Проверим наличие katana
    which = subprocess.run(["which", "katana"], capture_output=True, text=True)
    if which.returncode != 0 or not which.stdout.strip():
        console.print("[red]katana не найден. Установи его и повтори.[/red]")
        input("Enter...")
        return

    console.print("[yellow]Run katana[/yellow]")

    out_dir = _ensure_dir()
    targets_file = out_dir / "targets.txt"
    raw_out = out_dir / "katana_raw.txt"
    urls_out = out_dir / "katana_urls.txt"

    targets_file.write_text("\n".join(sorted(set(targets))), encoding="utf-8")

    cmd = [
        "katana",
        "-list", str(targets_file),
        "-d", "3",
        "-silent",
        "-nc",
        "-jc", "-iqp", "aff", "-fx",
        "-c", "10",
        "-s", "depth-first",
        "-o", str(raw_out),
    ]

    start = datetime.now()
    res = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = (datetime.now() - start).total_seconds()

    if res.returncode != 0:
        console.print("[red]katana завершился с ошибкой[/red]")
        if res.stdout.strip():
            console.print("[yellow]stdout:[/yellow]")
            console.print(res.stdout[:2000])
        if res.stderr.strip():
            console.print("[yellow]stderr:[/yellow]")
            console.print(res.stderr[:2000])
        input("Enter...")
        return

    # katana пишет результат в raw_out (мы задали -o)
    if not raw_out.exists():
        console.print("[yellow]katana не создал output файл[/yellow]")
        input("Enter...")
        return

    urls = []
    for line in raw_out.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)

    urls = sorted(set(urls))
    urls_out.write_text("\n".join(urls), encoding="utf-8")

    # Сохраним в config.yaml (не руками — автоматически)
    project_context.set(urls, "recon", "urls", "katana")

    snapshot = save_urls_snapshot(urls, source="katana")
    before, after = merge_urls_into_all(urls)
    console.print(f"[green]katana urls:[/green] {len(urls)}  [dim]elapsed:[/dim] {elapsed:.1f}s")
    console.print(f"[green]all_urls.txt:[/green] {before} -> {after}")
    console.print(f"[dim]snapshot:[/dim] {snapshot}")
