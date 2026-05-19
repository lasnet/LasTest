import subprocess
import json
from datetime import datetime
from rich.console import Console
from core.project_context import project_context
from modules.recon.storage import merge_urls_into_all, save_urls_snapshot

console = Console()


def _urls_dir():
    path = project_context.path / "recon" / "urls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_domains():
    return project_context.get("scope", "domains", default=[])


def run_passive_url_discovery():
    domains = get_domains()

    if not domains:
        console.print("[red]No scope domains[/red]")
        input("Enter...")
        return

    console.rule("[bold cyan]Passive URL discovery (gau + waybackurls)[/bold cyan]")

    out_dir = _urls_dir()
    raw_file = out_dir / "passive_raw.txt"
    json_file = out_dir / "passive_urls.json"

    all_urls = set()

    # -------- gau --------
    console.print("[yellow]Run gau[/yellow]")
    for domain in domains:
        cmd = ["gau", domain]
        console.print(f"[white]→ {domain}[/white]")
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("http"):
                all_urls.add(line.strip())

    # -------- waybackurls --------
    console.print("[yellow]Run waybackurls[/yellow]")
    for domain in domains:
        cmd = ["waybackurls", domain]
        console.print(f"[white]→ {domain}[/white]")
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("http"):
                all_urls.add(line.strip())

    if not all_urls:
        console.print("[yellow]URL not found[/yellow]")
        return

    # -------- save raw --------
    raw_file.write_text("\n".join(sorted(all_urls)), encoding="utf-8")
    passive_snapshot = save_urls_snapshot(all_urls, source="passive")

    # -------- normalize --------
    normalized = []

    for url in all_urls:
        normalized.append(
            {
                "url": url,
                "source": "passive",
            }
        )

    json_file.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(normalized),
                "urls": normalized,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    before, after = merge_urls_into_all(all_urls)

    console.print(f"[green]Found URL: {len(all_urls)}[/green]")
    console.print(f"[green]all_urls.txt:[/green] {before} -> {after}")
    console.print(f"[dim]snapshot:[/dim] {passive_snapshot}")
