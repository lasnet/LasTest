import subprocess
import json
import time
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from core.project_context import project_context

console = Console()


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _nuclei_dir():
    path = project_context.path / "web" / "nuclei"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_alive_hosts():
    hosts = project_context.get("recon", "httpx", "root_alive_hosts", default=[])
    if hosts:
        return hosts

    # fallback для старых проектов
    hosts = project_context.get("recon", "alive_hosts", default=[])
    if hosts:
        return hosts

    for path in (
        project_context.path / "recon" / "httpx" / "alive_hosts.txt",
        project_context.path / "recon" / "httpx" / "root" / "alive_hosts.txt",
    ):
        if path.exists():
            return [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

    return []

def get_alive_urls():
    urls = project_context.get("recon", "httpx", "alive_urls", default=[])
    if urls:
        return urls

    f = project_context.path / "recon" / "httpx" / "urls" / "alive_urls.txt"
    if f.exists():
        return [line.strip() for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]

    return []

# ------------------------------------------------------------
# Main logic
# ------------------------------------------------------------

def run_nuclei():
    hosts = get_alive_hosts()
    urls = get_alive_urls()

    if not hosts and not urls:
        console.print("[red]Нет живых HTTP-хостов. Сначала запустите httpx.[/red]")
        input("Enter...")
        return

    console.rule("[bold red]nuclei — Web Vulnerability Scan[/bold red]")

    severities = (
        Prompt.ask(
            "Severity (через запятую)",
            default="critical,high,medium",
        )
        .replace(" ", "")
        .lower()
    )

    default_targets_count = len(urls) if urls else len(hosts)
    confirm = Confirm.ask(f"[yellow]Запустить nuclei по {default_targets_count} targets?[/yellow]")

    if not confirm:
        return

    out_dir = _nuclei_dir()

    console.print(
        "[1] Targets: Root alive hosts (httpx root)\n"
        "[2] Targets: Alive URLs (httpx URL mode)\n"
    )
    mode = Prompt.ask("Выберите targets", choices=["1", "2"], default="2")

    if mode == "2":
        targets = urls
    else:
        targets = hosts

    if not targets:
        console.print("[red]Для выбранного режима нет targets.[/red]")
        input("Enter...")
        return

    targets_file = out_dir / "targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")


    raw_json_file = out_dir / "nuclei_raw.json"
    findings_json = out_dir / "findings.json"
    findings_md = out_dir / "findings.md"

    # --------------------------------------------------------
    # Diagnostics (who / which nuclei)
    # --------------------------------------------------------

#    which = subprocess.run(
#        ["which", "nuclei"], capture_output=True, text=True
#    )
#    version = subprocess.run(
#        ["nuclei", "-version"], capture_output=True, text=True
#    )

#    console.print(f"[dim]nuclei path:[/dim] {which.stdout.strip()}")
#    console.print(
#        f"[dim]nuclei version:[/dim] "
#        f"{version.stdout.strip() or version.stderr.strip()}"
#    )

    # --------------------------------------------------------
    # Build command (IMPORTANT: -jsonl, not -json)
    # --------------------------------------------------------

    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-severity", severities,
        "-jsonl",
        "-silent",
    ]

    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start

    console.print(
        f"[dim]elapsed:[/dim] {elapsed:.2f}s  "
        f"[dim]returncode:[/dim] {result.returncode}"
    )

    # --------------------------------------------------------
    # Error handling
    # --------------------------------------------------------

    if result.returncode != 0:
        console.print("[red]nuclei завершился с ошибкой[/red]")

        if result.stdout:
            console.print("[yellow]stdout:[/yellow]")
            console.print(result.stdout[:2000])

        if result.stderr:
            console.print("[yellow]stderr:[/yellow]")
            console.print(result.stderr[:2000])

        input("Enter...")
        return

    if not result.stdout.strip():
        console.print("[green]nuclei не нашёл уязвимостей[/green]")
        input("Enter...")
        return

    # --------------------------------------------------------
    # Parse JSONL output
    # --------------------------------------------------------

    raw_data = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_data.append(json.loads(line))
        except json.JSONDecodeError:
            # nuclei иногда пишет не-JSON строки
            continue

    raw_json_file.write_text(
        json.dumps(raw_data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Normalize findings
    # --------------------------------------------------------

    findings = []

    for item in raw_data:
        info = item.get("info", {})

        findings.append({
            "template_id": item.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "host": item.get("host"),
            "matched_at": item.get("matched-at"),
            "description": info.get("description", ""),
            "references": info.get("reference", []),
        })

    findings_json.write_text(
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

    # --------------------------------------------------------
    # Markdown summary (for reports)
    # --------------------------------------------------------

    with open(findings_md, "w", encoding="utf-8") as f:
        f.write("# Nuclei Findings\n\n")

        for fnd in findings:
            f.write(
                f"## {fnd['name']}\n"
                f"- **Severity:** {fnd['severity']}\n"
                f"- **Host:** {fnd['matched_at']}\n"
                f"- **Template:** {fnd['template_id']}\n\n"
            )

    console.print(f"[red]Найдено уязвимостей: {len(findings)}[/red]")
    input("Enter...")


# ------------------------------------------------------------
# Show results
# ------------------------------------------------------------

def show_findings():
    findings_json = _nuclei_dir() / "findings.json"

    if not findings_json.exists():
        console.print("[yellow]Результатов пока нет[/yellow]")
        input("Enter...")
        return

    data = json.loads(findings_json.read_text(encoding="utf-8"))

    console.rule("[bold red]Nuclei Findings[/bold red]")

    for f in data.get("findings", []):
        console.print(
            f"[{f['severity'].upper()}] "
            f"{f['name']} → {f['matched_at']}"
        )

    console.print(f"\nВсего: {data.get('count', 0)}")
    input("Enter...")
