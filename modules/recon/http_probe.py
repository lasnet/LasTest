import subprocess
import json
from datetime import datetime
from rich.console import Console
from core.project_context import project_context
import shutil

console = Console()


def _httpx_dir():
    path = project_context.path / "recon" / "httpx"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_subdomains():
    subdomains_file = project_context.path / "recon" / "subdomains" / "subdomains.json"

    if not subdomains_file.exists():
        return []

    data = json.loads(subdomains_file.read_text(encoding="utf-8"))
    return data.get("all", [])


def run_httpx_root():
    subdomains = get_subdomains()

    if not shutil.which("httpx"):
        console.print("[red]httpx не найден в PATH[/red]")
        input("Enter...")
        return

    if not subdomains:
        console.print("[red]Нет поддоменов. Сначала запустите Subdomains.[/red]")
        input("Enter...")
        return

    out_dir = _httpx_dir()

    input_file = out_dir / "input.txt"
    input_file.write_text("\n".join(subdomains), encoding="utf-8")

    raw_json = out_dir / "httpx_raw.json"
    alive_txt = out_dir / "alive_hosts.txt"
    alive_json = out_dir / "alive_hosts.json"

    console.rule("[bold cyan]httpx — HTTP probing[/bold cyan]")

    cmd = [
        "httpx",
        "-l",
        str(input_file),
        "-json",
        "-title",
        "-status-code",
        "-tech-detect",
        "-follow-redirects",
        "-silent",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if not result.stdout:
        console.print("[yellow]httpx не вернул результатов[/yellow]")
        input("Enter...")
        return

    raw_lines = result.stdout.strip().splitlines()
    raw_data = [json.loads(line) for line in raw_lines]

    raw_json.write_text(
        json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    alive_hosts = []

    for item in raw_data:
        alive_hosts.append(
            {
                "url": item.get("url"),
                "host": item.get("host"),
                "scheme": item.get("scheme"),
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "tech": item.get("tech", []),
            }
        )

    alive_json.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(alive_hosts),
                "hosts": alive_hosts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    alive_txt.write_text("\n".join([h["url"] for h in alive_hosts]), encoding="utf-8")

    root_alive_hosts = [h["url"] for h in alive_hosts]

    # Новый ключ для root HTTP probing
    project_context.set(root_alive_hosts, "recon", "httpx", "root_alive_hosts")

    # Оставляем старый ключ для обратной совместимости
    project_context.set(root_alive_hosts, "recon", "alive_hosts")

    console.print(f"[green]Найдено живых хостов: {len(alive_hosts)}[/green]")
    input("Enter...")


def show_alive_hosts():
    alive_json = _httpx_dir() / "alive_hosts.json"

    if not alive_json.exists():
        console.print("[red]Результатов пока нет[/red]")
        input("Enter...")
        return

    data = json.loads(alive_json.read_text(encoding="utf-8"))

    console.rule("[green]Живые HTTP-хосты[/green]")

    for h in data.get("hosts", []):
        console.print(f"{h['url']} [{h['status_code']}] {h.get('title', '')}")

    console.print(f"\nВсего: {data.get('count', 0)}")
    input("Enter...")
