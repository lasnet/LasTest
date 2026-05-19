import shutil
import subprocess
from datetime import datetime

from rich.console import Console
from core.project_context import project_context
from modules.recon.storage import save_subdomains

console = Console()

def _recon_dir():
    path = project_context.path / "recon" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_scope_ips() -> list[str]:
    ips = project_context.get("scope", "ips", default=[])
    # нормализация: убрать пробелы/пустые
    cleaned = []
    for ip in ips:
        if not ip:
            continue
        ip = str(ip).strip()
        if ip:
            cleaned.append(ip)
    # дедуп с сохранением порядка
    return list(dict.fromkeys(cleaned))


def _parse_hakrevdns_output(stdout: str) -> set[str]:
    """
    hakrevdns stdout обычно:  <ip>\t<hostname.>
    Берем hostname, убираем конечную точку.
    """
    out = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host = parts[1].strip()
        # часто PTR возвращается с точкой на конце
        if host.endswith("."):
            host = host[:-1]
        host = host.lower().strip()
        if host:
            out.add(host)
    return out


def run_revdns_subdomains_from_scope_ips():
    """
    Берет scope.ips -> делает reverse DNS (PTR) через hakrevdns -> сохраняет найденные hostnames как subdomains
    + добавляет их в scope.domains (через save_subdomains, если у тебя там это делается).
    """
    if shutil.which("hakrevdns") is None:
        console.print("[red]Не найден hakrevdns в PATH.[/red]")
        console.print("Установи: [cyan]go install github.com/hakluke/hakrevdns@latest[/cyan]")
        input("Enter...")
        return

    ips = get_scope_ips()
    if not ips:
        console.print("[yellow]В scope.ips пусто — нечего резолвить.[/yellow]")
        input("Enter...")
        return

    out_dir = _recon_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    console.rule("[cyan]Reverse DNS (PTR) -> subdomains (hakrevdns)[/cyan]")
    console.print(f"[green]IP в scope:[/green] {len(ips)}")


    # -U = использовать дефолтные резолверы, -t = потоки
    cmd = ["hakrevdns", "-U", "-t", "40"]

    # подаем IP на stdin (как в README)
    inp = "\n".join(ips) + "\n"
    result = subprocess.run(cmd, input=inp, capture_output=True, text=True)

    if result.stderr:
        # hakrevdns иногда пишет ошибки резолва в stderr — не всегда критично
        console.print("[yellow]hakrevdns stderr (можно игнорировать, если есть результаты):[/yellow]")
        console.print(result.stderr.strip())

    found_hosts = _parse_hakrevdns_output(result.stdout)

    # сохраним “сырое” в файл на всякий
    raw_file = out_dir / "revdns_hakrevdns_raw.txt"
    raw_file.write_text(result.stdout or "", encoding="utf-8")

    if not found_hosts:
        console.print("[yellow]PTR-записей не найдено (или rDNS не настроен).[/yellow]")
        return

    console.print(f"[green]Найдено hostnames:[/green] {len(found_hosts)}")
    # сохраняем как subdomains, а там же (как у тебя) они попадут и в scope.domains
    save_subdomains(found_hosts, source="hakrevdns_ptr")

    # можно сохранить еще и сводный отчет
    report_file = out_dir / "revdns_report.txt"
    report_file.write_text(
        "updated_at: " + datetime.now().isoformat() + "\n"
        + "\n".join(sorted(found_hosts)) + "\n",
        encoding="utf-8"
    )

    console.print(f"[cyan]Raw:[/cyan] {raw_file}")
    console.print(f"[cyan]Report:[/cyan] {report_file}")
