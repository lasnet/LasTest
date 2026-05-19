from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console
from rich.prompt import Prompt

from core.project_context import project_context
from core.url_utils import dedupe_urls  # уже есть :contentReference[oaicite:4]{index=4}

console = Console()


def _targets_urls_dir() -> Path:
    path = project_context.path / "recon" / "targets" / "urls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _get_all_urls_raw() -> list[str]:
    # Используем тот же источник, что и httpx_url_mode :contentReference[oaicite:5]{index=5}
    urls_file = project_context.path / "recon" / "urls" / "all_urls.txt"
    if not urls_file.exists():
        return []
    return [
        line.strip()
        for line in urls_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip().startswith("http")
    ]


def run_targets_url_normalize():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    console.clear()
    console.rule("[bold cyan]Targets — URL normalize (A1)[/bold cyan]")

    urls_raw = _get_all_urls_raw()
    if not urls_raw:
        console.print("[red]Нет URL для нормализации. Сначала запусти URL discovery.[/red]")
        input("Enter...")
        return

    # Лимит на хост — опционально (у тебя в httpx сейчас None) :contentReference[oaicite:6]{index=6}
    prm_limit = Prompt.ask(
        "Лимит URL на host (scheme+host). 0 = без лимита",
        default="0"
    )
    try:
        max_per_host = int(prm_limit)
    except ValueError:
        max_per_host = 0

    max_per_host = None if max_per_host <= 0 else max_per_host

    urls_norm = dedupe_urls(urls_raw, max_per_host=max_per_host)

    out_dir = _targets_urls_dir()
    raw_snapshot = out_dir / "input_urls_raw.txt"
    out_txt = out_dir / "targets_urls_normalized.txt"
    meta_json = out_dir / "targets_urls_meta.json"

    # сохраняем снимок исходных (для повторяемости)
    raw_snapshot.write_text("\n".join(urls_raw), encoding="utf-8")

    # сохраняем нормализованные (стабильно сортируем)
    urls_norm_sorted = sorted(urls_norm)
    out_txt.write_text("\n".join(urls_norm_sorted), encoding="utf-8")

    # метрики + топ хостов (чтобы понимать распределение)
    host_counter = Counter()
    for u in urls_norm_sorted:
        p = urlsplit(u)
        host_counter[f"{p.scheme}://{p.netloc}"] += 1

    meta = {
        "generated_at": datetime.now().isoformat(),
        "input_count": len(urls_raw),
        "output_count": len(urls_norm_sorted),
        "removed_count": len(urls_raw) - len(urls_norm_sorted),
        "max_per_host": max_per_host,
        "top_hosts": host_counter.most_common(20),
    }

    meta_json.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    # сохраняем в контекст (для следующих модулей)
    project_context.set(urls_norm_sorted, "recon", "targets", "normalized_urls")

    console.print(f"[green]Нормализовано URL: {len(urls_norm_sorted)}[/green]")
    console.print(f"[dim]Saved:[/dim] {out_txt}")
