from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from rich.console import Console

from core.project_context import project_context

console = Console()

TECH_BUCKETS = {
    "wordpress": [re.compile(r"\bwordpress\b", re.I)],
    "jira": [re.compile(r"\bjira\b", re.I), re.compile(r"atlassian", re.I)],
    "grafana": [re.compile(r"\bgrafana\b", re.I)],
    "nginx": [re.compile(r"\bnginx\b", re.I), re.compile(r"openresty", re.I)],
    "php": [re.compile(r"\bphp\b", re.I), re.compile(r"php-fpm", re.I)],
    "spring": [re.compile(r"\bspring\b", re.I), re.compile(r"spring boot", re.I)],
}


def _routing_dir() -> Path:
    path = project_context.path / "recon" / "targets" / "routing"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _httpx_targets_jsonl_path() -> Path:
    # привязываемся к твоему httpx месту хранения :contentReference[oaicite:12]{index=12}
    return project_context.path / "recon" / "httpx" / "urls" / "targets_alive_all.jsonl"


def run_targets_tech_routing():
    if not project_context.active:
        console.print("[red]Please open project[/red]")
        input("Enter...")
        return

    console.clear()
    console.rule("[bold cyan]Targets — Tech routing (A3)[/bold cyan]")
    console.print("Run Tech routing")

    src = _httpx_targets_jsonl_path()
    if not src.exists():
        console.print(
            "[red]Не найден targets_alive_all.jsonl. Сначала запусти HTTPX enrich (A2).[/red]"
        )
        input("Enter...")
        return

    out_dir = _routing_dir()
    meta_path = out_dir / "routing_meta.json"

    buckets = {k: set() for k in TECH_BUCKETS.keys()}
    buckets["unknown"] = set()

    total_in = 0

    with src.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            total_in += 1
            url = obj.get("final_url") or obj.get("url")
            if not url:
                continue

            tech = obj.get("tech") or []
            if isinstance(tech, list):
                tech_text = " ".join(str(x) for x in tech)
            else:
                tech_text = str(tech)

            matched = False
            for bucket, pats in TECH_BUCKETS.items():
                if any(p.search(tech_text) for p in pats):
                    buckets[bucket].add(url)
                    matched = True

            if not matched:
                buckets["unknown"].add(url)

    # сохраняем корзины в файлы + в project_context
    meta = {
        "generated_at": datetime.now().isoformat(),
        "input_count": total_in,
        "buckets": {},
    }

    for name, urls in buckets.items():
        items = sorted(urls)
        (out_dir / f"{name}.txt").write_text("\n".join(items), encoding="utf-8")
        meta["buckets"][name] = len(items)
        project_context.set(items, "recon", "targets", "routing", name)

    meta_path.write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    console.print(f"[green]Routing done[/green] {meta['buckets']}")
