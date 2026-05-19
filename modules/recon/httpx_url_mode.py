import subprocess
import json
from datetime import datetime
from functools import lru_cache
from rich.console import Console
from rich.prompt import Prompt
from core.project_context import project_context
from core.url_utils import dedupe_urls

console = Console()


def _httpx_urls_dir():
    path = project_context.path / "recon" / "httpx" / "urls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_all_urls():
    urls_file = project_context.path / "recon" / "urls" / "all_urls.txt"

    if not urls_file.exists():
        return []

    return [
        line.strip()
        for line in urls_file.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("http")
    ]


@lru_cache(maxsize=1)
def _httpx_supported_flags() -> set[str]:
    """
    Возвращает множество поддерживаемых флагов текущим httpx (по `httpx -h`).
    Нужна, чтобы не падать, если -cdn/-waf/-favicon отсутствуют.
    """
    try:
        r = subprocess.run(["httpx", "-h"], capture_output=True, text=True)
        help_txt = (r.stdout or "") + "\n" + (r.stderr or "")
    except Exception:
        return set()

    candidates = {
        "-content-type",
        "-ip",
        "-cdn",
        "-waf",
        "-favicon",
        "-favicon-hash",
        "-tech-detect",
        "-td",
        "-follow-redirects",
        "-fr",
        "-rate-limit",
        "-rl",
    }
    return {f for f in candidates if f in help_txt}


def _add_if_supported(cmd: list[str], supported: set[str], flag: str, *args: str):
    if flag in supported:
        cmd.append(flag)
        cmd.extend(args)


def _httpx_panic_detected(stderr: str) -> bool:
    text = (stderr or "").lower()
    return "panic:" in text or "nil pointer dereference" in text


def _build_httpx_url_cmd(
    input_file,
    supported: set[str],
    *,
    threads: str,
    rate_limit: str,
    timeout: str,
    retries: str,
    enrich: bool = True,
) -> list[str]:
    cmd = [
        "httpx",
        "-l",
        str(input_file),
        "-json",
        "-silent",
    ]

    _add_if_supported(cmd, supported, "-status-code")
    _add_if_supported(cmd, supported, "-title")

    if enrich:
        if "-tech-detect" in supported:
            cmd.append("-tech-detect")
        elif "-td" in supported:
            cmd.append("-td")

        _add_if_supported(cmd, supported, "-content-type")
        _add_if_supported(cmd, supported, "-ip")
        _add_if_supported(cmd, supported, "-cdn")
        _add_if_supported(cmd, supported, "-waf")

    if "-follow-redirects" in supported:
        cmd.append("-follow-redirects")
    elif "-fr" in supported:
        cmd.append("-fr")

    cmd += [
        "-threads",
        str(threads),
        "-rate-limit",
        str(rate_limit),
        "-timeout",
        str(timeout),
        "-retries",
        str(retries),
    ]
    return cmd


def run_httpx_url_mode():
    urls_raw = get_all_urls()
    urls = dedupe_urls(urls_raw, max_per_host=None)  # None bez limita

    if not urls:
        console.print(
            "[red]Нет URL для проверки. Сначала запустите URL discovery.[/red]"
        )
        input("Enter...")
        return

    console.rule("[bold cyan]HTTPX — URL mode[/bold cyan]")

    out_dir = _httpx_urls_dir()

    input_file = out_dir / "input_urls.txt"
    raw_json = out_dir / "httpx_urls_raw.json"
    alive_json = out_dir / "alive_urls.json"
    alive_txt = out_dir / "alive_urls.txt"
    alive_json_all = out_dir / "alive_urls_all.json"
    alive_txt_all = out_dir / "alive_urls_all.txt"

    input_file.write_text("\n".join(urls), encoding="utf-8")

    prm_threads = Prompt.ask("Kоличество используемых потоков", default="100")
    prm_rate_limit = Prompt.ask(
        "Mаксимальное количество запросов, отправляемых в секунду", default="50"
    )
    prm_timeout = Prompt.ask("Bремя ожидания в секундах", default="7")
    prm_retries = Prompt.ask("Kоличество повторных попыток(", default="0")

    supported = _httpx_supported_flags()

    cmd = _build_httpx_url_cmd(
        input_file,
        supported,
        threads=prm_threads,
        rate_limit=prm_rate_limit,
        timeout=prm_timeout,
        retries=prm_retries,
        enrich=True,
    )

    console.print(
        f"[dim]URLs before:[/dim] {len(urls_raw)}  [dim]after dedupe:[/dim] {len(urls)}"
    )

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and _httpx_panic_detected(result.stderr):
        console.print(
            "[yellow]httpx упал на enrich-флагах. Повторяю в безопасном режиме "
            "без tech/cdn/waf/ip/favicons.[/yellow]"
        )
        fallback_cmd = _build_httpx_url_cmd(
            input_file,
            supported,
            threads=prm_threads,
            rate_limit=prm_rate_limit,
            timeout=prm_timeout,
            retries=prm_retries,
            enrich=False,
        )
        result = subprocess.run(fallback_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        console.print("[red]httpx завершился с ошибкой[/red]")
        console.print(result.stderr)
        input("Enter...")
        return

    raw_data = []

    for line in result.stdout.splitlines():
        try:
            raw_data.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    raw_json.write_text(
        json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    alive_urls = []  # only live urls. status 2xx, 3xx

    for item in raw_data:
        # Filter for status code
        status = item.get("status_code")
        if status is None:
            continue

        # "active": 2xx, 3xx
        if not (200 <= status <= 399):
            continue

        alive_urls.append(
            {
                "url": item.get("url"),
                "status_code": status,
                "title": item.get("title"),
                "tech": item.get("tech", []),
            }
        )

    alive_json.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(alive_urls),
                "urls": alive_urls,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    alive_txt.write_text("\n".join(u["url"] for u in alive_urls), encoding="utf-8")

    # save in project context
    project_context.set([u["url"] for u in alive_urls], "recon", "httpx", "alive_urls")

    # extended: include 401/403
    alive_urls_all = []  # live urls. status 2xx, 3xx, 401/403
    for item in raw_data:
        # Filter for status code
        status = item.get("status_code")
        if status is None:
            continue

        # "active": 2xx, 3xx, and 401/403*
        if not (200 <= status <= 399 or status in (401, 403)):
            continue

        alive_urls_all.append(
            {
                "url": item.get("url"),
                "status_code": status,
                "title": item.get("title"),
                "tech": item.get("tech", []),
            }
        )

    alive_json_all.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count": len(alive_urls_all),
                "urls": alive_urls_all,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    alive_txt_all.write_text(
        "\n".join(u["url"] for u in alive_urls_all), encoding="utf-8"
    )

    #######################################
    targets_alive_jsonl = out_dir / "targets_alive.jsonl"
    targets_alive_all_jsonl = out_dir / "targets_alive_all.jsonl"
    targets_alive_meta = out_dir / "targets_alive_meta.json"

    def _pick(item: dict, key: str, default=None):
        v = item.get(key)
        return default if v is None else v

    def _extract_final_url(item: dict) -> str | None:
        # в разных версиях может быть final_url / final-url
        return item.get("final_url") or item.get("final-url") or item.get("url")

    def _extract_favicon_hash(item: dict):
        # варианты ключей
        return (
            item.get("favicon") or item.get("favicon_hash") or item.get("favicon-hash")
        )

    # truth: 2xx/3xx
    truth = []
    truth_all = []

    for item in raw_data:
        status = item.get("status_code")
        if status is None:
            continue

        rec = {
            "input": item.get("input"),
            "url": item.get("url"),
            "final_url": _extract_final_url(item),
            "status_code": status,
            "title": item.get("title"),
            "content_type": _pick(item, "content_type") or _pick(item, "content-type"),
            "ip": item.get("ip"),
            "tech": item.get("tech", []),
            "cdn": item.get("cdn"),
            "waf": item.get("waf"),
            "favicon_hash": _extract_favicon_hash(item),
        }

        if 200 <= status <= 399:
            truth.append(rec)

        if (200 <= status <= 399) or (status in (401, 403)):
            truth_all.append(rec)

    # пишем JSONL
    with targets_alive_jsonl.open("w", encoding="utf-8") as f:
        for rec in truth:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    with targets_alive_all_jsonl.open("w", encoding="utf-8") as f:
        for rec in truth_all:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    targets_alive_meta.write_text(
        json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "count_targets_alive": len(truth),
                "count_targets_alive_all": len(truth_all),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    #######################################

    # save in project context
    project_context.set(
        [u["url"] for u in alive_urls_all], "recon", "httpx", "alive_urls_all"
    )

    console.print(f"[green]Живых URL найдено: {len(alive_urls)}[/green]")
