import json
from pathlib import Path
from datetime import datetime
from core.project_context import project_context

def _recon_dir():
    path = project_context.path / "recon" / "subdomains"
    path.mkdir(parents=True, exist_ok=True)
    return path

# SCOPE DOMAIN LIST
def get_scope_domains():
    domains = project_context.get("scope", "domains", default=[])
    return domains if domains else []


def _urls_dir() -> Path:
    path = project_context.path / "recon" / "urls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _url_sources_dir() -> Path:
    path = _urls_dir() / "sources"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_urls_snapshot(urls: list[str] | set[str], source: str) -> Path:
    items = [
        str(url).strip()
        for url in urls
        if str(url).strip().startswith(("http://", "https://"))
    ]
    deduped = sorted(dict.fromkeys(items))

    out_file = _url_sources_dir() / f"{source}_urls.txt"
    out_file.write_text("\n".join(deduped), encoding="utf-8")
    return out_file


def merge_urls_into_all(urls: list[str] | set[str]) -> tuple[int, int]:
    all_file = _urls_dir() / "all_urls.txt"
    existing = set()

    if all_file.exists():
        existing = {
            line.strip()
            for line in all_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    before = len(existing)

    for url in urls:
        item = str(url).strip()
        if item.startswith(("http://", "https://")):
            existing.add(item)

    all_file.write_text("\n".join(sorted(existing)), encoding="utf-8")
    return before, len(existing)
    
# SAVE SUBDOMAINS
def save_subdomains(new_domains: set, source: str):
    out_dir = _recon_dir()
    json_file = out_dir / "subdomains.json"

    data = {
        "updated_at": datetime.now().isoformat(),
        "sources": {},
        "all": []
    }

    if json_file.exists():
        data = json.loads(json_file.read_text(encoding="utf-8"))

    existing_source_domains = data["sources"].get(source, [])
    combined_source = existing_source_domains + list(new_domains)
    data["sources"][source] = list(dict.fromkeys(combined_source))

    existing_all_domains = data.get("all", [])
    combined_all = existing_all_domains + list(new_domains)
    data["all"] = list(dict.fromkeys(combined_all))

    json_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    existing_scope_domains = project_context.get("scope", "domains", default=[])
    combined_scope = existing_scope_domains + list(new_domains)
    updated_scope_domains = list(dict.fromkeys(combined_scope))
    
    project_context.set(updated_scope_domains, "scope", "domains")

#SAVE IPS
def save_scope_ips(ips, source: str = "manual"):
    """
    Сохраняет IP в project_context -> scope -> ips
    Принимает:
      - set/tuple/list со строками (например {"192.168.1.1"})
      - или строку (например '{"192.168.1.1"}' или '192.168.1.1')
    Делает нормализацию и дедупликацию.
    """
    # 1) Нормализуем вход в список строк
    if ips is None:
        new_ips = []
    elif isinstance(ips, (set, list, tuple)):
        new_ips = [str(x) for x in ips]
    else:
        # если вдруг пришло строкой вида '{"1.2.3.4"}'
        s = str(ips).strip()
        if s.startswith("{") and s.endswith("}"):
            s = s[1:-1].strip()
        s = s.strip().strip('"').strip("'")
        new_ips = [s] if s else []

    # 2) Чистим каждый элемент: убираем { }, кавычки, пробелы
    cleaned = []
    for ip in new_ips:
        if ip is None:
            continue
        ip = str(ip).strip()

        # если внутри всё ещё фигурные скобки
        if ip.startswith("{") and ip.endswith("}"):
            ip = ip[1:-1].strip()

        # убрать кавычки вокруг
        ip = ip.strip().strip('"').strip("'")

        if ip:
            cleaned.append(ip)

    # 3) Дедупликация (с сохранением порядка)
    cleaned = list(dict.fromkeys(cleaned))

    # 4) Обновляем scope.ips
    existing_scope_ips = project_context.get("scope", "ips", default=[])
    combined_scope = existing_scope_ips + cleaned
    updated_scope_ips = list(dict.fromkeys(combined_scope))

    project_context.set(updated_scope_ips, "scope", "ips")
