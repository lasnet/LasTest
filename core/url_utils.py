from __future__ import annotations

from typing import Iterable, List, Set
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Расширения, которые почти всегда бесполезны для проверки живости endpoints
STATIC_EXTENSIONS: Set[str] = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".m4a",
    ".wav",
}

# Параметры-трекеры, которые обычно не влияют на уникальность endpoint'а
NOISE_QUERY_KEYS: Set[str] = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "ref_src",
    "spm",
}


def _has_static_ext(path: str) -> bool:
    p = path.lower()
    for ext in STATIC_EXTENSIONS:
        if p.endswith(ext):
            return True
    return False


def normalize_url(url: str) -> str | None:
    """
    Нормализует URL для дедупликации:
    - убирает fragment (#...)
    - фильтрует шумные query параметры
    - сортирует query параметры
    Возвращает нормализованный URL или None, если URL мусорный.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        return None

    parts = urlsplit(url)
    if not parts.netloc:
        return None

    # фильтр статики (можно отключить, если захочешь)
    if _has_static_ext(parts.path or ""):
        return None

    # чистим query от мусорных параметров
    q = parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k not in NOISE_QUERY_KEYS]
    q.sort(key=lambda kv: (kv[0], kv[1]))

    new_query = urlencode(q, doseq=True)

    # убираем fragment полностью
    normalized = urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            new_query,
            "",  # fragment
        )
    )

    return normalized


def dedupe_urls(urls: Iterable[str], max_per_host: int | None = None) -> List[str]:
    """
    Дедуп URL. Опционально ограничивает количество URL на один host (scheme+host).
    """
    seen: Set[str] = set()
    out: List[str] = []

    per_host_count = {}

    for u in urls:
        nu = normalize_url(u)
        if not nu:
            continue

        # лимит на хост
        if max_per_host is not None:
            p = urlsplit(nu)
            host_key = f"{p.scheme}://{p.netloc}"
            per_host_count.setdefault(host_key, 0)
            if per_host_count[host_key] >= max_per_host:
                continue

        if nu in seen:
            continue

        seen.add(nu)
        out.append(nu)

        if max_per_host is not None:
            p = urlsplit(nu)
            host_key = f"{p.scheme}://{p.netloc}"
            per_host_count[host_key] += 1

    return out
