from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Header, HTTPException, status

from app.core.settings import get_settings


def require_api_key(x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None):
    settings = get_settings()
    if settings.web_auth_disabled:
        return

    if not settings.web_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WEB_API_KEY is not configured",
        )

    if not x_api_key or not secrets.compare_digest(x_api_key, settings.web_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

