from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from app.core.settings import get_settings
from app.services.auth import AuthStore, has_role


def current_user(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> dict:
    settings = get_settings()
    if settings.web_auth_disabled:
        return {
            "username": "local-system",
            "role": "admin",
            "is_active": True,
            "session_id": "",
        }

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    token = authorization.split(" ", 1)[1].strip()
    try:
        return AuthStore(settings).validate_token(token)
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc


def require_role(required_role: str):
    def dependency(user: dict = Depends(current_user)) -> dict:
        if not has_role(user.get("role", ""), required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher is required",
            )
        return user

    return dependency


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
