from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.security import current_user, require_admin
from app.core.settings import get_settings
from app.models.schemas import CreateUserRequest, LoginRequest, UpdateUserRequest
from app.services.auth import AuthStore, jwt_secret


router = APIRouter(prefix="/api/auth")


@router.get("/status")
def auth_status():
    settings = get_settings()
    store = AuthStore(settings)
    auth_required = not settings.web_auth_disabled
    return {
        "auth_required": auth_required,
        "auth_configured": bool(jwt_secret(settings)) if auth_required else True,
        "setup_required": store.setup_required(),
        "roles": ["viewer", "analyst", "admin"],
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request):
    settings = get_settings()
    store = AuthStore(settings)
    user = store.authenticate(payload.username, payload.password)
    ip_address = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    if not user:
        store.audit(
            actor=None,
            action="auth.login",
            resource_type="user",
            resource_id=payload.username,
            status="failed",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session = store.create_session(user, ip_address=ip_address, user_agent=user_agent)
    store.audit(
        actor=user,
        action="auth.login",
        resource_type="user",
        resource_id=user["username"],
        status="success",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return session


@router.post("/logout")
def logout(request: Request, user: dict = Depends(current_user)):
    store = AuthStore()
    if user.get("session_id"):
        store.revoke_session(user["session_id"])
    store.audit(
        actor=user,
        action="auth.logout",
        resource_type="session",
        resource_id=user.get("session_id"),
        status="success",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    return {"message": "Logged out"}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return {"user": _public_user(user)}


@router.get("/users")
def users(user: dict = Depends(require_admin)):
    return {"users": AuthStore().list_users()}


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(payload: CreateUserRequest, request: Request, user: dict = Depends(require_admin)):
    store = AuthStore()
    try:
        created = store.create_user(payload.username, payload.password, payload.role)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="User already exists") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.audit(
        actor=user,
        action="auth.create_user",
        resource_type="user",
        resource_id=created["username"],
        status="success",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details={"role": created["role"]},
    )
    return created


@router.patch("/users/{username}")
def update_user(
    username: str,
    payload: UpdateUserRequest,
    request: Request,
    user: dict = Depends(require_admin),
):
    store = AuthStore()
    try:
        updated = store.update_user(
            username,
            role=payload.role,
            is_active=payload.is_active,
            password=payload.password,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.audit(
        actor=user,
        action="auth.update_user",
        resource_type="user",
        resource_id=updated["username"],
        status="success",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details={
            "role": payload.role,
            "is_active": payload.is_active,
            "password_changed": bool(payload.password),
        },
    )
    return updated


@router.get("/audit")
def audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    user: dict = Depends(require_admin),
):
    return {"events": AuthStore().list_audit_events(limit)}


def _public_user(user: dict) -> dict:
    return {
        "username": user.get("username"),
        "role": user.get("role"),
        "is_active": bool(user.get("is_active")),
    }


def _client_ip(request: Request | None) -> str:
    if not request or not request.client:
        return ""
    return request.client.host
