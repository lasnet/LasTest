from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core.settings import get_settings
from app.services.jobs import JobStore
from app.services.paths import ensure_runtime_dirs


def create_app() -> FastAPI:
    settings = get_settings()
    ensure_runtime_dirs(settings)
    JobStore(settings).ensure_schema()

    app = FastAPI(title=settings.app_name)
    app.include_router(api_router)

    @app.middleware("http")
    async def add_static_cache_headers(request, call_next):
        response = await call_next(request)
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    @app.get("/api/health")
    def health():
        auth_required = not settings.web_auth_disabled
        return {
            "status": "ok",
            "app": settings.app_name,
            "auth_required": auth_required,
            "auth_configured": bool(settings.web_api_key) if auth_required else True,
        }

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html")

    return app


app = create_app()
