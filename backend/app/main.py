"""World Monitor Security Assessment Platform — FastAPI application factory."""
import os
from pathlib import Path

# Scanner targets are authorized local-lab endpoints; never route them through
# system/environment proxies (a dead proxy would hang every request).
os.environ["NO_PROXY"] = "*"
os.environ["no_proxy"] = "*"
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("http_proxy", None)
os.environ.pop("https_proxy", None)

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import assessment_routes, auth_routes, delete_routes, misc_routes
from .config import ROOT_DIR, settings
from .db import SessionLocal, init_db
from .models import Assessment, User
from .scanners.registry import load_registry
from .security import hash_password

FRONTEND_DIR = ROOT_DIR / "frontend"


def _seed_users() -> None:
    db = SessionLocal()
    try:
        for email, password, role in (
            (settings.ADMIN_EMAIL, settings.ADMIN_PASSWORD, "admin"),
            (settings.ANALYST_EMAIL, settings.ANALYST_PASSWORD, "analyst"),
        ):
            existing = db.query(User).filter(User.email == email).one_or_none()
            if existing is None:
                db.add(User(email=email, password_hash=hash_password(password), role=role))
        db.commit()
    finally:
        db.close()


def _sweep_stale_runs() -> None:
    """Any assessment left queued/running by a previous process is dead."""
    from datetime import datetime, timezone

    from sqlalchemy import select

    db = SessionLocal()
    try:
        stale = db.scalars(
            select(Assessment).where(Assessment.status.in_(("queued", "running")))
        ).all()
        for a in stale:
            a.status = "failed"
            a.error = "interrupted by platform restart"
        if stale:
            db.commit()
    finally:
        db.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    init_db()
    _seed_users()
    _sweep_stale_runs()
    load_registry()

    @app.middleware("http")
    async def secure_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(assessment_routes.router, prefix="/api")
    app.include_router(misc_routes.router, prefix="/api")
    app.include_router(delete_routes.router, prefix="/api")

    @app.get("/api/health")
    def health():
        return {"status": "healthy", "app": settings.APP_NAME, "version": __version__,
                "lab_mode": settings.LAB_MODE}

    if FRONTEND_DIR.exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(FRONTEND_DIR / "index.html")

        @app.get("/{page}", include_in_schema=False)
        def spa_fallback(page: str):
            candidate = FRONTEND_DIR / page
            if candidate.is_file() and page != ".env":
                return FileResponse(candidate)
            return FileResponse(FRONTEND_DIR / "index.html")

    else:

        @app.get("/", include_in_schema=False)
        def root_placeholder():
            return JSONResponse({"message": "frontend not built; see docs/deployment.md"})

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
