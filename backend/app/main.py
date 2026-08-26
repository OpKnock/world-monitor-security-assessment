"""World Monitor Security Assessment Platform — FastAPI application factory.

Startup sequence
----------------
1. Neutralise environment proxies for scanner targets (``NO_PROXY=*``).
2. Create :class:`FastAPI` with security headers middleware.
3. Enable CORS (configurable via ``CORS_ALLOW_ORIGINS`` env var).
4. Initialise DB, seed bootstrap users, sweep stale assessments, load scanner registry.
5. Mount routers, health check and (optionally) the frontend SPA.

The module exports both :func:`create_app` (factory, preferred for tests)
and :data:`app` (eager singleton for ``uvicorn backend.app.main:app``).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

# ---------------------------------------------------------------------------
# 0.  Proxy neutralisation — MUST happen before any HTTP client is imported
# ---------------------------------------------------------------------------
# Scanner targets are authorised local-lab endpoints; routing them through a
# system / environment proxy would hang every request when the proxy is down
# or would leak lab traffic externally.  We force a wildcard bypass and drop
# any proxy env vars that the host may have injected.  This is done at import
# time so it also applies when the module is imported by ``uvicorn`` workers.
for _var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(_var, None)
# ``NO_PROXY=*`` is understood by httpx / requests / curl to bypass all
# proxies.  We unconditionally set both cases because tools vary.
os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "*") or "*"
os.environ["no_proxy"] = os.environ.get("no_proxy", "*") or "*"

# ---------------------------------------------------------------------------
# Imports that may read the proxy env vars — keep them AFTER the block above
# ---------------------------------------------------------------------------
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import assessment_routes, auth_routes, delete_routes, misc_routes
from .config import ROOT_DIR, settings
from .db import SessionLocal, dispose_engine, init_db
from .models import Assessment, User
from .scanners.registry import load_registry
from .security import hash_password

logger = logging.getLogger(__name__)

FRONTEND_DIR: Path = ROOT_DIR / "frontend"


# ---------------------------------------------------------------------------
# Helpers — DB bootstrap
# ---------------------------------------------------------------------------


def _seed_users() -> None:
    """Upsert bootstrap accounts on every boot.

    Creates ``admin`` / ``analyst`` if missing and syncs password + role
    from ``.env`` on every restart so ``.env`` is always the source of
    truth (prevents stale-password lockouts after credential rotation).
    """
    db = SessionLocal()
    try:
        # Normalise emails to lower-case so lookups are deterministic.
        for email, password, role in (
            (settings.ADMIN_EMAIL.lower().strip(), settings.ADMIN_PASSWORD, "admin"),
            (settings.ANALYST_EMAIL.lower().strip(), settings.ANALYST_PASSWORD, "analyst"),
        ):
            if not email or not password:
                logger.warning("skipping seed for role=%s: empty email/password", role)
                continue
            existing = db.query(User).filter(User.email == email).one_or_none()
            if existing is None:
                db.add(User(email=email, password_hash=hash_password(password), role=role, is_active=True))
                logger.info("seeded bootstrap user %s (%s)", email, role)
            else:
                # Always rotate to the env-declared password / role.
                existing.password_hash = hash_password(password)
                existing.role = role
                existing.is_active = True
        db.commit()
    except Exception:
        logger.exception("failed to seed bootstrap users")
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def _sweep_stale_runs() -> None:
    """Mark any assessment left ``queued`` / ``running`` by a prior process as failed."""
    from datetime import datetime, timezone

    from sqlalchemy import select

    db = SessionLocal()
    try:
        stale = db.scalars(
            select(Assessment).where(Assessment.status.in_(("queued", "running")))  # type: ignore[arg-type]
        ).all()
        if not stale:
            return
        for assessment in stale:
            assessment.status = "failed"
            assessment.error = "interrupted by platform restart"
        db.commit()
        logger.info("swept %d stale assessment(s) to 'failed'", len(stale))
    except Exception:
        logger.exception("failed to sweep stale assessments")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialise on startup, dispose resources on shutdown."""
    # Startup
    try:
        init_db()
        _seed_users()
        _sweep_stale_runs()
        load_registry()
        logger.info("application startup complete (lab_mode=%s)", settings.LAB_MODE)
    except Exception:
        logger.exception("startup initialisation failed")
        raise
    yield
    # Shutdown
    try:
        dispose_engine()
        logger.info("application shutdown — engine disposed")
    except Exception:
        logger.exception("error during shutdown")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""

    app = FastAPI(
        title=settings.APP_NAME,
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=_lifespan,
    )

    # ------------------------------------------------------------------
    # CORS — allow frontend dev server + any explicitly configured origins
    # ------------------------------------------------------------------
    cors_origins_env = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
    if cors_origins_env == "*":
        allow_origins = ["*"]
    elif cors_origins_env:
        allow_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
    else:
        # Sensible defaults: local dev + lab
        allow_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
        ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Security headers + cache control
    # ------------------------------------------------------------------

    @app.middleware("http")
    async def secure_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "0"
        # Permissions-Policy to restrict browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
        )
        # Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # HSTS is only meaningful over HTTPS; include it anyway for
        # completeness — browsers ignore it on plain HTTP.
        if settings.ENABLE_HSTS:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # CSP - only for API responses to avoid breaking the SPA
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            if settings.ENABLE_CSP:
                # For API responses, we use a restrictive CSP
                response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    # ------------------------------------------------------------------
    # Request ID middleware for tracing
    # ------------------------------------------------------------------

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        import uuid
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ------------------------------------------------------------------
    # Global rate limiting (lightweight, per-IP)
    # ------------------------------------------------------------------
    # Individual routes enforce their own stricter limits via
    # ``enforce_rate_limit``.  This middleware provides a coarse global
    # backstop so a single abusive client cannot saturate the thread pool.

    @app.middleware("http")
    async def global_rate_limit(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Only throttle API routes; skip docs / health / static
        if request.url.path.startswith("/api"):
            # Health is excluded — it must stay available for probes.
            if request.url.path not in ("/api/health", "/api/openapi.json", "/api/docs"):
                from .api.rate_limit import limiter

                # Global backstop: 600 req/min per IP (same as default
                # API_RATE_LIMIT_PER_MINUTE).  Higher than the per-route
                # auth limit so the latter still takes precedence.
                client_ip = request.client.host if request.client else "unknown"
                # Use a distinct key so this window does not interfere with
                # per-route windows.
                if not limiter.check(f"global:{client_ip}", settings.API_RATE_LIMIT_PER_MINUTE):
                    return JSONResponse(
                        status_code=429,
                        content={"detail": {"error": "rate_limited", "retry_after_s": 60}},
                        headers={"Retry-After": "60", "X-Request-ID": getattr(request.state, "request_id", "")},
                    )
        return await call_next(request)

    # ------------------------------------------------------------------
    # Request logging middleware
    # ------------------------------------------------------------------

    @app.middleware("http")
    async def request_logging(request: Request, call_next):  # type: ignore[no-untyped-def]
        import time
        start_time = time.perf_counter()
        request_id = getattr(request.state, "request_id", "-")
        client_ip = request.client.host if request.client else "unknown"
        
        # Log request
        logger.info(
            "req_start method=%s path=%s client=%s request_id=%s",
            request.method, request.url.path, client_ip, request_id
        )
        
        try:
            response = await call_next(request)
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            logger.info(
                "req_end method=%s path=%s status=%d duration_ms=%d request_id=%s",
                request.method, request.url.path, response.status_code, duration_ms, request_id
            )
            return response
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            logger.exception(
                "req_error method=%s path=%s duration_ms=%d request_id=%s error=%s",
                request.method, request.url.path, duration_ms, request_id, exc
            )
            raise

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(assessment_routes.router, prefix="/api")
    app.include_router(misc_routes.router, prefix="/api")
    app.include_router(delete_routes.router, prefix="/api")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @app.get("/api/health", tags=["health"])
    def health():  # type: ignore[no-untyped-def]
        """Liveness probe — does not require auth and never touches secrets."""
        return {
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": __version__,
            "lab_mode": settings.LAB_MODE,
        }

    # ------------------------------------------------------------------
    # Frontend SPA (if built)
    # ------------------------------------------------------------------
    if FRONTEND_DIR.exists():
        assets_dir = FRONTEND_DIR / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/", include_in_schema=False)
        def index():  # type: ignore[no-untyped-def]
            idx = FRONTEND_DIR / "index.html"
            if idx.exists():
                return FileResponse(idx)
            return JSONResponse({"message": "frontend not built; see docs/deployment.md"})

        @app.get("/{page:path}", include_in_schema=False)
        def spa_fallback(page: str):  # type: ignore[no-untyped-def]
            """Serve SPA fallback while preventing path traversal."""
            # Block traversal attempts that contain ``..`` after resolution.
            # ``Path.resolve`` follows symlinks, so we also ensure the
            # resolved path stays inside FRONTEND_DIR.
            try:
                candidate = (FRONTEND_DIR / page).resolve()
                candidate.relative_to(FRONTEND_DIR.resolve())
            except (ValueError, RuntimeError):
                return FileResponse(FRONTEND_DIR / "index.html")
            # Only serve files that actually exist and are not directories.
            if candidate.is_file():
                return FileResponse(candidate)
            # All other paths fall back to the SPA entry point.
            fallback = FRONTEND_DIR / "index.html"
            if fallback.exists():
                return FileResponse(fallback)
            return JSONResponse({"message": "frontend not built; see docs/deployment.md"})

    else:

        @app.get("/", include_in_schema=False)
        def root_placeholder():  # type: ignore[no-untyped-def]
            return JSONResponse({"message": "frontend not built; see docs/deployment.md"})

    return app


# Eager singleton for ``uvicorn backend.app.main:app``
app: FastAPI = create_app()


def main() -> None:
    """Run the application with uvicorn (``python -m backend.app.main``)."""
    import uvicorn

    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
