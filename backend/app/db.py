"""Database engine, session factories and initialisation helpers.

SQLite handling
---------------
* ``NullPool`` — each checkout gets a fresh DB-API connection; no pooling
  artefacts are shared across threads.
* WAL + ``busy_timeout`` pragmas — concurrent readers + one writer can
  coexist without immediate ``database is locked`` errors.
* :data:`DB_WRITE_LOCK` — coarse-grained serialisation for writes; on
  some Windows SQLite builds concurrent writers still wedge even with WAL.

Non-SQLite URLs (Postgres / MySQL) use SQLAlchemy's default ``QueuePool``
with ``pool_pre_ping`` so stale connections are recycled transparently.
"""

from __future__ import annotations

import threading
from collections.abc import Generator
from typing import TYPE_CHECKING

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from .config import settings

if TYPE_CHECKING:
    from sqlalchemy import Engine

# ---------------------------------------------------------------------------
# Base & global write lock
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Serialise all DB writes — SQLite tolerates concurrent writers poorly on
# some Windows configurations even with WAL.  An RLock allows the same
# thread to re-enter (e.g. audit helper called inside a write block).
DB_WRITE_LOCK: threading.RLock = threading.RLock()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_sqlite_url(url: str) -> bool:
    return url.startswith("sqlite")


def _apply_sqlite_pragmas(dbapi_conn: object, _record: object) -> None:
    """Set WAL journal mode and busy timeout on every new SQLite connection."""
    cur = dbapi_conn.cursor()  # type: ignore[union-attr]
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        # Additional hardening pragmas
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
    finally:
        cur.close()


def _build_connect_args(url: str) -> dict:
    if _is_sqlite_url(url):
        return {"check_same_thread": False}
    return {}


def _build_engine(url: str, *, connect_args: dict | None = None) -> Engine:
    """Create an :class:`Engine` with the correct pool for the URL."""
    args = connect_args if connect_args is not None else _build_connect_args(url)
    kwargs: dict = {
        "pool_pre_ping": True,
        "connect_args": args,
    }
    # SQLite benefits from NullPool (no cross-thread connection sharing).
    # Other backends keep the default QueuePool for performance.
    if _is_sqlite_url(url):
        kwargs["poolclass"] = NullPool
    engine = create_engine(url, **kwargs)
    if _is_sqlite_url(url):
        event.listen(engine, "connect", _apply_sqlite_pragmas)
    return engine


# ---------------------------------------------------------------------------
# Global engine / session factory (used by request handlers)
# ---------------------------------------------------------------------------

engine = _build_engine(settings.DATABASE_URL)
SessionLocal: sessionmaker[Session] = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def worker_session() -> Session:
    """Create a dedicated, non-pooled :class:`Session` for scanner workers.

    Sharing pooled SQLite connections across threads (allowed via
    ``check_same_thread=False``) can serialise or wedge under load.  Each
    worker therefore gets its own throwaway engine + connection.

    The returned :class:`Session` owns its engine.  Callers **must** call
    ``session.close()``; the underlying engine is disposed automatically via
    an event hook so no file descriptors leak even if the caller forgets to
    dispose the engine explicitly.
    """
    eng = _build_engine(settings.DATABASE_URL, connect_args=dict(_build_connect_args(settings.DATABASE_URL)))

    factory: sessionmaker[Session] = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    session: Session = factory()

    # Ensure the short-lived engine is disposed when the session is closed.
    # SQLAlchemy's Session.close() is idempotent, so we wrap it once.
    original_close = session.close

    def _close_and_dispose() -> None:
        try:
            original_close()
        finally:
            try:
                eng.dispose()
            except Exception:
                pass

    session.close = _close_and_dispose  # type: ignore[method-assign]
    return session


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a request-scoped :class:`Session`."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables (no-op if they already exist) and add missing columns."""
    # Import here to avoid circular imports and to ensure all mappers are
    # registered before ``create_all`` inspects metadata.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    # Handle schema drift for existing DB files — add new columns if missing
    # (lightweight alternative to alembic for this single-node SQLite deployment)
    try:
        _maybe_migrate_existing_db()
    except Exception:
        # Migration is best-effort; don't fail startup if it can't run
        import logging
        logging.getLogger(__name__).exception("DB migration check failed")


def _maybe_migrate_existing_db() -> None:
    """Add columns that were introduced after initial release.

    Uses `PRAGMA table_info` to inspect existing schema and `ALTER TABLE`
    for missing columns. Safe to run repeatedly; only SQLite is handled
    here (Postgres would use separate migration tooling).
    """
    if not settings.DATABASE_URL.startswith("sqlite"):
        return
    from sqlalchemy import text
    # Map table -> list of (column_name, column_definition)
    # Definition must be valid SQLite column spec.
    migrations: dict[str, list[tuple[str, str]]] = {
        "users": [
            ("last_login_at", "DATETIME"),
            ("failed_login_attempts", "INTEGER DEFAULT 0"),
            ("locked_until", "DATETIME"),
        ],
        "targets": [
            ("last_assessed_at", "DATETIME"),
            ("assessment_count", "INTEGER DEFAULT 0"),
        ],
        "assessments": [
            ("total_findings", "INTEGER DEFAULT 0"),
            ("total_duration_ms", "INTEGER DEFAULT 0"),
        ],
        "scan_runs": [
            ("started_at", "DATETIME"),
            ("finished_at", "DATETIME"),
        ],
        "audit_logs": [
            ("ip_address", "VARCHAR(45)"),
            ("user_agent", "VARCHAR(512)"),
        ],
    }
    with engine.connect() as conn:
        for table, cols in migrations.items():
            try:
                existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})")).fetchall()}
            except Exception:
                continue
            for col_name, col_def in cols:
                if col_name not in existing:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}"))
                        conn.commit()
                    except Exception:
                        # Column may have been added concurrently; ignore
                        try:
                            conn.rollback()
                        except Exception:
                            pass


def dispose_engine() -> None:
    """Dispose the global engine — call on application shutdown."""
    try:
        engine.dispose()
    except Exception:
        pass


__all__ = ["Base", "DB_WRITE_LOCK", "SessionLocal", "dispose_engine", "engine", "get_db", "init_db", "worker_session"]
