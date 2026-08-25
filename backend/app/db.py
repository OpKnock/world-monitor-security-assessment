from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = (
    {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)
engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    poolclass=NullPool,
)

if settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")       # concurrent readers + 1 writer
        cur.execute("PRAGMA busy_timeout=30000")     # wait instead of instant error
        cur.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def worker_session():
    """Dedicated, non-pooled session for scanner worker threads.

    Sharing pooled SQLite connections across threads (allowed via
    check_same_thread=False) can serialize/wedge under load; workers get
    their own throwaway connection instead.
    """
    eng = create_engine(
        settings.DATABASE_URL,
        connect_args=dict(connect_args),
        poolclass=NullPool,
    )

    if settings.DATABASE_URL.startswith("sqlite"):

        @event.listens_for(eng, "connect")
        def _pragmas(dbapi_conn, _rec):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

    return sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)


# Serialize all DB writes; SQLite tolerates concurrent writers poorly
# on some Windows configurations.
import threading as _threading

DB_WRITE_LOCK = _threading.RLock()
