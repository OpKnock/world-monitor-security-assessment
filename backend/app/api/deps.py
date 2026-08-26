"""Shared authentication dependencies and role-based access control.

Roles are strictly ordered: ``viewer < analyst < admin``.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..security import decode_token

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)

ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}


def _normalize_email(raw: object) -> str:
    """Return a lower-cased, stripped email string or ``""`` if invalid."""
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Resolve the bearer token to an active :class:`User`.

    Raises:
        HTTPException: 401 for missing / invalid / expired tokens or unknown
            / inactive users.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="authentication required")

    token: str = credentials.credentials.strip()
    if not token:
        raise HTTPException(status_code=401, detail="authentication required")

    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")

    # ``sub`` is the canonical email claim; normalise to lower-case so
    # ``Admin@Example.com`` and ``admin@example.com`` resolve identically.
    raw_sub = payload.get("sub", "")
    email = _normalize_email(raw_sub)
    if not email:
        raise HTTPException(status_code=401, detail="invalid token: missing subject")

    # Defensive: treat emails case-insensitively at the DB layer as well.
    # ``User.email`` is stored lower-cased on registration, but older rows
    # or direct DB inserts may have mixed case.
    try:
        user = db.scalar(select(User).where(User.email == email))
        # Fallback: case-insensitive lookup if exact match misses (covers
        # legacy mixed-case rows without requiring a DB migration).
        if user is None:
            # Use lower() SQL function for portable case-insensitive search.
            from sqlalchemy import func as _func

            user = db.scalar(select(User).where(_func.lower(User.email) == email))
    except Exception:
        logger.exception("database error during user lookup")
        raise HTTPException(status_code=500, detail="internal error")

    if user is None or not getattr(user, "is_active", False):
        raise HTTPException(status_code=401, detail="unknown user")

    return user


def require_role(minimum: str):  # type: ignore[no-untyped-def]
    """Return a FastAPI dependency that enforces *minimum* role.

    Args:
        minimum: One of ``viewer`` / ``analyst`` / ``admin``.

    Raises:
        RuntimeError: If *minimum* is not a known role (programmer error).
        HTTPException: 403 if the current user's rank is insufficient,
            500 if the user's role value is corrupt.
    """
    if minimum not in ROLE_RANK:
        raise RuntimeError(f"Unknown minimum role '{minimum}'; valid: {sorted(ROLE_RANK)}")

    required_rank = ROLE_RANK[minimum]

    def checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        try:
            user_rank = ROLE_RANK[user.role]
        except KeyError:
            logger.warning("user %s has unknown role %r", user.email, getattr(user, "role", None))
            raise HTTPException(status_code=500, detail="user role misconfigured")
        except AttributeError:
            raise HTTPException(status_code=500, detail="user role missing")

        if user_rank < required_rank:
            raise HTTPException(status_code=403, detail=f"requires role '{minimum}' or higher")
        return user

    return checker


__all__ = ["ROLE_RANK", "get_current_user", "require_role"]
