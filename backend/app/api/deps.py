"""Shared auth dependencies + RBAC (roles: admin > analyst > viewer)."""
import fastapi
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..security import decode_token

_bearer = HTTPBearer(auto_error=False)

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(401, detail="authentication required")
    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(401, detail="invalid or expired token")
    user = None
    from sqlalchemy import select

    email = str(payload.get("sub", ""))
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active:
        raise HTTPException(401, detail="unknown user")
    return user


def require_role(minimum: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(403, detail=f"requires role '{minimum}' or higher")
        return user

    return checker
