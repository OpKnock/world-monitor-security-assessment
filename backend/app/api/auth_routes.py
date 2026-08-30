"""Platform authentication routes: register / login / me."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import AuditLog, User
from ..security import create_access_token, hash_password, verify_password_timing_safe
from .deps import get_current_user
from .rate_limit import enforce_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(request, settings.AUTH_RATE_LIMIT_PER_MINUTE)
    exists = db.scalar(select(User).where(User.email == body.email.lower()))
    if exists:
        raise HTTPException(409, detail="email already registered")
    is_first_user = db.scalar(select(User).limit(1)) is None
    role = "admin" if is_first_user else "viewer"
    user = User(email=str(body.email).lower(), password_hash=hash_password(body.password), role=role)
    db.add(user)
    db.commit()
    db.add(AuditLog(user_email=user.email, action="auth.register", target="", detail={"role": role}))
    db.commit()
    return {"id": user.id, "email": user.email, "role": role,
            "access_token": create_access_token(user.email, role)}


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(request, settings.AUTH_RATE_LIMIT_PER_MINUTE)
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    ok = verify_password_timing_safe(body.password, user.password_hash if user else None)
    if not ok or not user or not user.is_active:
        raise HTTPException(401, detail="invalid credentials")
    token = create_access_token(user.email, user.role)
    db.add(AuditLog(user_email=user.email, action="auth.login", target="", detail={}))
    db.commit()
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user.id, "email": user.email, "role": user.role}}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}
