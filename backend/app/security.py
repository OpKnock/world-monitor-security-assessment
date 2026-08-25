"""Platform authentication: PBKDF2 password hashing + HS256 JWT.

Patterns adopted from OpKnock/siem-dashboard (timing-safe verification,
anti-enumeration dummy hash) implemented on stdlib to avoid compiled deps.
"""
import hashlib
import hmac
import os
import time

import jwt

from .config import settings

_PBKDF2_ITERATIONS = 390_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


DUMMY_HASH = hash_password("dummy_password_for_timing_attack_prevention")


def verify_password_timing_safe(password: str, stored: str | None) -> bool:
    """Constant-time-ish verify; hashes a dummy when stored is unknown."""
    if not stored or "$" not in stored:
        try:
            hash_password(password)
        except Exception:
            pass
        return False
    try:
        algo, iterations, salt_hex, dk_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_access_token(email: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "role": role,
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "iss": "world-monitor",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],  # pinned — never accept 'none'
            issuer="world-monitor",
        )
    except jwt.PyJWTError:
        return None


def verify_token_timing_safe(token: str) -> dict | None:
    """Decode wrapper kept for symmetry with password verify naming."""
    return decode_token(token)
