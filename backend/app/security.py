"""Platform authentication: PBKDF2 password hashing + HS256 JWT.

Patterns adopted from OpKnock / siem-dashboard (timing-safe verification,
anti-enumeration dummy hash) implemented on the standard library so no
compiled native dependencies are required.

Security properties
-------------------
* PBKDF2-HMAC-SHA256 with 390 000 iterations (OWASP 2023 recommendation).
* Per-password 16-byte CSPRNG salt; verifier uses :func:`hmac.compare_digest`.
* Missing-user path performs the same PBKDF2 work and a dummy compare so
  an attacker cannot enumerate accounts via timing.
* JWT: HS256 only (``none`` rejected), ``exp`` / ``iat`` / ``iss`` /
  ``jti`` claims, issuer pinned.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import uuid
from typing import Any

import jwt

from .config import settings

_PBKDF2_ITERATIONS: int = 390_000
_PBKDF2_ALGO: str = "pbkdf2_sha256"
_JWT_ISSUER: str = "world-monitor"
_JWT_ALGORITHM: str = "HS256"

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def _parse_hash(stored: str) -> tuple[str, int, bytes, bytes] | None:
    """Parse ``algo$iterations$salt_hex$dk_hex``; return ``None`` on malformed input."""
    try:
        algo, iter_s, salt_hex, dk_hex = stored.split("$", 3)
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        dk = bytes.fromhex(dk_hex)
        if algo != _PBKDF2_ALGO or iterations <= 0 or len(salt) == 0 or len(dk) == 0:
            return None
        return algo, iterations, salt, dk
    except (ValueError, TypeError):
        return None


def hash_password(password: str) -> str:
    """Hash *password* with PBKDF2-SHA256 and a fresh 16-byte salt.

    Returns a self-describing string ``pbkdf2_sha256$iterations$salt_hex$dk_hex``
    suitable for storage in :attr:`User.password_hash`.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")
    # 16 bytes = 128-bit salt; os.urandom is CSPRNG
    salt: bytes = os.urandom(16)
    dk: bytes = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


# Pre-computed dummy hash used to equalise timing when the account does not
# exist.  Computed at import time so the first login attempt does not pay
# the PBKDF2 cost twice.
_DUMMY_PASSWORD: str = "dummy_password_for_timing_attack_prevention__32chars!"
_DUMMY_SALT: bytes = os.urandom(16)
_DUMMY_DK: bytes = hashlib.pbkdf2_hmac(
    "sha256", _DUMMY_PASSWORD.encode("utf-8"), _DUMMY_SALT, _PBKDF2_ITERATIONS
)
DUMMY_HASH: str = f"{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${_DUMMY_SALT.hex()}${_DUMMY_DK.hex()}"


def verify_password_timing_safe(password: str, stored: str | None) -> bool:
    """Verify *password* against *stored* in (approximately) constant time.

    When *stored* is ``None`` or malformed the function still performs a full
    PBKDF2 derivation and a :func:`hmac.compare_digest` against the dummy
    hash so the observable timing is indistinguishable from the valid-user
    path (modulo OS scheduling jitter).

    Returns ``False`` for any invalid input rather than raising.
    """
    if not isinstance(password, str):
        # Still burn PBKDF2 time to avoid type-based oracle
        hashlib.pbkdf2_hmac("sha256", b"", _DUMMY_SALT, _PBKDF2_ITERATIONS)
        hmac.compare_digest(_DUMMY_DK.hex(), _DUMMY_DK.hex())
        return False

    # Choose the reference hash: real stored hash or the dummy.
    reference: str | None = stored if stored and "$" in stored else None
    parsed = _parse_hash(reference) if reference else None

    if parsed is None:
        # Unknown user or corrupt hash — hash with dummy parameters and
        # compare against the dummy to keep timing uniform.
        dk_attempt = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _DUMMY_SALT, _PBKDF2_ITERATIONS
        )
        # Dummy compare — always False, but takes the same compare_digest path
        hmac.compare_digest(dk_attempt.hex(), _DUMMY_DK.hex())
        return False

    _algo, iterations, salt, expected_dk = parsed
    try:
        dk_attempt = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    except Exception:
        return False
    # Compare hex-encoded digests in constant time
    return hmac.compare_digest(dk_attempt.hex(), expected_dk.hex())


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def create_access_token(email: str, role: str) -> str:
    """Create a signed HS256 JWT for *email* / *role*.

    Claims:
        * ``sub`` — subject (email, lower-cased)
        * ``role`` — platform role (admin / analyst / viewer)
        * ``iat`` — issued-at (unix seconds)
        * ``exp`` — expiry (``iat`` + ``ACCESS_TOKEN_EXPIRE_MINUTES``)
        * ``iss`` — issuer (``world-monitor``)
        * ``jti`` — unique token id (prevents replay correlation)
    """
    if not email or not isinstance(email, str):
        raise ValueError("email must be a non-empty string")
    if not role or not isinstance(role, str):
        raise ValueError("role must be a non-empty string")
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": email.strip().lower(),
        "role": role.strip().lower(),
        "iat": now,
        "exp": now + int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60,
        "iss": _JWT_ISSUER,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any] | None:
    """Decode and verify *token*; return payload or ``None`` on failure.

    Verification enforces:
        * HS256 only (``none`` and other algorithms rejected)
        * Valid signature against :attr:`settings.SECRET_KEY`
        * ``exp`` not in the past (with 10s leeway for clock skew)
        * ``iss`` == ``world-monitor``

    Any :class:`jwt.PyJWTError` (including expiry / issuer mismatch) results
    in ``None`` rather than an exception so callers can map it uniformly to
    HTTP 401 without leaking details.
    """
    if not token or not isinstance(token, str):
        return None
    # Strip common "Bearer " prefix if caller forgot to strip it
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[_JWT_ALGORITHM],
            issuer=_JWT_ISSUER,
            leeway=10,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
        return payload
    except jwt.PyJWTError:
        return None


def verify_token_timing_safe(token: str) -> dict[str, Any] | None:
    """Timing-safe wrapper around :func:`decode_token` (kept for API symmetry).

    JWT verification is already constant-time w.r.t. the HMAC, but this alias
    preserves the naming convention paired with
    :func:`verify_password_timing_safe`.
    """
    return decode_token(token)


__all__ = [
    "DUMMY_HASH",
    "create_access_token",
    "decode_token",
    "hash_password",
    "verify_password_timing_safe",
    "verify_token_timing_safe",
]
