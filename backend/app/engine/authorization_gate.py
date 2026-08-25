"""Authorization gate (spec §12, §47).

The scanner must NEVER attack arbitrary targets. In LAB_MODE (default) only
loopback/private-network HTTP targets and paths inside the lab source tree are
permitted. Every assessment records the authorization decision in audit_logs.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from ..config import settings, ROOT_DIR


class AuthorizationError(ValueError):
    pass


def _is_loopback_or_private(host_ip: str) -> bool:
    ip = ipaddress.ip_address(host_ip)
    if ip.is_loopback or ip.is_private:
        # explicitly exclude cloud-metadata style link-local targets
        return not ipaddress.ip_address(host_ip).is_link_local
    return False


def validate_http_target(target: str) -> str:
    """Return normalized target URL or raise AuthorizationError."""
    parsed = urlparse(target.strip())
    if parsed.scheme not in ("http", "https"):
        raise AuthorizationError("Target must use http:// or https://")
    host = parsed.hostname
    if not host:
        raise AuthorizationError("Target URL has no hostname")

    allowed_extra = [t.strip().rstrip("/") for t in settings.ALLOWED_TARGETS.split(",") if t.strip()]
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}" if parsed.path else target.strip().rstrip("/")

    for allowed in allowed_extra:
        if normalized == allowed or normalized.startswith(allowed):
            return target.strip()

    if settings.LAB_MODE:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise AuthorizationError(f"Cannot resolve target host '{host}': {exc}") from exc
        for info in infos:
            ip = info[4][0]
            if not _is_loopback_or_private(ip):
                raise AuthorizationError(
                    f"LAB_MODE permits only localhost/private-lab targets; "
                    f"'{host}' resolves to public address {ip}"
                )
        # block well-known metadata endpoints even on private ranges
        if host in ("169.254.169.254", "metadata.google.internal"):
            raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
        return target.strip()

    raise AuthorizationError(
        "Authorization failed: enable LAB_MODE or add the target to ALLOWED_TARGETS"
    )


def validate_source_path(path: str) -> str:
    """Filesystem scope for secrets/dependency scanners must stay inside LAB_SOURCE_DIR."""
    from pathlib import Path

    p = Path(path).resolve()
    root = Path(settings.LAB_SOURCE_DIR).resolve()
    if ROOT_DIR.resolve() not in p.parents and root not in p.parents and p != root:
        # allow scanning any project inside the master repo tree (e.g., its own backend/)
        inside_root = ROOT_DIR.resolve() in p.parents
        inside_lab = root in p.parents or p == root
        if not (inside_lab or inside_root):
            raise AuthorizationError(
                f"Source path '{p}' is outside authorized scope "
                f"(lab dir {root} / repo root)"
            )
    return str(p)


def assert_authorized_flag(authorized: bool) -> None:
    if not bool(authorized):
        raise AuthorizationError(
            "Assessment refused: operator must explicitly confirm the target is "
            "authorized for security testing (authorized=true)."
        )
