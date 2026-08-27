"""Authorization gate (spec §12, §47).

The scanner must NEVER attack arbitrary targets. In LAB_MODE (default) only
loopback/private-network HTTP targets and paths inside the lab source tree are
permitted. Every assessment records the authorization decision in audit_logs.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

from ..config import ROOT_DIR, settings


class AuthorizationError(ValueError):
    """Refused target or scope – caller should translate to HTTP 403."""

    pass


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

# Hosts that are never valid scan targets even if they happen to resolve to
# a private address in some environments.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.google",
        "instance-data",
    }
)

# Networks explicitly forbidden regardless of LAB_MODE private-allow logic.
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")


def _is_loopback_or_private(host_ip: str) -> bool:
    """Return True only for loopback or RFC1918/private addresses.

    Rejects link-local (169.254/16), multicast, unspecified (0.0.0.0),
    reserved and broadcast ranges.  Handles both IPv4 and IPv6.
    """
    try:
        ip = ipaddress.ip_address(host_ip.split("%")[0])  # strip zone id
    except ValueError:
        return False

    # Explicit rejects – never considered authorized even if is_private is True
    # on some Python versions.
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_link_local:
        return False
    # 0.0.0.0 / ::  is handled by is_unspecified above, but be explicit
    if str(ip) in ("0.0.0.0", "::"):
        return False

    # Loopback (127/8, ::1) and RFC1918 / ULA (fc00::/7) are allowed.
    if ip.is_loopback:
        return True
    if ip.is_private:
        # ip.is_private is True for 10/8, 172.16/12, 192.168/16, fc00::/7,
        # and also for 100.64/10 (CGNAT) on Python >=3.11 – all intended to be
        # allowed in LAB_MODE.  Link-local already rejected above.
        return True
    return False


# ---------------------------------------------------------------------------
# HTTP target validation
# ---------------------------------------------------------------------------

_MAX_URL_LENGTH = 2048


def _allowed_targets() -> list[str]:
    """Parse ALLOWED_TARGETS into a normalized list."""
    raw = getattr(settings, "ALLOWED_TARGETS", "") or ""
    out: list[str] = []
    for entry in raw.split(","):
        t = entry.strip().rstrip("/")
        if t:
            out.append(t)
    return out


def is_explicitly_allowed_target(target: str) -> bool:
    """Return whether *target* matches an explicit ALLOWED_TARGETS entry."""
    if not isinstance(target, str) or not target.strip():
        return False
    try:
        normalized = _normalize_target_url(target.strip())
    except Exception:
        return False
    for allowed in _allowed_targets():
        try:
            allowed_norm = _normalize_target_url(allowed) if "://" in allowed else allowed.rstrip("/")
        except Exception:
            allowed_norm = allowed.rstrip("/")
        if normalized == allowed_norm or normalized.startswith(allowed_norm + "/"):
            return True
    return False


def _normalize_target_url(target: str) -> str:
    """Return scheme://host[:port]/path without trailing slash for comparison."""
    parsed = urlparse(target)
    # urlparse lower-cases scheme already; host is case-insensitive.
    # Rebuild with lower-cased host for consistent comparison.
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path.rstrip("/") if parsed.path else ""
    # userinfo should have been rejected before calling this.
    return f"{parsed.scheme.lower()}://{host}{port}{path}"


def validate_http_target(target: str) -> str:
    """Return normalized target URL or raise AuthorizationError.

    Validation order:
      1. Type / length / scheme / userinfo / hostname / port checks
      2. Explicit ALLOWED_TARGETS prefix allow-list (exact or slash-boundary)
      2. LAB_MODE private/loopback DNS gate
      3. Cloud metadata hostname block
    """
    if not isinstance(target, str):
        raise AuthorizationError("Target must be a string URL")
    stripped = target.strip()
    if not stripped:
        raise AuthorizationError("Target URL is empty")
    if len(stripped) > _MAX_URL_LENGTH:
        raise AuthorizationError("Target URL exceeds maximum length")
    if "\x00" in stripped:
        raise AuthorizationError("Target URL contains null bytes")
    # Basic scheme check before urlparse to give clearer message for e.g. "file://"
    if "://" not in stripped:
        raise AuthorizationError("Target must use http:// or https://")

    parsed = urlparse(stripped)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise AuthorizationError("Target must use http:// or https://")

    # Reject URLs containing userinfo (credentials in URL) – spec §47
    if parsed.username or parsed.password:
        raise AuthorizationError("Target URL must not contain credentials")

    host = parsed.hostname
    if not host:
        raise AuthorizationError("Target URL has no hostname")
    host_lower = host.lower()

    # Validate port if present
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise AuthorizationError(f"Target port {parsed.port} is out of range")

    # Block metadata endpoints by hostname string before any DNS
    if host_lower in _BLOCKED_HOSTNAMES:
        raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
    # Also block raw 169.254.169.254 string host – covered by set but double-check IP literal
    if host_lower == "169.254.169.254":
        raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")

    normalized = _normalize_target_url(stripped)

    # Explicit allow-list bypasses LAB_MODE DNS gate but still requires valid scheme/host
    if is_explicitly_allowed_target(stripped):
        return stripped

    if settings.LAB_MODE:
        # DNS gate – every resolved address must be loopback/private
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AuthorizationError(f"Cannot resolve target host '{host}': {exc}") from exc
        if not infos:
            raise AuthorizationError(f"Cannot resolve target host '{host}': no addresses")

        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            # Handle IPv6 tuple (ip, port, flow, scope)
            ip_str = str(ip_str).split("%")[0]
            # Fast path: metadata IP literal
            if ip_str == "169.254.169.254":
                raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
            # Check link-local network directly
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                pass
            else:
                if ip_obj in _LINK_LOCAL_NET or ip_obj.is_link_local:
                    raise AuthorizationError(
                        f"LAB_MODE permits only localhost/private-lab targets; "
                        f"'{host}' resolves to link-local address {ip_str}"
                    )
            if not _is_loopback_or_private(ip_str):
                raise AuthorizationError(
                    f"LAB_MODE permits only localhost/private-lab targets; "
                    f"'{host}' resolves to public address {ip_str}"
                )

        # Final hostname block after DNS (covers CNAME chains)
        if host_lower in _BLOCKED_HOSTNAMES:
            raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
        return stripped

    raise AuthorizationError(
        "Authorization failed: enable LAB_MODE or add the target to ALLOWED_TARGETS"
    )


def resolve_target_ips(host: str, *, allow_public: bool = False) -> list[str]:
    """Resolve hostname to list of IPs at scan time. Returns list of IP strings.
    
    Raises AuthorizationError if resolution fails or any IP is not allowed in LAB_MODE.
    ``allow_public`` is reserved for an explicit ``ALLOWED_TARGETS`` entry; the
    metadata and link-local blocks still apply in that mode.
    """
    if not isinstance(host, str) or not host.strip():
        raise AuthorizationError("Host must be a non-empty string")
    
    host = host.strip().lower()
    
    # Block metadata endpoints before DNS
    if host in _BLOCKED_HOSTNAMES:
        raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
    if host == "169.254.169.254":
        raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
    
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AuthorizationError(f"Cannot resolve target host '{host}': {exc}") from exc
    
    if not infos:
        raise AuthorizationError(f"Cannot resolve target host '{host}': no addresses")
    
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        ip_str = str(ip_str).split("%")[0]
        
        # Fast path: metadata IP literal
        if ip_str == "169.254.169.254":
            raise AuthorizationError("Cloud metadata endpoints are never valid scan targets")
        
        # Check link-local network directly
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            pass
        else:
            # Keep link-local and other non-routable special ranges blocked
            # even for an explicitly allow-listed public target.
            if (
                ip_obj.is_link_local
                or ip_obj in _LINK_LOCAL_NET
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
                or ip_obj.is_reserved
            ):
                raise AuthorizationError(
                    f"Resolved target IP {ip_str} is a blocked special-purpose address"
                )
        if not allow_public and settings.LAB_MODE and not _is_loopback_or_private(ip_str):
            raise AuthorizationError(
                f"LAB_MODE permits only localhost/private-lab targets; "
                f"resolved IP {ip_str} is public"
            )
        ips.append(ip_str)
    
    if not ips:
        raise AuthorizationError(f"Cannot resolve target host: no valid addresses")
    
    return ips


# ---------------------------------------------------------------------------
# Filesystem scope validation
# ---------------------------------------------------------------------------


def _is_relative_to(path: Path, parent: Path) -> bool:
    """Compatibility wrapper for Path.is_relative_to (Python 3.9+)."""
    try:
        return path.is_relative_to(parent)  # type: ignore[attr-defined]
    except AttributeError:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False


def validate_source_path(path: str) -> str:
    """Validate that *path* stays inside LAB_SOURCE_DIR or the repo tree.

    Uses ``Path.resolve()`` to follow symlinks and collapse ``..`` components,
    then checks ``is_relative_to`` against both the lab directory and the
    repository root.  Rejects null bytes, empty strings, and drive mismatches
    on Windows.
    """
    if not isinstance(path, str):
        raise AuthorizationError("Source path must be a string")
    if "\x00" in path:
        raise AuthorizationError("Source path contains null bytes")
    stripped = path.strip()
    if not stripped:
        raise AuthorizationError("Source path is empty")
    if len(stripped) > 4096:
        raise AuthorizationError("Source path exceeds maximum length")

    # Reject obvious traversal attempts early (informative message)
    # but rely on resolve() for the authoritative check.
    if re.search(r"(^|[\\/])\.\.(?:[\\/]|$)", stripped):
        # Don't immediately reject – resolve will tell – but note it.
        pass

    try:
        p = Path(stripped).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorizationError(f"Invalid source path '{stripped}': {exc}") from exc

    try:
        root = Path(settings.LAB_SOURCE_DIR).resolve()
    except Exception as exc:
        raise AuthorizationError(f"Lab source directory misconfigured: {exc}") from exc

    repo_root = ROOT_DIR.resolve()

    # Windows drive-letter check – a path on D: can never be inside C: repo
    if p.drive.lower() != repo_root.drive.lower() and p.drive.lower() != root.drive.lower():
        # If drives differ from both allowed roots, reject.  If one matches,
        # is_relative_to will correctly decide.
        if p.drive and root.drive and p.drive.lower() != root.drive.lower():
            if p.drive.lower() != repo_root.drive.lower():
                raise AuthorizationError(
                    f"Source path '{p}' is on drive '{p.drive}' outside authorized scope "
                    f"(lab dir {root} / repo root {repo_root})"
                )

    inside_lab = p == root or _is_relative_to(p, root)
    inside_repo = p == repo_root or _is_relative_to(p, repo_root)

    if not (inside_lab or inside_repo):
        raise AuthorizationError(
            f"Source path '{p}' is outside authorized scope "
            f"(lab dir {root} / repo root {repo_root})"
        )
    return str(p)


# ---------------------------------------------------------------------------
# Authorization flag
# ---------------------------------------------------------------------------


def assert_authorized_flag(authorized: bool) -> None:
    """Require explicit ``authorized=true`` from the operator."""
    if not isinstance(authorized, bool):
        # Coerce but require explicit truthy bool – don't accept "true" strings
        authorized = bool(authorized) and authorized is True
    if not authorized:
        raise AuthorizationError(
            "Assessment refused: operator must explicitly confirm the target is "
            "authorized for security testing (authorized=true)."
        )


__all__ = [
    "AuthorizationError",
    "validate_http_target",
    "is_explicitly_allowed_target",
    "resolve_target_ips",
    "validate_source_path",
    "assert_authorized_flag",
]
