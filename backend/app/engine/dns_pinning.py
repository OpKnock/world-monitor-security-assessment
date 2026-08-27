"""Thread-safe DNS pinning for scanner network requests.

The scan target keeps its hostname so HTTPS SNI and virtual-host routing work,
while requests made inside the pinning context resolve that hostname only to
the addresses authorized immediately before the scan.
"""
from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

_INSTALL_LOCK = threading.Lock()
_INSTALLED = False
_PIN = threading.local()
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def _pinned_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> list[tuple]:
    pin = getattr(_PIN, "value", None)
    normalized = str(host).rstrip(".").lower() if host is not None else ""
    if pin is None or normalized != pin[0]:
        return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)

    results: list[tuple] = []
    for ip in pin[1]:
        results.extend(_ORIGINAL_GETADDRINFO(ip, port, *args, **kwargs))
    if not results:
        raise socket.gaierror(socket.EAI_NONAME, "pinned host has no addresses")
    return results


def _install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    with _INSTALL_LOCK:
        if not _INSTALLED:
            socket.getaddrinfo = _pinned_getaddrinfo
            _INSTALLED = True


@contextmanager
def pin_target_dns(target: str, ips: list[str]) -> Iterator[None]:
    """Pin DNS for *target* during all requests on the current thread."""
    host = urlparse(target).hostname if target else None
    if not host or not ips:
        yield
        return
    _install()
    previous = getattr(_PIN, "value", None)
    _PIN.value = (host.rstrip(".").lower(), tuple(ips))
    try:
        yield
    finally:
        if previous is None:
            try:
                del _PIN.value
            except AttributeError:
                pass
        else:
            _PIN.value = previous


__all__ = ["pin_target_dns"]
