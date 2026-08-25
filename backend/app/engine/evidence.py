"""Evidence engine (spec §18).

Stores per-finding evidence as sanitized JSON files under EVIDENCE_DIR and
masks every sensitive value before persisting: Authorization/Cookie/API-key
headers, tokens, passwords and common secret shapes.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings

MAX_BODY_BYTES = 4096

MASK = "********"

_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-session-token", "proxy-authorization",
}

_SECRET_BODY_PATTERNS = [
    re.compile(r"(?i)(\"?password\"?\s*[:=]\s*)(\"[^\"]{1,64}\"|'[^']{1,64}'|[^\s,&\"]{4,64})"),
    re.compile(r"(?i)(\"?token\"?\s*[:=]\s*)(\"?[A-Za-z0-9._\-]{8,64}\"?)"),
    re.compile(r"(?i)(\"?api[_-]?key\"?\s*[:=]\s*)(\"?[A-Za-z0-9._\-]{8,64}\"?)"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,})"),
    re.compile(r"(sk-[A-Za-z0-9]{20,})"),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)"),
]


def mask_headers(headers: dict[str, str] | list[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, dict) else headers
    masked: dict[str, str] = {}
    for name, value in items:
        key = str(name)
        low = key.lower()
        if low in _SENSITIVE_HEADERS:
            prefix = ""
            for scheme in ("Bearer ", "Basic ", "bearer ", "basic "):
                if str(value).startswith(scheme):
                    prefix = scheme
                    break
            masked[key] = f"{prefix}{MASK}"
        else:
            masked[key] = str(value)
    return masked


def mask_text(text: str) -> str:
    """Mask captured secret portions while keeping key/prefix context."""
    out = text or ""
    for pattern in _SECRET_BODY_PATTERNS:
        def _sub(match: re.Match) -> str:
            ngroups = pattern.groups
            if ngroups >= 2:
                return f"{match.group(1)}{MASK}"
            return MASK
        out = pattern.sub(_sub, out)
    return out


def mask_body(body: str | bytes | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return mask_text(body[:MAX_BODY_BYTES])


class EvidenceStore:
    def __init__(self, assessment_id: str):
        self.dir = Path(settings.EVIDENCE_DIR) / assessment_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def save(
        self,
        kind: str,
        payload: dict,
        summary: str = "",
    ) -> dict:
        """Persist a sanitized evidence document; returns {id,path,...} metadata."""
        self._counter += 1
        ts = datetime.now(timezone.utc).isoformat()
        doc = {"kind": kind, "captured_at": ts, **payload}
        name = f"evidence_{self._counter:04d}.json"
        path = self.dir / name
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        rel = str(path.relative_to(settings.EVIDENCE_DIR)).replace("\\", "/")
        return {"path": rel, "kind": kind, "summary": summary or kind}

    def save_http_exchange(
        self,
        method: str,
        url: str,
        request_headers: dict[str, str] | None = None,
        request_body: str | bytes | None = None,
        status_code: int | None = None,
        response_headers: dict[str, str] | list[tuple[str, str]] | None = None,
        response_body: str | bytes | None = None,
        note: str = "",
    ) -> dict:
        return self.save(
            kind="http_exchange",
            summary=note or f"{method} {url} -> {status_code}",
            payload={
                "request": {
                    "method": method,
                    "url": url,
                    "headers": mask_headers(request_headers or {}),
                    "body_excerpt": mask_body(request_body),
                },
                "response": {
                    "status_code": status_code,
                    "headers": mask_headers(response_headers or {}),
                    "body_excerpt": mask_body(response_body),
                },
            },
        )

    def save_scanner_output(self, scanner: str, raw_output: str | dict, note: str = "") -> dict:
        text = raw_output if isinstance(raw_output, str) else json.dumps(raw_output, indent=2)
        return self.save(
            kind="scanner_output",
            summary=note or f"{scanner} raw output",
            payload={"scanner": scanner, "output_excerpt": mask_text(text[:MAX_BODY_BYTES])},
        )

    def save_file_match(self, file_path: str, line_number: int, snippet_masked: str, rule_id: str) -> dict:
        return self.save(
            kind="file_match",
            summary=f"{rule_id} at {file_path}:{line_number}",
            payload={
                "file_path": file_path,
                "line_number": line_number,
                "snippet": snippet_masked,
            },
        )
