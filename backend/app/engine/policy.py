"""Policy engine for release gate — fail-closed."""
from typing import Any

DEFAULT_POLICY = {
    "block_on_critical": True,
    "block_on_high": 2,
    "block_on_health_below": 70,
    "block_on_incomplete": True,
}

def evaluate_policy(counts: dict, health_score: int, has_incomplete: bool, has_failed: bool, policy: dict | None = None) -> dict[str, Any]:
    p = policy or DEFAULT_POLICY
    reasons: list[str] = []
    blocked = False
    if has_incomplete and p.get("block_on_incomplete", True):
        blocked = True
        reasons.append("INCOMPLETE assessment(s) — scanner error/timeout")
    if has_failed:
        blocked = True
        reasons.append("FAILED assessment(s)")
    if p.get("block_on_critical") and counts.get("CRITICAL", 0) > 0:
        blocked = True
        reasons.append(f"CRITICAL {counts.get('CRITICAL',0)}")
    if counts.get("HIGH", 0) > p.get("block_on_high", 2):
        blocked = True
        reasons.append(f"HIGH {counts.get('HIGH',0)} > {p['block_on_high']}")
    if health_score < p.get("block_on_health_below", 70):
        blocked = True
        reasons.append(f"Health {health_score}/100 < {p['block_on_health_below']}")
    return {"blocked": blocked, "status": "BLOCKED" if blocked else "APPROVED", "reasons": reasons, "policy": p}
