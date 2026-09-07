"""Quality Gate — fail-closed thresholds for CI/CD integration."""
from typing import Any

DEFAULT_QUALITY_GATE = {
    "fail_on_critical": True,
    "fail_on_high": 2,
    "fail_on_health_below": 70,
    "fail_on_incomplete": True,
}

def check_quality_gate(counts: dict, health_score: int, has_incomplete: bool, has_failed: bool, gate: dict | None = None) -> dict[str, Any]:
    """Return {passed: bool, reasons: list[str], details: dict} for CI exit code."""
    g = gate or DEFAULT_QUALITY_GATE
    reasons: list[str] = []
    if has_incomplete and g.get("fail_on_incomplete", True):
        reasons.append("INCOMPLETE assessment(s)")
    if has_failed:
        reasons.append("FAILED assessment(s)")
    if g.get("fail_on_critical") and counts.get("CRITICAL", 0) > 0:
        reasons.append(f"CRITICAL {counts.get('CRITICAL', 0)}")
    if counts.get("HIGH", 0) > g.get("fail_on_high", 2):
        reasons.append(f"HIGH {counts.get('HIGH', 0)} > {g['fail_on_high']}")
    if health_score < g.get("fail_on_health_below", 70):
        reasons.append(f"Health {health_score}/100 < {g['fail_on_health_below']}")
    return {
        "passed": len(reasons) == 0,
        "reasons": reasons,
        "details": {"counts": counts, "health": health_score, "has_incomplete": has_incomplete, "has_failed": has_failed},
    }

def cli_check(counts: dict, health_score: int, has_incomplete: bool, has_failed: bool) -> int:
    """CLI helper — returns 0 on pass, 1 on fail (for CI)."""
    result = check_quality_gate(counts, health_score, has_incomplete, has_failed)
    if result["passed"]:
        print("QUALITY GATE: PASSED")
        return 0
    print("QUALITY GATE: FAILED")
    for r in result["reasons"]:
        print(f"  - {r}")
    return 1