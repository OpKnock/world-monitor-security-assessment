"""CVSS 3.1 validation — basic format and score/vector consistency."""
import re
from typing import Any

CVSS31_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.1/"
    r"(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|"
    r"C:[HNL]|I:[HNL]|A:[HNL]"
    r"(?:/CR:[XLMH]|/IR:[XLMH]|/AR:[XLMH]|"
    r"/MAV:[NALP]|/MAC:[LH]|/MPR:[NLH]|/MUI:[NR]|/MS:[UC]|"
    r"/MC:[HNL]|/MI:[HNL]|/MA:[HNL])*)$"
)

VALID_CVSS_VERSIONS = ("3.1", "4.0")

def validate_cvss(version: str, score: float | None, vector: str) -> dict[str, Any]:
    """Return {valid: bool, errors: list[str]}."""
    errors: list[str] = []
    if version not in VALID_CVSS_VERSIONS:
        errors.append(f"Invalid CVSS version: {version} (expected 3.1 or 4.0)")
    if score is not None:
        if not (0.0 <= score <= 10.0):
            errors.append(f"CVSS score out of range: {score}")
    if vector:
        if not CVSS31_VECTOR_PATTERN.match(vector):
            errors.append(f"Invalid CVSS 3.1 vector format: {vector[:80]}")
    return {"valid": len(errors) == 0, "errors": errors}

def severity_from_cvss(score: float) -> str:
    """Map CVSS v3.1 score to qualitative severity."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"