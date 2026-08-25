"""Finding normalization, dedupe fingerprints and scoring."""
from backend.app.engine.findings import (
    RawFinding,
    fingerprint_for,
    score_finding,
)


def test_fingerprint_stable_and_scoped():
    a = fingerprint_for("http://h/api", "AUTHORIZATION", "idor.x", "/api/reports")
    b = fingerprint_for("http://h/api/", "AUTHORIZATION", "idor.x", "/api/reports")
    c = fingerprint_for("http://h/api", "AUTHORIZATION", "idor.y", "/api/reports")
    assert a == b  # trailing slash normalized
    assert a != c


def test_preset_vector_scores_deterministically():
    raw = RawFinding(title="t", severity="CRITICAL", scanner="authentication",
                     check_id="auth.jwt_none_algorithm_accepted")
    score, vector, rationale = score_finding(raw)
    assert score == 9.8
    assert vector.startswith("CVSS:3.1/")
    assert rationale


def test_severity_fallback_when_no_preset():
    raw = RawFinding(title="x", severity="HIGH", scanner="custom", check_id="custom.unknown")
    score, _, rationale = score_finding(raw)
    assert score is not None and rationale


def test_informational_without_vector_scores_none():
    raw = RawFinding(title="i", severity="INFORMATIONAL", scanner="s", check_id="s.none")
    assert score_finding(raw) == (None, "", "")
