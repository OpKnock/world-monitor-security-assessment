"""CVSS v3.1 engine correctness (spec §17) — validated against FIRST examples."""
import pytest

from backend.app.engine.cvss import CVSS_PRESETS, compute_base_score, parse_vector


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_known_vectors(vector, score):
    assert compute_base_score(vector).score == score


def test_severity_bands():
    assert compute_base_score(CVSS_PRESETS["auth.jwt_none_algorithm_accepted"]).severity == "CRITICAL"
    assert compute_base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N").severity == "MEDIUM"


def test_rationale_mentions_metrics():
    r = compute_base_score(CVSS_PRESETS["auth.jwt_none_algorithm_accepted"])
    assert "network" in r.rationale and "total confidentiality" in r.rationale


def test_rejects_incomplete_vector():
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:N/AC:L")


def test_presets_are_parseable():
    for check_id, vector in CVSS_PRESETS.items():
        if vector:
            compute_base_score(vector)
