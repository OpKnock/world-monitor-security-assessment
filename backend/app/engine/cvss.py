"""CVSS v3.1 base-score engine (spec §17).

Scores are computed from real CVSS v3.1 vectors using the FIRST specification
formulas — never invented. Curated vectors per check live in CVSS_PRESETS so
findings get deterministic, explainable scores.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0}

_ALLOWED_VALUES = {
    "AV": set(AV),
    "AC": set(AC),
    "PR": set(PR_U),  # PR_U and PR_C share keys
    "UI": set(UI),
    "S": {"U", "C"},
    "C": set(CIA),
    "I": set(CIA),
    "A": set(CIA),
}


@dataclass(frozen=True)
class CVSSResult:
    score: float
    severity: str
    vector: str
    rationale: str


def parse_vector(vector: str) -> dict[str, str]:
    """Parse and validate a CVSS:3.1 vector string."""
    if not isinstance(vector, str):
        raise ValueError("CVSS vector must be a string")
    v = vector.strip()
    if not v.startswith("CVSS:3.1/"):
        raise ValueError("Only CVSS:3.1 vectors are supported")
    body = v[len("CVSS:3.1/") :]
    if not body:
        raise ValueError("CVSS vector body is empty")
    parts: dict[str, str] = {}
    for chunk in body.split("/"):
        if not chunk:
            raise ValueError("Empty metric chunk in CVSS vector")
        if ":" not in chunk:
            raise ValueError(f"Malformed metric chunk '{chunk}': missing ':'")
        k, _, val = chunk.partition(":")
        k = k.strip()
        val = val.strip()
        if not k or not val:
            raise ValueError(f"Malformed metric chunk '{chunk}'")
        if k in parts:
            raise ValueError(f"Duplicate metric '{k}' in vector")
        if k not in _ALLOWED_VALUES:
            raise ValueError(f"Unknown metric '{k}' in vector")
        if val not in _ALLOWED_VALUES[k]:
            raise ValueError(f"Invalid value '{val}' for metric '{k}'")
        parts[k] = val
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(parts)
    if missing:
        raise ValueError(f"Missing base metrics: {sorted(missing)}")
    return parts


def _roundup(value: float) -> float:
    """FIRST-spec 'Roundup': smallest 1-decimal >= value (5-significant-digit guard).

    Reference: https://www.first.org/cvss/specification-document#t6
    """
    if value <= 0:
        return 0.0
    # Scale to 5 decimal places, then apply ceil to 1 decimal.
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def compute_base_score(vector: str) -> CVSSResult:
    """Compute CVSS v3.1 base score for *vector*."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    iss = 1 - ((1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]]))
    if scope_changed:
        # Scope Changed – impact uses different formula
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        # Clamp negative impact due to floating error when iss < 0.029
        if iss <= 0.029:
            # Clamp to small negative then handle via impact <=0 branch
            pass
        exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR_C[m["PR"]] * UI[m["UI"]]
    else:
        impact = 6.42 * iss
        exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR_U[m["PR"]] * UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    else:
        if scope_changed:
            score = _roundup(min(1.08 * (impact + exploitability), 10))
        else:
            score = _roundup(min(impact + exploitability, 10))
    return CVSSResult(score=score, severity=score_to_severity(score), vector=vector, rationale=explain(m, score))


def score_to_severity(score: float) -> str:
    """Map numeric score to qualitative severity (FIRST thresholds)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "NONE"
    if s == 0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


def explain(m: dict[str, str], score: float) -> str:
    """Generate a human-readable rationale for the score."""
    av_text = {
        "N": "exploitable over the network without physical access",
        "A": "exploitable from an adjacent network segment",
        "L": "requires local access to the system",
        "P": "requires physical access",
    }[m["AV"]]
    ac_text = {"L": "no special conditions", "H": "special conditions the attacker cannot easily control"}[m["AC"]]
    pr_text = {"N": "no privileges", "L": "low privileges", "H": "high privileges"}[m["PR"]]
    ui_text = {"N": "no user interaction", "R": "a user to interact"}[m["UI"]]
    cia: list[str] = []
    for key, label in (("C", "confidentiality"), ("I", "integrity"), ("A", "availability")):
        if m[key] == "H":
            cia.append(f"total {label} loss")
        elif m[key] == "L":
            cia.append(f"partial {label} loss")
    scope = "other components beyond its security scope" if m["S"] == "C" else "its own security scope"
    return (
        f"CVSS v3.1 base score {score:.1f}: the weakness is {av_text}, with {ac_text}, "
        f"requires {pr_text} and {ui_text}. Impact: {', '.join(cia) or 'none'}; effects are contained to {scope}."
    )


# Curated vectors per stable check_id. Each is a deliberate, documented
# modelling decision — adjust here rather than inventing scores ad hoc.
CVSS_PRESETS: dict[str, str] = {
    # Authentication
    "auth.jwt_none_algorithm_accepted": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "auth.jwt_signature_not_verified": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "auth.invalid_tokens_accepted": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "auth.missing_authentication": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "auth.cookie_flags_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # Authorization
    "idor.numeric_id_enumeration": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "idor.string_id_manipulation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "idor.predictable_id_patterns": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    # API security
    "rate_limit.no_rate_limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "rate_limit.bypass_ip_header_spoofing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "rate_limit.bypass_endpoint_variant": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "rate_limit.headers_without_enforcement": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    # Input validation
    "sqli.error_based": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "sqli.boolean_based_blind": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sqli.time_based_blind": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "input_validation.reflected_xss_indicator": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "input_validation.verbose_error_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "input_validation.csrf_token_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "input_validation.fuzz_anomalies": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    # Client security (headers)
    "headers.strict_transport_security": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "headers.content_security_policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "headers.x_content_type_options": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.x_frame_options": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.referrer_policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.permissions_policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # Secure communication
    "tls.no_https_available": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "tls.no_https_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "tls.certificate_expiring_soon": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "tls.self_signed_certificate": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    # Privacy / secrets
    "secrets.default": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "secrets.private_key_material": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "privacy.excessive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "supply_chain.typosquat_candidates": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "supply_chain.unpinned_dependencies": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "supply_chain.unknown_licenses": "",
    "graphql.introspection_enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    # Dependencies – score comes from OSV/CVSS data per CVE; no static preset
    "dependencies.known_vulnerability": "",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "NONE": 0}

# Validate presets at import – fail fast on typo so scoring never silently breaks.
for _cid, _vec in CVSS_PRESETS.items():
    if _vec:
        try:
            compute_base_score(_vec)
        except Exception as exc:
            raise ValueError(f"Invalid CVSS preset for '{_cid}': {_vec} ({exc})") from exc


__all__ = [
    "AV",
    "AC",
    "PR_U",
    "PR_C",
    "UI",
    "CIA",
    "CVSSResult",
    "CVSS_PRESETS",
    "SEVERITY_ORDER",
    "parse_vector",
    "compute_base_score",
    "score_to_severity",
    "explain",
]
