"""CVSS v3.1 base-score engine (spec §17).

Scores are computed from real CVSS v3.1 vectors using the FIRST specification
formulas — never invented. Curated vectors per check live in CVSS_PRESETS so
findings get deterministic, explainable scores.
"""
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0}


@dataclass
class CVSSResult:
    score: float
    severity: str
    vector: str
    rationale: str


def parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Only CVSS:3.1 vectors are supported")
    parts = {}
    for chunk in vector[len("CVSS:3.1/"):].split("/"):
        k, _, v = chunk.partition(":")
        parts[k] = v
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(parts)
    if missing:
        raise ValueError(f"Missing base metrics: {sorted(missing)}")
    return parts


def _roundup(value: float) -> float:
    """FIRST-spec 'Roundup': smallest 1-decimal >= value (5-significant-digit guard)."""
    import math

    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def compute_base_score(vector: str) -> CVSSResult:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    iss = 1 - ((1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR_C[m["PR"]] * UI[m["UI"]]
    else:
        impact = 6.42 * iss
        exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR_U[m["PR"]] * UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10)) if scope_changed else _roundup(min(impact + exploitability, 10))
    return CVSSResult(score=score, severity=score_to_severity(score), vector=vector, rationale=explain(m, score))


def score_to_severity(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def explain(m: dict[str, str], score: float) -> str:
    av_text = {
        "N": "exploitable over the network without physical access",
        "A": "exploitable from an adjacent network segment",
        "L": "requires local access to the system",
        "P": "requires physical access",
    }[m["AV"]]
    ac_text = {"L": "no special conditions", "H": "special conditions the attacker cannot easily control"}[m["AC"]]
    pr_text = {"N": "no privileges", "L": "low privileges", "H": "high privileges"}[m["PR"]]
    ui_text = {"N": "no user interaction", "R": "a user to interact"}[m["UI"]]
    cia = []
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
    "rate_limit.headers_without_enforcement": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    # Input validation
    "sqli.error_based": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "sqli.boolean_based_blind": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sqli.time_based_blind": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "input_validation.reflected_xss_indicator": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "input_validation.verbose_error_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    # Client security (headers)
    "headers.strict_transport_security": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "headers.content_security_policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "headers.x_content_type_options": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.x_frame_options": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.referrer_policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "headers.permissions_policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    # Secure communication
    "tls.no_https_available": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "tls.certificate_expiring_soon": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "tls.self_signed_certificate": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    # Privacy / secrets
    "secrets.default": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "secrets.private_key_material": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "privacy.excessive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    'supply_chain.typosquat_candidates': 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N',
    'graphql.introspection_enabled': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    # Dependencies
    "dependencies.known_vulnerability": "",  # score comes from OSV/CVSS data per CVE
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "NONE": 0}
