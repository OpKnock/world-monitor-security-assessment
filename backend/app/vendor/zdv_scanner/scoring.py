import math

SEVERITY_SCORES = {
    "low": 3.0,
    "medium": 5.0,
    "high": 7.5,
    "critical": 9.8,
}

SEVERITY_BANDS = (("none", 0.1), ("low", 4.0), ("medium", 7.0), ("high", 9.0), ("critical", 10.1))

AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALUES = {"L": 0.77, "H": 0.44}
UI_VALUES = {"N": 0.85, "R": 0.62}
CIA_VALUES = {"H": 0.56, "L": 0.22, "N": 0.0}
PR_VALUES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def _roundup(value):
    if value <= 0:
        return 0.0
    scaled = value * 10
    if scaled - int(scaled) < 0.5:
        return int(scaled) / 10
    return math.ceil(scaled) / 10


def severity_from_score(score):
    for label, upper in SEVERITY_BANDS:
        if score < upper:
            return label
    return "critical"


def score_from_severity(severity):
    return SEVERITY_SCORES.get(severity, 5.0)


def cvss_base(
    attack_vector="N",
    complexity="L",
    privileges="N",
    user_interaction="N",
    scope="U",
    confidentiality="H",
    integrity="H",
    availability="H",
):
    av = AV_VALUES[attack_vector]
    ac = AC_VALUES[complexity]
    pr = PR_VALUES[scope][privileges]
    ui = UI_VALUES[user_interaction]
    c = CIA_VALUES[confidentiality]
    i = CIA_VALUES[integrity]
    a = CIA_VALUES[availability]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    base = impact + exploitability
    if impact <= 0:
        base = 0.0
    score = _roundup(min(base, 10.0))
    return {"score": round(score, 1), "severity": severity_from_score(score)}


def prioritize(findings):
    ranked = []
    for finding in findings:
        score = finding.get("score") if finding.get("score") is not None else score_from_severity(finding.get("severity", "medium"))
        severity = finding.get("severity") or severity_from_score(score)
        ranked.append({**finding, "score": round(score, 1), "severity": severity})
    return sorted(ranked, key=lambda f: f["score"], reverse=True)
