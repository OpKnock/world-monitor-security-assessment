"""Finding engine (spec §16): normalization, dedupe, remediation association."""
import hashlib
import logging

logger = logging.getLogger(__name__)
from datetime import datetime, timezone

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import DB_WRITE_LOCK
from ..models import Assessment, Evidence, Finding, ScanRun
from .cvss import CVSS_PRESETS, SEVERITY_ORDER, compute_base_score


class RawFinding(BaseModel):
    """Adapter output — the Common Finding Format before persistence."""

    title: str
    description: str = ""
    severity: str = "MEDIUM"
    category: str = "API_SECURITY"
    affected_component: str = ""
    scanner: str
    check_id: str
    reproduction: list[str] = Field(default_factory=list)
    impact: str = ""
    business_impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None  # explicit vector overrides preset
    scan_target: str | None = None  # URL/path actually probed (fingerprint basis)
    meta: dict = Field(default_factory=dict)
    evidence_payloads: list[dict] = Field(default_factory=list)


def fingerprint_for(target: str, category: str, check_id: str, component: str) -> str:
    basis = "|".join([target.rstrip("/"), category, check_id, component])
    return hashlib.sha1(basis.encode()).hexdigest()  # noqa: S324 - non-crypto identity key


def score_finding(raw: RawFinding) -> tuple[float | None, str, str]:
    vector = raw.cvss_vector or CVSS_PRESETS.get(raw.check_id)
    if raw.check_id.startswith("secrets.") and "PRIVATE KEY" in raw.title.upper():
        vector = CVSS_PRESETS["secrets.private_key_material"]
    elif raw.check_id.startswith("secrets.") and not vector:
        vector = CVSS_PRESETS["secrets.default"]
    if raw.severity == "INFORMATIONAL" and not vector:
        return None, "", ""
    if not vector:
        # deterministic fallback by severity band keeps scoring honest & explainable
        fallback_vectors = {
            "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "HIGH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "LOW": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        }
        vector = fallback_vectors[raw.severity]
    result = compute_base_score(vector)
    return result.score, result.vector, result.rationale


REMEDIATION_KB: dict[str, dict] = {
    # check_id prefix -> default impact/business-impact/remediation/references
    "auth.": {
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
        "business_impact": "Account takeover and session hijacking expose user data and platform trust.",
    },
    "idor.": {
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
        "business_impact": "Users can read other users' data — a direct privacy breach and regulatory exposure.",
    },
    "rate_limit.": {
        "references": ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
        "business_impact": "Enables brute force, credential stuffing and resource exhaustion at scale.",
    },
    "sqli.": {
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        "business_impact": "Full database compromise: mass data theft or tampering through one endpoint.",
    },
    "input_validation.": {
        "references": ["https://owasp.org/www-community/attacks/xss/"],
        "business_impact": "Script injection in user browsers leads to session theft and phishing.",
    },
    "headers.": {
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "business_impact": "Browser-side defenses are disabled, amplifying XSS/clickjacking attacks.",
    },
    "tls.": {
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
        "business_impact": "Traffic can be intercepted or downgraded in transit.",
    },
    "secrets.": {
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
        "business_impact": "Exposed credentials grant attackers direct access to systems and data.",
    },
    "graphql.": {
        "references": ["https://graphql.org/learn/security/"],
        "business_impact": "Schema disclosure maps your entire API surface for attackers.",
    },
    "supply_chain.": {
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html"],
        "business_impact": "Compromised packages flow straight into production builds.",
    },
    "dependencies.": {
        "references": ["https://osv.dev/"],
        "business_impact": "Known-exploitable library flaws are reachable from the application.",
    },
}


def enrich_from_kb(raw: RawFinding) -> RawFinding:
    for prefix, kb in REMEDIATION_KB.items():
        if raw.check_id.startswith(prefix):
            raw.references = list(dict.fromkeys(raw.references + kb["references"]))
            if not raw.business_impact:
                raw.business_impact = kb["business_impact"]
            break
    return raw


def persist_raw_findings(
    db: Session,
    assessment: Assessment,
    scan_run: ScanRun,
    raw_findings: list[RawFinding],
) -> tuple[list[Finding], int]:
    """Normalize + dedupe into DB. Returns (new_or_updated_findings, duplicates_merged)."""
    logger.debug('persist begin')
    existing = db.scalars(select(Finding).where(Finding.assessment_id == assessment.id)).all()
    by_fp = {f.fingerprint: f for f in existing}
    merged = 0
    out: list[Finding] = []
    for raw in raw_findings:
        raw = enrich_from_kb(raw)
        fp = fingerprint_for(raw.scan_target or assessment.target,
                             raw.category, raw.check_id, raw.affected_component)
        score, vector, rationale = score_finding(raw)
        finding = by_fp.get(fp)
        if finding is None:
            finding = Finding(
                id=hashlib.md5(fp.encode()).hexdigest()[:32],  # noqa: S324 - stable derived id
                assessment_id=assessment.id,
                title=raw.title,
                description=raw.description,
                severity=raw.severity,
                category=raw.category,
                affected_component=raw.affected_component,
                target=assessment.target,
                scanner=raw.scanner,
                check_id=raw.check_id,
                fingerprint=fp,
                cvss_score=score,
                cvss_vector=vector,
                severity_rationale=rationale,
                reproduction=raw.reproduction,
                impact=raw.impact,
                business_impact=raw.business_impact,
                remediation=raw.remediation,
                references=raw.references,
                status="CONFIRMED" if SEVERITY_ORDER[raw.severity] >= 2 else "OPEN",
                authorized_target=True,
                meta=raw.meta,
            )
            db.add(finding)
            by_fp[fp] = finding
        else:
            # duplicate across scanners/runs: merge evidence only, keep strongest severity
            merged += 1
            if SEVERITY_ORDER[raw.severity] > SEVERITY_ORDER[finding.severity]:
                finding.severity = raw.severity
        for ev in raw.evidence_payloads:
            finding.evidence_items.append(Evidence(**ev))
        out.append(finding)
    logger.debug('persist pre-flush')
    with DB_WRITE_LOCK:
        db.flush()
    logger.debug('persist flushed')
    return out, merged
