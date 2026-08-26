"""Finding engine (spec §16): normalization, dedupe, remediation association."""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import DB_WRITE_LOCK
from ..models import Assessment, Evidence, Finding, ScanRun
from .cvss import CVSS_PRESETS, SEVERITY_ORDER, compute_base_score

logger = logging.getLogger(__name__)

# Allowed enumerations – keep in sync with models.Finding
_ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"}
_ALLOWED_CATEGORIES = {
    "AUTHENTICATION",
    "AUTHORIZATION",
    "INPUT_VALIDATION",
    "API_SECURITY",
    "CLIENT_SECURITY",
    "SECURE_COMMUNICATION",
    "DATA_PRIVACY",
    "DEPENDENCIES",
    "INFRASTRUCTURE",
    "PRIVACY",
}


class RawFinding(BaseModel):
    """Adapter output — the Common Finding Format before persistence."""

    title: str = Field(min_length=1, max_length=512)
    description: str = Field(default="")
    severity: str = Field(default="MEDIUM")
    category: str = Field(default="API_SECURITY")
    affected_component: str = Field(default="")
    scanner: str = Field(min_length=1, max_length=64)
    check_id: str = Field(min_length=1, max_length=128)
    reproduction: list[str] = Field(default_factory=list)
    impact: str = Field(default="")
    business_impact: str = Field(default="")
    remediation: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    cvss_vector: str | None = Field(default=None)
    scan_target: str | None = Field(default=None)
    meta: dict[str, Any] = Field(default_factory=dict)
    evidence_payloads: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        up = str(v).strip().upper() if isinstance(v, str) else "MEDIUM"
        if up not in _ALLOWED_SEVERITIES:
            # Map common variants
            mapping = {"CRIT": "CRITICAL", "MED": "MEDIUM", "INFO": "INFORMATIONAL"}
            up = mapping.get(up, "MEDIUM")
            if up not in _ALLOWED_SEVERITIES:
                up = "MEDIUM"
        return up

    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str) -> str:
        up = str(v).strip().upper() if v and isinstance(v, str) else "API_SECURITY"
        # Normalize underscores/hyphens
        up = up.replace("-", "_")
        if up not in _ALLOWED_CATEGORIES:
            # Fallback to API_SECURITY for unknown
            return "API_SECURITY"
        return up

    @field_validator("check_id")
    @classmethod
    def _validate_check_id(cls, v: str) -> str:
        s = str(v).strip() if v else ""
        if not s:
            raise ValueError("check_id must be non-empty")
        # Sanitize to allowed charset
        if not re.fullmatch(r"[a-zA-Z0-9._\-]+", s):
            # Replace illegal chars with underscore rather than rejecting
            s = re.sub(r"[^a-zA-Z0-9._\-]", "_", s)
        return s[:128]


def _normalize_target_for_fingerprint(target: str) -> str:
    """Normalize target for fingerprint stability: strip, lower scheme/host, remove trailing slash."""
    if not isinstance(target, str) or not target:
        return ""
    t = target.strip()
    # Strip trailing slashes but keep "http://host" intact
    # For fingerprint we want "http://h/api" == "http://h/api/" so rstrip
    # Lowercase scheme and host for consistency
    try:
        from urllib.parse import urlparse

        parsed = urlparse(t)
        if parsed.scheme and parsed.netloc:
            host = (parsed.hostname or "").lower()
            port = f":{parsed.port}" if parsed.port else ""
            # Keep path without trailing slash
            path = (parsed.path or "").rstrip("/")
            # Preserve query? For fingerprint we include full without trailing slash but keep path case
            # Use lower host, original path case
            rebuilt = f"{parsed.scheme.lower()}://{host}{port}{path}"
            if parsed.query:
                rebuilt += f"?{parsed.query}"
            return rebuilt.rstrip("/")
        return t.rstrip("/")
    except Exception:
        return t.rstrip("/")


def fingerprint_for(target: str, category: str, check_id: str, component: str) -> str:
    """Stable dedupe key: SHA1(target|category|check_id|component) – non-crypto identity."""
    if not isinstance(target, str):
        target = str(target) if target is not None else ""
    if not isinstance(category, str):
        category = str(category)
    if not isinstance(check_id, str):
        check_id = str(check_id)
    if not isinstance(component, str):
        component = str(component) if component is not None else ""
    basis = "|".join(
        [
            _normalize_target_for_fingerprint(target),
            category.strip().upper(),
            check_id.strip(),
            component.strip(),
        ]
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()  # noqa: S324 - non-crypto identity key


def score_finding(raw: RawFinding) -> tuple[float | None, str, str]:
    """Derive CVSS score/vector/rationale for a RawFinding.

    Priority:
      1. Explicit raw.cvss_vector
      2. Preset for raw.check_id (including private-key specialization)
      3. Fallback band by severity
    Returns (score, vector, rationale) where score may be None for INFORMATIONAL.
    """
    # Private-key specialization – always elevate even if caller supplied a generic vector
    vector: str | None = raw.cvss_vector or CVSS_PRESETS.get(raw.check_id)
    if raw.check_id.startswith("secrets.") and "PRIVATE KEY" in raw.title.upper():
        vector = CVSS_PRESETS.get("secrets.private_key_material") or vector
    elif raw.check_id.startswith("secrets.") and not vector:
        vector = CVSS_PRESETS.get("secrets.default")

    # INFORMATIONAL findings have no meaningful CVSS – return None consistently
    if raw.severity == "INFORMATIONAL":
        if not vector:
            return None, "", ""
        # If a preset exists for an informational check (e.g. unknown_licenses has "")
        # treat empty as no score
        if vector == "":
            return None, "", ""
        # Otherwise allow scoring but keep score (some informational may have LOW vector)
        # Fall through to compute

    if not vector:
        # Deterministic fallback by severity band keeps scoring honest & explainable
        fallback_vectors = {
            "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "HIGH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "LOW": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "NONE": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        }
        vector = fallback_vectors.get(raw.severity, fallback_vectors["MEDIUM"])

    if vector == "":
        return None, "", ""

    try:
        result = compute_base_score(vector)
    except Exception as exc:
        logger.warning("Failed to compute CVSS for check %s vector %s: %s", raw.check_id, vector, exc)
        # Fallback to severity band scoring
        fb = {
            "CRITICAL": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            "HIGH": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2),
            "MEDIUM": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3),
            "LOW": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
        }.get(raw.severity, ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3))
        # Recompute rationale for fallback vector
        try:
            r2 = compute_base_score(fb[0])
            return r2.score, r2.vector, r2.rationale
        except Exception:
            return fb[1], fb[0], f"Fallback scoring for severity {raw.severity}"

    return result.score, result.vector, result.rationale


REMEDIATION_KB: dict[str, dict[str, Any]] = {
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
    "privacy.": {
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
        "business_impact": "Excessive data returned to clients leaks sensitive fields and internals.",
    },
    "deep_scan.": {
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
        "business_impact": "Exposed banners and open services reduce attacker effort for targeted exploitation.",
    },
}


def enrich_from_kb(raw: RawFinding) -> RawFinding:
    """Enrich a finding with KB references and default business impact.

    Does not overwrite existing business_impact; merges references without duplicates
    preserving order.
    """
    for prefix, kb in REMEDIATION_KB.items():
        if raw.check_id.startswith(prefix):
            # Merge references – deduplicate preserving first occurrence
            combined = list(raw.references) + list(kb.get("references", []))
            # dict.fromkeys preserves order and deduplicates
            raw.references = list(dict.fromkeys(combined))
            if not raw.business_impact:
                raw.business_impact = str(kb.get("business_impact", ""))
            break
    return raw


def _sanitize_evidence_dict(ev: dict[str, Any]) -> dict[str, Any]:
    """Filter an evidence payload dict to only valid Evidence columns."""
    allowed = {"kind", "path", "summary", "meta"}
    out: dict[str, Any] = {}
    for k in allowed:
        if k in ev:
            val = ev[k]
            if isinstance(val, str):
                # Truncate to column limits
                if k == "kind":
                    out[k] = val[:30]
                elif k == "path":
                    out[k] = val[:1024]
                else:
                    out[k] = val
            else:
                out[k] = val
    # Ensure required fields have defaults
    if "kind" not in out:
        out["kind"] = "scanner_output"
    if "path" not in out:
        out["path"] = ""
    if "summary" not in out:
        out["summary"] = out.get("kind", "")
    if "meta" not in out:
        out["meta"] = {}
    return out


def persist_raw_findings(
    db: Session,
    assessment: Assessment,
    scan_run: ScanRun,
    raw_findings: list[RawFinding],
) -> tuple[list[Finding], int]:
    """Normalize + dedupe into DB. Returns (new_or_updated_findings, duplicates_merged)."""
    if not isinstance(raw_findings, list):
        raise ValueError("raw_findings must be a list")
    logger.debug("persist begin assessment=%s findings=%d", assessment.id, len(raw_findings))

    # Pre-load existing findings for this assessment to build fingerprint index
    try:
        existing = db.scalars(select(Finding).where(Finding.assessment_id == assessment.id)).all()
    except Exception as exc:
        logger.error("Failed to load existing findings for %s: %s", assessment.id, exc)
        raise

    by_fp: dict[str, Finding] = {f.fingerprint: f for f in existing}
    merged = 0
    out: list[Finding] = []

    for raw in raw_findings:
        if not isinstance(raw, RawFinding):
            logger.warning("Skipping non-RawFinding item: %r", raw)
            continue
        try:
            raw = enrich_from_kb(raw)
        except Exception as exc:
            logger.warning("KB enrichment failed for %s: %s", raw.check_id, exc)

        # Fingerprint is the dedupe key
        try:
            fp = fingerprint_for(
                raw.scan_target or assessment.target,
                raw.category,
                raw.check_id,
                raw.affected_component,
            )
        except Exception as exc:
            logger.error("Fingerprint failed for %s: %s", raw.check_id, exc)
            continue

        try:
            score, vector, rationale = score_finding(raw)
        except Exception as exc:
            logger.warning("Scoring failed for %s: %s", raw.check_id, exc)
            score, vector, rationale = None, "", ""

        finding = by_fp.get(fp)
        if finding is None:
            # Stable derived PK: sha256(assessment_id + fingerprint)[:32]
            # Guarantees uniqueness across assessments and idempotency within one.
            derived_id = hashlib.sha256((assessment.id + fp).encode("utf-8")).hexdigest()[:32]  # noqa: S324
            # Guard against truncated collision within same assessment (extremely unlikely)
            # If derived id already exists globally with different assessment, append counter
            try:
                existing_id = db.get(Finding, derived_id)
                if existing_id is not None and existing_id.assessment_id != assessment.id:
                    # Perturb with component hash to disambiguate
                    derived_id = hashlib.sha256(
                        (assessment.id + fp + raw.affected_component).encode("utf-8")
                    ).hexdigest()[:32]
            except Exception:
                pass

            # Clamp string fields to DB column limits
            finding = Finding(
                id=derived_id,
                assessment_id=assessment.id,
                title=raw.title[:512],
                description=(raw.description or "")[:8192],
                severity=raw.severity,
                category=raw.category[:40],
                affected_component=(raw.affected_component or "")[:1024],
                target=(assessment.target or "")[:2048],
                scanner=raw.scanner[:64],
                check_id=raw.check_id[:128],
                fingerprint=fp,
                cvss_score=score,
                cvss_vector=(vector or "")[:128],
                severity_rationale=(rationale or "")[:4096],
                reproduction=list(raw.reproduction)[:20] if raw.reproduction else [],
                impact=(raw.impact or "")[:4096],
                business_impact=(raw.business_impact or "")[:4096],
                remediation=(raw.remediation or "")[:8192],
                references=list(raw.references)[:20] if raw.references else [],
                status="CONFIRMED" if SEVERITY_ORDER.get(raw.severity, 0) >= 2 else "OPEN",
                authorized_target=True,
                meta=dict(raw.meta) if isinstance(raw.meta, dict) else {},
            )
            db.add(finding)
            by_fp[fp] = finding
        else:
            # Duplicate across scanners/runs: merge evidence, keep strongest severity
            merged += 1
            try:
                current_order = SEVERITY_ORDER.get(finding.severity, 0)
                incoming_order = SEVERITY_ORDER.get(raw.severity, 0)
                if incoming_order > current_order:
                    finding.severity = raw.severity
                    # Also upgrade CVSS to match the higher severity finding
                    finding.cvss_score = score
                    finding.cvss_vector = (vector or "")[:128]
                    finding.severity_rationale = (rationale or "")[:4096]
                    # Prefer more severe title/description if meaningfully different
                    # Keep original title unless incoming is significantly longer/more descriptive
                    if len(raw.title) > len(finding.title):
                        finding.title = raw.title[:512]
                # Merge references
                if raw.references:
                    merged_refs = list(dict.fromkeys(list(finding.references or []) + list(raw.references)))
                    finding.references = merged_refs[:20]
                # Merge meta
                if raw.meta:
                    base_meta = dict(finding.meta or {})
                    base_meta.update({k: v for k, v in raw.meta.items() if k not in base_meta})
                    finding.meta = base_meta
            except Exception as exc:
                logger.warning("Failed to merge duplicate finding %s: %s", fp, exc)

        # Attach evidence items – each is a dict returned by EvidenceStore.save()
        for ev in raw.evidence_payloads or []:
            if not isinstance(ev, dict):
                logger.warning("Skipping non-dict evidence payload for %s: %r", raw.check_id, ev)
                continue
            try:
                clean = _sanitize_evidence_dict(ev)
                # Evidence finding_id is set via relationship; don't set explicitly
                evidence_row = Evidence(**clean)
                finding.evidence_items.append(evidence_row)
            except Exception as exc:
                logger.warning("Failed to attach evidence for %s: %s", raw.check_id, exc)
        out.append(finding)

    logger.debug("persist pre-flush assessment=%s merged=%d", assessment.id, merged)
    # Flush under global write lock to serialize SQLite writers
    try:
        with DB_WRITE_LOCK:
            db.flush()
    except Exception as exc:
        logger.error("DB flush failed for assessment %s: %s", assessment.id, exc)
        raise
    logger.debug("persist flushed assessment=%s", assessment.id)
    return out, merged


__all__ = [
    "RawFinding",
    "fingerprint_for",
    "score_finding",
    "REMEDIATION_KB",
    "enrich_from_kb",
    "persist_raw_findings",
]
