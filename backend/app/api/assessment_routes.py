"""Assessment / findings / retest routes."""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from ..config import settings
from ..db import get_db
from ..engine.authorization_gate import AuthorizationError
from ..engine.orchestration import create_assessment, retest_finding, start_assessment_async
from ..models import Assessment, Evidence, Finding, ScanRun
from .deps import get_current_user, require_role
from .rate_limit import enforce_rate_limit
from fastapi import Request

router = APIRouter(prefix="/assessments", tags=["assessments"])


class NewAssessment(BaseModel):
    target: str = ""
    modules: list[str] = Field(min_length=1)
    authorized: bool = False
    source_path: str | None = None
    # optional lab demo token for authenticated checks; never persisted
    auth_token: str | None = None
    # optional per-module target overrides, e.g. {"authorization": ".../api/reports"}
    module_targets: dict[str, str] = Field(default_factory=dict)


@router.post("", status_code=201)
def create(
    body: NewAssessment,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("analyst")),
):
    enforce_rate_limit(request, 20)
    try:
        assessment = create_assessment(
            db,
            user_email=user.email,
            target=body.target.strip(),
            modules=body.modules,
            authorized=body.authorized,
            source_path=body.source_path,
            module_targets={k: v for k, v in body.module_targets.items() if v.strip()},
        )
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc)) from exc
    start_assessment_async(assessment.id, auth_token=body.auth_token)
    return _assessment_dict(db, assessment)


@router.get("")
def list_assessments(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.scalars(select(Assessment).order_by(Assessment.created_at.desc()).limit(50)).all()
    return [_assessment_summary(a) for a in rows]


@router.get("/{assessment_id}")
def get_assessment(assessment_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, detail="assessment not found")
    return _assessment_dict(db, assessment)


@router.get("/{assessment_id}/findings")
def assessment_findings(assessment_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.scalars(
        select(Finding).where(Finding.assessment_id == assessment_id).order_by(Finding.severity)
    ).all()
    return [_finding_dict(f) for f in rows]


@router.get("/-/findings")
def all_findings(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    q = select(Finding).order_by(Finding.created_at.desc()).limit(300)
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if category:
        q = q.where(Finding.category == category.upper())
    if status:
        q = q.where(Finding.status == status.upper())
    return [_finding_dict(f) for f in db.scalars(q).all()]


@router.get("/findings/{finding_id}")
def get_single_finding(finding_id: str, db: Session = Depends(get_db),
                       user=Depends(get_current_user)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, detail="finding not found")
    return _finding_dict(finding)


@router.post("/findings/{finding_id}/retest")
def retest(
    finding_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("analyst")),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, detail="finding not found")
    try:
        result = retest_finding(db, finding_id, user.email)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    return result


@router.get("/findings/{finding_id}/evidence")
def finding_evidence(finding_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, detail="finding not found")
    items = db.scalars(select(Evidence).where(Evidence.finding_id == finding_id)).all()
    out = []
    for ev in items:
        doc = {}
        path = settings.EVIDENCE_DIR / ev.path
        if path.exists():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                doc = {"error": "unreadable evidence file"}
        out.append({"id": ev.id, "kind": ev.kind, "summary": ev.summary,
                    "path": ev.path, "created_at": ev.created_at.isoformat(), "document": doc})
    return out


def _assessment_summary(a: Assessment) -> dict:
    return {
        "id": a.id, "target": a.target, "modules": a.modules, "status": a.status,
        "authorized": a.authorized, "created_at": a.created_at.isoformat(),
        "finished_at": a.finished_at.isoformat() if a.finished_at else None,
    }


def _assessment_dict(db: Session, a: Assessment) -> dict:
    runs = db.scalars(select(ScanRun).where(ScanRun.assessment_id == a.id)).all()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in db.scalars(select(Finding).where(Finding.assessment_id == a.id)).all():
        counts[f.severity] = counts.get(f.severity, 0) + 1
    data = _assessment_summary(a)
    data.update({
        "scan_runs": [{
            "id": r.id, "scanner": r.scanner, "status": r.status,
            "duration_ms": r.duration_ms, "findings_count": r.findings_count,
            "checks_total": r.checks_total, "checks_safe": r.checks_safe,
            "error": r.error[:400],
        } for r in runs],
        "severity_counts": counts,
    })
    return data


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "category": f.category,
        "affected_component": f.affected_component,
        "target": f.target,
        "scanner": f.scanner,
        "check_id": f.check_id,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "severity_rationale": f.severity_rationale,
        "reproduction": f.reproduction,
        "impact": f.impact,
        "business_impact": f.business_impact,
        "remediation": f.remediation,
        "references": f.references,
        "status": f.status,
        "retest_status": f.retest_status,
        "retest_count": f.retest_count,
        "retested_at": f.retested_at.isoformat() if f.retested_at else None,
        "created_at": f.created_at.isoformat(),
        "assessment_id": f.assessment_id,
    }
