"""Dashboard, scanners metadata, reports, settings routes."""
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..engine.reporting import generate_report
from ..models import Assessment, AuditLog, Finding, Report
from ..scanners.base import AVAILABLE_MODULES
from .deps import get_current_user, require_role


# --- Health Score (0-100) ---  weights calibrated for cinematic before/after demo
#   CRITICAL 5, HIGH 3, MEDIUM 1.5, LOW 0.5  ->  e.g. 2C+4H+6M+3L = 32.5 penalty -> 68 health
#   After fixing 2C+3H+3M -> penalty ~9 -> 91 health. Clamped 0-100.
HEALTH_WEIGHTS = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 1.5, "LOW": 0.5, "INFORMATIONAL": 0}

def compute_health(counts: dict) -> int:
    penalty = sum(counts.get(k, 0) * w for k, w in HEALTH_WEIGHTS.items())
    score = 100 - penalty
    # bonus for zero findings is 100, never negative
    return max(0, min(100, round(score)))

def health_breakdown(counts: dict) -> dict:
    return {
        "score": compute_health(counts),
        "penalty": round(sum(counts.get(k,0)*w for k,w in HEALTH_WEIGHTS.items()),1),
        "weights": HEALTH_WEIGHTS,
    }


router = APIRouter(tags=["misc"])


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user=Depends(require_role("analyst"))):
    sev_rows = db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    ).all()
    cat_rows = db.execute(
        select(Finding.category, Finding.severity, func.count(Finding.id))
        .group_by(Finding.category, Finding.severity)
    ).all()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for severity, n in sev_rows:
        counts[severity] = counts.get(severity, 0) + n

    categories: dict[str, dict] = {}
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    for category, severity, n in cat_rows:
        entry = categories.setdefault(category, {"total": 0, "worst_severity": "INFORMATIONAL", "counts": {}})
        entry["total"] += n
        entry["counts"][severity] = entry["counts"].get(severity, 0) + n
        if rank.get(severity, 0) > rank.get(entry["worst_severity"], 0):
            entry["worst_severity"] = severity

    recent = db.scalars(select(Assessment).order_by(Assessment.created_at.desc()).limit(8)).all()
    health = health_breakdown(counts)
    # per-assessment health (last 8)
    recent_health = []
    for a in recent:
        ac = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFORMATIONAL":0}
        for sev, n in db.execute(select(Finding.severity, func.count(Finding.id)).where(Finding.assessment_id==a.id).group_by(Finding.severity)).all():
            ac[sev]=n
        recent_health.append({"id": a.id, "score": compute_health(ac), "counts": ac})
    # retest summary across all findings
    retest_counts = {"FIXED":0, "STILL_PRESENT":0, "INCONCLUSIVE":0, "PENDING":0}
    for f in db.scalars(select(Finding)).all():
        if f.retest_status:
            retest_counts[f.retest_status] = retest_counts.get(f.retest_status,0)+1
        else:
            retest_counts["PENDING"]+=1
    return {
        "total_findings": sum(counts.values()),
        "severity_counts": counts,
        "categories": categories,
        "health": health,
        "recent_health": recent_health,
        "retest_summary": retest_counts,
        "recent_assessments": [{
            "id": a.id, "target": a.target, "status": a.status,
            "created_at": a.created_at.isoformat(), "modules": a.modules,
        } for a in recent],
    }


@router.get("/scanners")
def scanners_meta(user=Depends(require_role("analyst"))):
    return {
        "modules": [
            {"key": key, **meta, "available": True}
            for key, meta in AVAILABLE_MODULES.items()
        ],
        "lab_mode": settings.LAB_MODE,
        "allowed_targets_extra": [t for t in settings.ALLOWED_TARGETS.split(",") if t.strip()],
    }


@router.post("/reports/assessment/{assessment_id}")
def create_report(
    assessment_id: str,
    format: str = "pdf",
    db: Session = Depends(get_db),
    user=Depends(require_role("analyst")),
):
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(404, detail="assessment not found")
    fmt = format.lower()
    if fmt not in ("pdf", "json", "md", "csv"):
        raise HTTPException(422, detail="format must be pdf|json|md|csv")
    try:
        report = generate_report(db, assessment, fmt, generated_by=user.email)
    except Exception as exc:
        raise HTTPException(500, detail=f"report generation failed: {exc}") from exc
    return {"id": report.id, "format": report.format, "path": f"/api/reports/{report.id}/download"}


@router.get("/reports/assessment/{assessment_id}")
def list_reports(assessment_id: str, db: Session = Depends(get_db), user=Depends(require_role("analyst"))):
    rows = db.scalars(select(Report).where(Report.assessment_id == assessment_id)).all()
    return [{"id": r.id, "format": r.format, "created_at": r.created_at.isoformat(),
             "download": f"/api/reports/{r.id}/download"} for r in rows]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db), user=Depends(require_role("analyst"))):
    from pathlib import Path

    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, detail="report not found")
    file = settings.REPORT_DIR / Path(report.path).name
    if not file.exists():
        raise HTTPException(404, detail="report file missing")
    media = {"pdf": "application/pdf", "json": "application/json",
             "md": "text/markdown", "csv": "text/csv"}.get(report.format, "application/octet-stream")
    return FileResponse(file, media_type=media)


@router.post("/lab/token")
def lab_token(user=Depends(get_current_user)):
    """Fetch a JWT from the local vulnerable lab using its documented demo
    account, so assessments can exercise authenticated checks. The lab and its
    credentials are public by design; this proxy exists purely for UX."""
    import httpx

    try:
        resp = httpx.post(
            f"{settings.LAB_APP_URL.rstrip('/')}/login",
            json={"username": "alice", "password": "user123"},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(503, detail=f"lab unreachable at {settings.LAB_APP_URL}: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(502, detail="lab login failed")
    return {"access_token": resp.json().get("access_token"), "note": "lab demo token"}


@router.get("/audit-logs")
def audit_logs(db: Session = Depends(get_db), user=Depends(require_role("admin"))):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)).all()
    return [{
        "id": r.id, "user_email": r.user_email, "action": r.action,
        "target": r.target, "detail": r.detail, "created_at": r.created_at.isoformat(),
    } for r in rows]


@router.get("/settings")
def platform_settings(user=Depends(require_role("analyst"))):
    from pathlib import Path as _P
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "lab_mode": settings.LAB_MODE,
        "lab_url": settings.LAB_APP_URL,
        "lab_source_dir": str(settings.LAB_SOURCE_DIR),
        "evidence_dir": str(settings.EVIDENCE_DIR),
        "report_dir": str(settings.REPORT_DIR),
        "secrets_binary": settings.SECRETS_SCANNER_BIN or str(settings.BIN_DIR / "portia.exe"),
        "sbom_binary": settings.SBOM_SCANNER_BIN or str(settings.BIN_DIR / "bomber.exe"),
        "binaries_present": {
            "portia": (_P(settings.SECRETS_SCANNER_BIN) if settings.SECRETS_SCANNER_BIN else settings.BIN_DIR / "portia.exe").exists(),
            "bomber": (_P(settings.SBOM_SCANNER_BIN) if settings.SBOM_SCANNER_BIN else settings.BIN_DIR / "bomber.exe").exists(),
        },
    }
