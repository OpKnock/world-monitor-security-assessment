"""Destructive operations: delete assessments / findings / reports with cascade.

Deletes remove DB rows, evidence/report FILES, and any audit-log rows that
reference the deleted identifiers (per product requirement: deletion leaves
no orphaned traces). Each operation itself writes one 'x.deleted' audit row.
"""
import json
import shutil

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Assessment, AuditLog, Evidence, Finding, Report, ScanRun
from .deps import require_role

router = APIRouter(tags=["delete"])


def _purge_audit_refs(db: Session, needle_ids: list[str]) -> int:
    """Remove audit rows whose payload references any deleted identifier."""
    removed = 0
    rows = db.scalars(select(AuditLog)).all()
    needles = [n for n in needle_ids if n]
    for row in rows:
        blob = json.dumps({"t": row.target, "d": row.detail})
        if any(n in blob for n in needles):
            db.delete(row)
            removed += 1
    return removed


@router.delete("/assessments/{assessment_id}")
def delete_assessment(assessment_id: str, db: Session = Depends(get_db),
                      user=Depends(require_role("analyst"))):
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(404, detail="assessment not found")

    # filesystem cleanup: evidence folder + report files
    ev_dir = settings.EVIDENCE_DIR / assessment_id
    if ev_dir.exists():
        shutil.rmtree(ev_dir, ignore_errors=True)
    reports = db.scalars(select(Report).where(
        Report.assessment_id == assessment_id)).all()
    for rep in reports:
        f = settings.REPORT_DIR / rep.path
        f.unlink(missing_ok=True)

    ref_ids = [assessment_id] + [
        f.id for f in db.scalars(select(Finding).where(
            Finding.assessment_id == assessment_id)).all()]
    ref_ids += [r.id for r in reports]

    db.delete(a)          # ORM cascades scan_runs / findings / evidence / reports
    purged = _purge_audit_refs(db, ref_ids)
    db.add(AuditLog(user_email=user.email, action="assessment.deleted",
                    target=a.target,
                    detail={"assessment_id": assessment_id, "audit_rows_purged": purged}))
    db.commit()
    return {"deleted": assessment_id, "reports_removed": len(reports),
            "audit_rows_purged": purged}


@router.delete("/assessments")
def delete_all_assessments(db: Session = Depends(get_db),
                           user=Depends(require_role("admin"))):
    # Fresh start: delete ALL assessments, findings, evidence, reports, and audit refs (admin only)
    all_assessments = db.scalars(select(Assessment)).all()
    if not all_assessments:
        return {"deleted": 0, "message": "no assessments to delete"}
    count = len(all_assessments)
    if settings.EVIDENCE_DIR.exists():
        shutil.rmtree(settings.EVIDENCE_DIR, ignore_errors=True)
        settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if settings.REPORT_DIR.exists():
        shutil.rmtree(settings.REPORT_DIR, ignore_errors=True)
        settings.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for a in all_assessments:
        db.delete(a)
    db.query(AuditLog).delete()
    db.add(AuditLog(user_email=user.email, action="assessments.bulk_deleted",
                    target="*",
                    detail={"deleted_assessments": count}))
    db.commit()
    return {"deleted": count, "message": f"deleted {count} assessments - fresh start"}


@router.delete("/findings/{finding_id}")
def delete_finding(finding_id: str, db: Session = Depends(get_db),
                   user=Depends(require_role("analyst"))):
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, detail="finding not found")
    aid = f.assessment_id

    # remove evidence files tied to this finding
    for ev in db.scalars(select(Evidence).where(Evidence.finding_id == finding_id)):
        p = settings.EVIDENCE_DIR / ev.path
        if ev.path and p.exists():
            try:
                p.unlink()
            except OSError:
                pass

    title = f.title
    db.delete(f)
    purged = _purge_audit_refs(db, [finding_id])
    db.add(AuditLog(user_email=user.email, action="finding.deleted",
                    target=f.target,
                    detail={"finding_id": finding_id, "title": title[:120],
                            "audit_rows_purged": purged}))
    db.commit()
    return {"deleted": finding_id}


@router.delete("/reports/{report_id}")
def delete_report(report_id: str, db: Session = Depends(get_db),
                  user=Depends(require_role("analyst"))):
    rep = db.get(Report, report_id)
    if rep is None:
        raise HTTPException(404, detail="report not found")
    from pathlib import Path

    fp = Path(rep.path).name
    target_file = settings.REPORT_DIR / fp
    if target_file.exists():
        target_file.unlink()
    db.delete(rep)
    purged = _purge_audit_refs(db, [report_id])
    db.add(AuditLog(user_email=user.email, action="report.deleted",
                    target=fp, detail={"report_id": report_id}))
    db.commit()
    return {"deleted": report_id}
