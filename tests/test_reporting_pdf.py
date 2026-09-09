"""PDF report reads like a real report: verdict banner, footers, OWASP, gate section."""
import re
import zlib

from backend.app.db import SessionLocal
from backend.app.engine.reporting import _PdfReport
from backend.app.models import Assessment, Finding, User
from backend.app.security import hash_password


def _seed():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "pdf@example.com").one_or_none()
    if user is None:
        user = User(email="pdf@example.com",
                    password_hash=hash_password("Pdf_Pass_1234"), role="analyst")
        db.add(user)
        db.commit()
    a = Assessment(user_id=user.id, target="http://127.0.0.1/pdf-probe",
                   modules=["headers"], status="completed", authorized=True)
    db.add(a)
    db.commit()
    if not db.query(Finding).filter(Finding.assessment_id == a.id).first():
        db.add(Finding(assessment_id=a.id, title="Broken Object Level Authorization",
                       severity="CRITICAL", category="AUTHORIZATION", scanner="authorization",
                       check_id="IDOR-1", fingerprint=f"fp-pdf-crit-{a.id}",
                       cvss_score=9.1, description="d", impact="i",
                       business_impact="b", remediation="fix it"))
        db.add(Finding(assessment_id=a.id, title="Missing Content-Security-Policy",
                       severity="HIGH", category="CLIENT_SECURITY", scanner="headers",
                       check_id="HDR-CSP", fingerprint=f"fp-pdf-high-{a.id}",
                       cvss_score=6.1, description="d", impact="i",
                       business_impact="b", remediation="fix it"))
        db.commit()
    aid = a.id
    db.close()
    return aid


def _pdf_text(blob: bytes) -> str:
    """Concatenate raw + Flate-decoded page streams (fpdf2 compresses output)."""
    parts = [blob.decode("latin-1", "replace")]
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", blob, re.DOTALL):
        try:
            parts.append(zlib.decompress(m.group(1).strip()).decode("latin-1", "replace"))
        except Exception:
            continue
    return "\n".join(parts)


def test_pdf_has_verdict_banner_footer_and_owasp(client):
    db = SessionLocal()
    try:
        aid = _seed()
        a = db.get(Assessment, aid)
        blob = _PdfReport(doc_label=aid[:8]).build(db, a)
    finally:
        db.close()
    assert blob[:4] == b"%PDF"
    text = _pdf_text(blob)
    assert "RELEASE DECISION: BLOCKED" in text
    assert "Confidential" in text  # footer on every page
    assert "Page " in text
    assert "OWASP" in text
    assert "2. Release Decision" in text
    assert "4. Findings Detail" in text
    for sev in ("Critical", "High", "Medium", "Low"):
        assert sev in text
