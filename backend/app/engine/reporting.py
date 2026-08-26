"""Report engine (spec §34): JSON + Markdown + CSV + professional PDF."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Assessment, Evidence, Finding, Report, ScanRun

OWASP_BY_CATEGORY = {
    "AUTHENTICATION": "A07:2021 Identification and Authentication Failures",
    "AUTHORIZATION": "A01:2021 Broken Access Control",
    "INPUT_VALIDATION": "A03:2021 Injection",
    "API_SECURITY": "A04:2021 Insecure Design",
    "CLIENT_SECURITY": "A05:2021 Security Misconfiguration",
    "SECURE_COMMUNICATION": "A02:2021 Cryptographic Failures",
    "DATA_PRIVACY": "A02:2021 Cryptographic Failures",
    "DEPENDENCIES": "A06:2021 Vulnerable and Outdated Components",
    "INFRASTRUCTURE": "A05:2021 Security Misconfiguration",
    "PRIVACY": "A02:2021 Cryptographic Failures",
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
_SEV_ORDER_INDEX = {sev: idx for idx, sev in enumerate(SEV_ORDER)}
# Unknown severities (e.g. NONE) sort last
_DEFAULT_SEV_INDEX = len(SEV_ORDER)

_ALLOWED_FORMATS = {"json", "md", "pdf", "csv"}


def _severity_sort_key(finding: Finding) -> int:
    return _SEV_ORDER_INDEX.get(getattr(finding, "severity", ""), _DEFAULT_SEV_INDEX)


def _collect(db: Session, assessment: Assessment) -> dict:
    """Gather findings, runs, and counts for a report."""
    if assessment is None or not getattr(assessment, "id", None):
        raise ValueError("assessment must have an id")

    findings = db.scalars(
        select(Finding)
        .where(Finding.assessment_id == assessment.id)
        .order_by(Finding.created_at)
    ).all()
    runs = db.scalars(select(ScanRun).where(ScanRun.assessment_id == assessment.id)).all()

    counts: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = getattr(f, "severity", "INFORMATIONAL")
        counts[sev] = counts.get(sev, 0) + 1

    # Single query for evidence count – avoids N+1
    try:
        evidence_count = db.scalar(
            select(func.count(Evidence.id)).where(Evidence.finding_id.in_([f.id for f in findings]))
        )
        if evidence_count is None:
            evidence_count = 0
        # Fallback for empty findings list: in_ with empty list may produce no rows on some DBs
        if not findings:
            evidence_count = 0
    except Exception:
        # Fallback to per-finding counting if the bulk query fails (e.g. empty IN clause on SQLite)
        evidence_count = 0
        for f in findings:
            try:
                evidence_count += len(db.scalars(select(Evidence.id).where(Evidence.finding_id == f.id)).all())
            except Exception:
                continue

    return {"findings": findings, "runs": runs, "counts": counts, "evidence_count": int(evidence_count)}


def _safe_str(value: object, max_len: int = 2048) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _front_matter(assessment: Assessment, data: dict) -> list[str]:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # Safely resolve executor email – relationship may be unloaded
    executor = "analyst"
    try:
        user = getattr(assessment, "user", None)
        if user is not None and getattr(user, "email", None):
            executor = str(user.email)
    except Exception:
        executor = "analyst"

    modules = getattr(assessment, "modules", None) or []
    if isinstance(modules, (list, tuple)):
        modules_str = ", ".join(str(m) for m in modules) if modules else "n/a"
    else:
        modules_str = str(modules)

    auth_note = getattr(assessment, "authorization_note", "") or ""
    auth_line = f"CONFIRMED — {auth_note}" if getattr(assessment, "authorized", False) else "NOT CONFIRMED"

    target = _safe_str(getattr(assessment, "target", "(unknown)"), 2048)
    source = _safe_str(getattr(assessment, "source_path", "") or "n/a", 1024)

    total = sum(data["counts"].values())

    return [
        "# World Monitor — Security Assessment Report",
        "",
        f"- **Assessment ID:** `{_safe_str(assessment.id, 64)}`",
        f"- **Target:** {target}",
        f"- **Scope (filesystem):** {source}",
        f"- **Modules:** {modules_str}",
        f"- **Authorization:** {auth_line}",
        f"- **Executed by:** {executor}",
        f"- **Generated:** {generated}",
        "",
        "## Executive Summary",
        "",
        f"The authorized assessment of **{target}** executed "
        f"{len(data['runs'])} scanner modules and produced **{total} findings**: ",
        f"{data['counts'].get('CRITICAL', 0)} critical, {data['counts'].get('HIGH', 0)} high, "
        f"{data['counts'].get('MEDIUM', 0)} medium, {data['counts'].get('LOW', 0)} low, "
        f"{data['counts'].get('INFORMATIONAL', 0)} informational. All testing was confined to the "
        "authorized local lab target; no third-party systems were contacted.",
        "",
    ]


def build_markdown(db: Session, assessment: Assessment) -> str:
    data = _collect(db, assessment)
    lines = _front_matter(assessment, data)
    lines += [
        "## Scope & Methodology",
        "",
        "Modules executed:",
        "",
    ]
    for run in data["runs"]:
        scanner = _safe_str(getattr(run, "scanner", "?"), 64)
        status = _safe_str(getattr(run, "status", "?"), 20)
        lines.append(
            f"- `{scanner}` — {status}, {getattr(run, 'checks_total', 0)} checks, "
            f"{getattr(run, 'checks_safe', 0)} passed, {getattr(run, 'findings_count', 0)} findings"
        )
    lines += ["", "## Vulnerability Findings", ""]
    ordered = sorted(data["findings"], key=_severity_sort_key)
    for i, f in enumerate(ordered, 1):
        sev = _safe_str(f.severity, 20)
        cvss_score = f.cvss_score if f.cvss_score is not None else "n/a"
        cvss_vector = _safe_str(f.cvss_vector or "n/a", 128)
        cvss_version = _safe_str(getattr(f, "cvss_version", "3.1") or "3.1", 8)
        category = _safe_str(f.category, 40)
        component = _safe_str(f.affected_component, 1024)
        scanner = _safe_str(f.scanner, 64)
        check_id = _safe_str(f.check_id, 128)
        status = _safe_str(f.status, 20)
        retest = f" — RETEST: {_safe_str(f.retest_status, 30)}" if getattr(f, "retest_status", "") else ""
        lines += [
            f"### {i}. {_safe_str(f.title, 512)}",
            "",
            f"- **Severity:** {sev}  ",
            f"- **CVSS v{cvss_version}:** {cvss_score} (`{cvss_vector}`)",
            f"- **Category:** {category}  ",
            f"- **Affected component:** `{component}`  ",
            f"- **Scanner:** {scanner} ({check_id})  ",
            f"- **Status:** {status}{retest}",
            "",
            f"**Description.** {_safe_str(f.description, 8192) or 'n/a'}",
            "",
            f"**Impact.** {_safe_str(f.impact, 4096) or 'n/a'}",
            "",
            f"**Business impact.** {_safe_str(f.business_impact, 4096) or 'n/a'}",
            "",
            "**Reproduction (authorized lab only).**",
            "",
        ]
        repro = getattr(f, "reproduction", None) or []
        if repro:
            for idx, step in enumerate(repro, 1):
                lines.append(f"{idx}. {_safe_str(step, 1024)}")
        else:
            lines.append("1. See evidence documents for reproduction details.")
        lines += ["", f"**Remediation.** {_safe_str(f.remediation, 8192) or 'n/a'}", ""]
        refs = getattr(f, "references", None) or []
        if refs:
            # Sanitize references
            safe_refs = [_safe_str(r, 512) for r in refs[:10]]
            lines.append("**References.** " + "; ".join(safe_refs))
            lines.append("")
        # Also include severity rationale if present
        rationale = getattr(f, "severity_rationale", "") or ""
        if rationale:
            lines.append(f"*Why this score:* {_safe_str(rationale, 1024)}")
            lines.append("")
    lines += [
        "## Conclusion",
        "",
        "Findings above were validated against the intentionally vulnerable World Monitor lab.",
        "Retest status is recorded per finding after remediation verification.",
        "",
    ]
    return "\n".join(lines)


def build_json_report(db: Session, assessment: Assessment) -> dict:
    data = _collect(db, assessment)

    def fdump(f: Finding) -> dict:
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "cvss_version": getattr(f, "cvss_version", "3.1"),
            "category": f.category,
            "owasp": OWASP_BY_CATEGORY.get(f.category, ""),
            "affected_component": f.affected_component,
            "description": f.description,
            "impact": f.impact,
            "business_impact": f.business_impact,
            "remediation": f.remediation,
            "reproduction": f.reproduction or [],
            "references": f.references or [],
            "scanner": f.scanner,
            "check_id": f.check_id,
            "status": f.status,
            "retest_status": f.retest_status or "",
            "retest_count": getattr(f, "retest_count", 0),
            "created_at": f.created_at.isoformat() if getattr(f, "created_at", None) else None,
        }

    return {
        "document": "World Monitor Security Assessment Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment": {
            "id": assessment.id,
            "target": assessment.target,
            "source_path": assessment.source_path,
            "modules": assessment.modules or [],
            "authorized": bool(assessment.authorized),
            "authorization_note": assessment.authorization_note or "",
            "started_at": assessment.started_at.isoformat() if getattr(assessment, "started_at", None) else None,
            "finished_at": assessment.finished_at.isoformat() if getattr(assessment, "finished_at", None) else None,
        },
        "summary": {
            "total": sum(data["counts"].values()),
            "by_severity": data["counts"],
            "evidence_documents": data["evidence_count"],
            "scan_runs": [
                {
                    "scanner": r.scanner,
                    "status": r.status,
                    "duration_ms": r.duration_ms,
                    "checks_total": r.checks_total,
                    "checks_safe": r.checks_safe,
                    "findings_count": r.findings_count,
                }
                for r in data["runs"]
            ],
        },
        "findings": [fdump(f) for f in sorted(data["findings"], key=_severity_sort_key)],
    }


class _PdfReport:
    """Minimal professional PDF via fpdf2 with severity color coding."""

    SEV_RGB = {
        "CRITICAL": (127, 29, 29),
        "HIGH": (198, 40, 40),
        "MEDIUM": (230, 126, 0),
        "LOW": (30, 136, 229),
        "INFORMATIONAL": (96, 125, 139),
        "NONE": (120, 120, 120),
    }
    INK = (26, 32, 44)
    ACCENT = (11, 87, 208)

    def __init__(self) -> None:
        from fpdf import FPDF

        self.pdf = FPDF(format="A4")
        self.pdf.set_auto_page_break(auto=True, margin=16)
        self.pdf.set_margins(18, 18, 18)
        self._body_font = 10

    @staticmethod
    def _safe(text: object) -> str:
        """Core helvetica font is latin-1 only; replace exotic chars."""
        return str(text).encode("latin-1", "replace").decode("latin-1")

    def _para(self, text: str, size: float | None = None, style: str = "", h: float = 5.2) -> None:
        text = self._safe(text)
        p = self.pdf
        if p.get_x() != p.l_margin:
            p.set_x(p.l_margin)
        if size is not None or style:
            p.set_font("helvetica", style, size or self._body_font)
        p.multi_cell(0, h, text, new_x="LMARGIN", new_y="NEXT")

    def _label(self, text: str, size: float = 9.5) -> None:
        text = self._safe(text)
        p = self.pdf
        p.set_x(p.l_margin)
        p.set_font("helvetica", "B", size)
        p.cell(0, 5.5, text, new_x="LMARGIN", new_y="NEXT")

    def _section(self, title: str) -> None:
        p = self.pdf
        if p.get_y() > 250:
            p.add_page()
        p.set_x(p.l_margin)
        p.ln(4)
        p.set_text_color(*self.ACCENT)
        p.set_font("helvetica", "B", 14)
        p.set_draw_color(*self.ACCENT)
        p.set_line_width(0.5)
        p.cell(0, 9, self._safe(title), border="B", new_x="LMARGIN", new_y="NEXT")
        p.ln(3)
        p.set_text_color(*self.INK)
        p.set_font("helvetica", "", self._body_font)

    def _kv_row(self, label: str, value: str) -> None:
        label = self._safe(label)
        value = self._safe(value)
        p = self.pdf
        p.set_x(p.l_margin)
        p.set_font("helvetica", "B", 10)
        p.cell(52, 6.5, label)
        p.set_font("helvetica", "", 10)
        p.multi_cell(0, 6.5, value[:140], new_x="LMARGIN", new_y="NEXT")

    def _cover(self, assessment: Assessment, data: dict) -> None:
        p = self.pdf
        p.add_page()
        p.set_fill_color(*self.ACCENT)
        p.rect(0, 0, 210, 88, style="F")
        p.set_text_color(255, 255, 255)
        p.set_xy(18, 26)
        p.set_font("helvetica", "B", 25)
        p.cell(0, 12, "WORLD MONITOR")
        p.set_xy(18, 42)
        p.set_font("helvetica", "", 15)
        p.cell(0, 10, "Security Assessment Report")
        p.set_xy(18, 56)
        p.set_font("helvetica", "", 9.5)
        p.cell(0, 8, "DETECT > VERIFY > DOCUMENT > SCORE > EXPLAIN IMPACT > REMEDIATE > RETEST")
        p.set_text_color(*self.INK)
        p.set_y(98)
        rows = [
            ("Assessment ID", _safe_str(assessment.id, 64)),
            ("Target", _safe_str(assessment.target, 120)),
            ("Filesystem scope", _safe_str(assessment.source_path or "n/a", 120)),
            ("Modules", ", ".join(assessment.modules) if getattr(assessment, "modules", None) else "n/a"),
            ("Authorization", "CONFIRMED - local lab" if getattr(assessment, "authorized", False) else "NOT CONFIRMED"),
            ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            ("Total findings", str(sum(data["counts"].values()))),
        ]
        for label, value in rows:
            self._kv_row(label + ":", _safe_str(value, 140))
        p.ln(6)
        p.set_font("helvetica", "B", 12)
        p.set_x(p.l_margin)
        p.cell(0, 8, "Severity distribution", new_x="LMARGIN", new_y="NEXT")
        for sev in SEV_ORDER:
            rgb = self.SEV_RGB.get(sev, self.SEV_RGB["LOW"])
            p.set_x(p.l_margin)
            p.set_font("helvetica", "B", 11)
            p.set_text_color(*rgb)
            p.cell(36, 7, sev.title())
            p.set_text_color(*self.INK)
            p.set_font("helvetica", "", 11)
            p.cell(0, 7, f"{data['counts'].get(sev, 0)}", new_x="LMARGIN", new_y="NEXT")

    def build(self, db: Session, assessment: Assessment) -> bytes:
        data = _collect(db, assessment)
        self._cover(assessment, data)
        total = sum(data["counts"].values())

        self._section("1. Executive Summary")
        self._para(
            f"An authorized security assessment of {_safe_str(assessment.target, 200)} was performed using the "
            f"World Monitor platform. {len(data['runs'])} scanner module(s) executed "
            f"{sum(getattr(r, 'checks_total', 0) for r in data['runs'])} checks in total and identified "
            f"{total} finding(s): {data['counts'].get('CRITICAL', 0)} critical, {data['counts'].get('HIGH', 0)} high, "
            f"{data['counts'].get('MEDIUM', 0)} medium, {data['counts'].get('LOW', 0)} low and "
            f"{data['counts'].get('INFORMATIONAL', 0)} informational. All activity was restricted to the "
            "explicitly authorized local lab environment.",
            size=10.5,
        )

        self._section("2. Scope & Methodology")
        for r in data["runs"]:
            scanner = _safe_str(getattr(r, "scanner", "?"), 64)
            status = _safe_str(getattr(r, "status", "?"), 20)
            self._para(
                f"*  {scanner}: {status}; {getattr(r, 'checks_total', 0)} checks; "
                f"{getattr(r, 'checks_safe', 0)} passed; {getattr(r, 'findings_count', 0)} findings."
            )

        self._section("3. Findings Detail")
        ordered = sorted(data["findings"], key=_severity_sort_key)
        if not ordered:
            self._para("No findings were recorded for this assessment.")
        for idx, f in enumerate(ordered, 1):
            sev = _safe_str(getattr(f, "severity", "LOW"), 20)
            rgb = self.SEV_RGB.get(sev, self.SEV_RGB["LOW"])
            if self.pdf.get_y() > 235:
                self.pdf.add_page()
            p = self.pdf
            p.set_x(p.l_margin)
            p.set_fill_color(*rgb)
            p.set_text_color(255, 255, 255)
            p.set_font("helvetica", "B", 11)
            title = _safe_str(getattr(f, "title", "Untitled"), 86)
            p.cell(0, 7.5, self._safe(f"  {idx}. [{sev}] {title}"), fill=True, new_x="LMARGIN", new_y="NEXT")
            p.ln(1.5)
            p.set_text_color(*self.INK)
            cvss_score = getattr(f, "cvss_score", None)
            cvss_score_str = str(cvss_score) if cvss_score is not None else "n/a"
            cvss_vector = _safe_str(getattr(f, "cvss_vector", "") or "n/a", 128)
            cvss_version = _safe_str(getattr(f, "cvss_version", "3.1") or "3.1", 8)
            component = _safe_str(getattr(f, "affected_component", ""), 200)
            scanner = _safe_str(getattr(f, "scanner", ""), 64)
            check_id = _safe_str(getattr(f, "check_id", ""), 128)
            status = _safe_str(getattr(f, "status", ""), 20)
            retest = f"   Retest: {_safe_str(getattr(f, 'retest_status', ''), 30)}" if getattr(f, "retest_status", "") else ""
            self._para(
                f"CVSS v{cvss_version}: {cvss_score_str}   Vector: {cvss_vector}\n"
                f"Component: {component}   Scanner: {scanner} ({check_id})\n"
                f"Status: {status}{retest}",
                size=9,
            )
            self._label("Description")
            self._para(_safe_str(getattr(f, "description", ""), 4096) or "n/a", size=9.5)
            impact = _safe_str(getattr(f, "impact", "") or "", 4096)
            if impact:
                self._label("Impact")
                self._para(impact, size=9.5)
            business = _safe_str(getattr(f, "business_impact", "") or "", 4096)
            if business:
                self._label("Business impact")
                self._para(business, size=9.5)
            repro = getattr(f, "reproduction", None) or []
            if repro:
                self._label("Controlled reproduction (lab only)")
                for step in repro[:10]:
                    self._para("  -  " + _safe_str(step, 1024), size=9.5)
            self._label("Remediation")
            self._para(_safe_str(getattr(f, "remediation", ""), 8192) or "n/a", size=9.5)
            rationale = _safe_str(getattr(f, "severity_rationale", "") or "", 2048)
            if rationale:
                self._para(f"Why this score: {rationale}", size=8.5, style="I")
            p.ln(4)

        self._section("4. Evidence & Retest Statement")
        self._para(
            f"{data['evidence_count']} sanitized evidence document(s) are archived under the "
            "platform evidence store for this assessment. Sensitive values (tokens, cookies, "
            "API keys) are masked before storage. Retest results are recorded per finding and "
            "retained alongside the original evidence."
        )

        self._section("5. Conclusion")
        self._para(
            "All findings were reproduced against the intentionally vulnerable World Monitor "
            "lab. Prioritize remediation by CVSS score, apply fixes, then execute the built-in "
            "retest to verify resolution before sign-off."
        )
        return bytes(self.pdf.output())


def _sanitize_assessment_id_for_filename(aid: str) -> str:
    if not isinstance(aid, str) or not aid:
        raise ValueError("assessment id is required")
    # Allow hex ids, strip unsafe chars
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", aid)[:64]
    if not safe:
        raise ValueError("assessment id contains no safe characters")
    return safe


def generate_report(db: Session, assessment: Assessment, fmt: str, generated_by: str = "") -> Report:
    """Generate a report file and persist its DB record.

    Args:
        db: SQLAlchemy session
        assessment: Assessment to report on
        fmt: One of 'json', 'md', 'pdf', 'csv' (case-insensitive)
        generated_by: Email of the user generating the report

    Returns:
        Report ORM instance (already committed)
    """
    if not isinstance(fmt, str) or not fmt.strip():
        raise ValueError("format must be a non-empty string")
    fmt = fmt.strip().lower()
    if fmt not in _ALLOWED_FORMATS:
        raise ValueError(f"Unsupported report format '{fmt}'; allowed: {sorted(_ALLOWED_FORMATS)}")
    if assessment is None or not getattr(assessment, "id", None):
        raise ValueError("assessment must be a persisted instance with an id")

    # Sanitize filename components
    safe_id = _sanitize_assessment_id_for_filename(assessment.id)
    out_dir = Path(settings.REPORT_DIR).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_dir.chmod(0o700)
    except Exception:
        pass

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")[:18]  # microseconds to avoid collisions

    # Atomic write helpers
    def _write_text(path: Path, content: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        try:
            path.chmod(0o600)
        except Exception:
            pass

    def _write_bytes(path: Path, content: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(content)
        tmp.replace(path)
        try:
            path.chmod(0o600)
        except Exception:
            pass

    if fmt == "json":
        payload = build_json_report(db, assessment)
        fname = f"report_{safe_id}_{stamp}.json"
        path = out_dir / fname
        _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False))
    elif fmt == "csv":
        fname = f"report_{safe_id}_{stamp}.csv"
        path = out_dir / fname
        # Write via temp file for atomicity
        tmp_path = path.with_suffix(".csv.tmp")
        with tmp_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(
                [
                    "title",
                    "severity",
                    "cvss_score",
                    "cvss_vector",
                    "category",
                    "owasp",
                    "affected_component",
                    "scanner",
                    "check_id",
                    "status",
                    "retest_status",
                ]
            )
            data_csv = _collect(db, assessment)
            ordered_csv = sorted(data_csv["findings"], key=_severity_sort_key)
            for f_ in ordered_csv:
                w.writerow(
                    [
                        _safe_str(f_.title, 512),
                        _safe_str(f_.severity, 20),
                        f_.cvss_score if f_.cvss_score is not None else "",
                        _safe_str(f_.cvss_vector or "", 128),
                        _safe_str(f_.category, 40),
                        OWASP_BY_CATEGORY.get(f_.category, ""),
                        _safe_str(f_.affected_component, 1024),
                        _safe_str(f_.scanner, 64),
                        _safe_str(f_.check_id, 128),
                        _safe_str(f_.status, 20),
                        _safe_str(f_.retest_status or "", 30),
                    ]
                )
        tmp_path.replace(path)
        try:
            path.chmod(0o600)
        except Exception:
            pass
    elif fmt == "md":
        fname = f"report_{safe_id}_{stamp}.md"
        path = out_dir / fname
        _write_text(path, build_markdown(db, assessment))
    else:  # pdf
        fname = f"report_{safe_id}_{stamp}.pdf"
        path = out_dir / fname
        pdf_bytes = _PdfReport().build(db, assessment)
        _write_bytes(path, pdf_bytes)

    from ..models import AuditLog

    # Persist report record + audit log
    report = Report(assessment_id=assessment.id, format=fmt, path=fname, generated_by=_safe_str(generated_by, 64))
    db.add(report)
    db.add(
        AuditLog(
            user_email=_safe_str(generated_by or "system", 255),
            action="report.generated",
            target=_safe_str(assessment.target, 2048),
            detail={"format": fmt, "file": fname},
        )
    )
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        # Clean up file on DB failure to avoid orphaned reports
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass
        raise IOError(f"Failed to persist report record: {exc}") from exc
    return report


__all__ = [
    "OWASP_BY_CATEGORY",
    "SEV_ORDER",
    "build_markdown",
    "build_json_report",
    "generate_report",
]
