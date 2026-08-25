"""Report engine (spec §34): JSON + Markdown + professional PDF."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Assessment, Evidence, Finding, Report, ScanRun

OWASP_BY_CATEGORY = {
    'AUTHENTICATION': 'A07:2021 Identification and Authentication Failures',
    'AUTHORIZATION': 'A01:2021 Broken Access Control',
    'INPUT_VALIDATION': 'A03:2021 Injection',
    'API_SECURITY': 'A04:2021 Insecure Design',
    'CLIENT_SECURITY': 'A05:2021 Security Misconfiguration',
    'SECURE_COMMUNICATION': 'A02:2021 Cryptographic Failures',
    'DATA_PRIVACY': 'A02:2021 Cryptographic Failures',
    'DEPENDENCIES': 'A06:2021 Vulnerable and Outdated Components',
    'INFRASTRUCTURE': 'A05:2021 Security Misconfiguration',
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _collect(db: Session, assessment: Assessment) -> dict:
    findings = db.scalars(
        select(Finding).where(Finding.assessment_id == assessment.id)
        .order_by(Finding.created_at)).all()
    runs = db.scalars(select(ScanRun).where(ScanRun.assessment_id == assessment.id)).all()
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    evidence_count = 0
    for f in findings:
        evidence_count += len(
            db.scalars(select(Evidence.id).where(Evidence.finding_id == f.id)).all())
    return {"findings": findings, "runs": runs, "counts": counts,
            "evidence_count": evidence_count}


def _front_matter(assessment: Assessment, data: dict) -> list[str]:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return [
        "# World Monitor — Security Assessment Report",
        "",
        f"- **Assessment ID:** `{assessment.id}`",
        f"- **Target:** {assessment.target}",
        f"- **Scope (filesystem):** {assessment.source_path or 'n/a'}",
        f"- **Modules:** {', '.join(assessment.modules)}",
        f"- **Authorization:** {'CONFIRMED — ' + assessment.authorization_note if assessment.authorized else 'NOT CONFIRMED'}",
        f"- **Executed by:** {getattr(assessment.user, 'email', 'analyst')}",
        f"- **Generated:** {generated}",
        "",
        "## Executive Summary",
        "",
        f"The authorized assessment of **{assessment.target}** executed "
        f"{len(data['runs'])} scanner modules and produced **{sum(data['counts'].values())} findings**: ",
        f"{data['counts']['CRITICAL']} critical, {data['counts']['HIGH']} high, "
        f"{data['counts']['MEDIUM']} medium, {data['counts']['LOW']} low, "
        f"{data['counts']['INFORMATIONAL']} informational. All testing was confined to the "
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
        lines.append(f"- `{run.scanner}` — {run.status}, {run.checks_total} checks, "
                     f"{run.checks_safe} passed, {run.findings_count} findings")
    lines += ["", "## Vulnerability Findings", ""]
    for i, f in enumerate(sorted(data["findings"], key=lambda x: -SEV_ORDER.index(x.severity)), 1):
        lines += [
            f"### {i}. {f.title}",
            "",
            f"- **Severity:** {f.severity}  ",
            f"- **CVSS v{f.cvss_version}:** {f.cvss_score} (`{f.cvss_vector}`)",
            f"- **Category:** {f.category}  ",
            f"- **Affected component:** `{f.affected_component}`  ",
            f"- **Scanner:** {f.scanner} ({f.check_id})  ",
            f"- **Status:** {f.status}" +
            (f" — RETEST: {f.retest_status}" if f.retest_status else ""),
            "",
            f"**Description.** {f.description}",
            "",
            f"**Impact.** {f.impact}",
            "",
            f"**Business impact.** {f.business_impact}",
            "",
            "**Reproduction (authorized lab only).**",
            "",
        ]
        for step in f.reproduction:
            lines.append(f"1. {step}")
        lines += ["", f"**Remediation.** {f.remediation}", ""]
        if f.references:
            lines.append("**References.** " + "; ".join(f.references))
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
            "id": f.id, "title": f.title, "severity": f.severity,
            "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
            "category": f.category,
            "owasp": OWASP_BY_CATEGORY.get(f.category, ""),
            "affected_component": f.affected_component,
            "description": f.description, "impact": f.impact,
            "business_impact": f.business_impact, "remediation": f.remediation,
            "reproduction": f.reproduction, "references": f.references,
            "scanner": f.scanner, "check_id": f.check_id, "status": f.status,
            "retest_status": f.retest_status, "created_at": f.created_at.isoformat(),
        }

    return {
        "document": "World Monitor Security Assessment Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment": {
            "id": assessment.id, "target": assessment.target,
            "source_path": assessment.source_path, "modules": assessment.modules,
            "authorized": assessment.authorized, "authorization_note": assessment.authorization_note,
            "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
            "finished_at": assessment.finished_at.isoformat() if assessment.finished_at else None,
        },
        "summary": {
            "total": sum(data["counts"].values()),
            "by_severity": data["counts"],
            "evidence_documents": data["evidence_count"],
            "scan_runs": [{
                "scanner": r.scanner, "status": r.status, "duration_ms": r.duration_ms,
                "checks_total": r.checks_total, "checks_safe": r.checks_safe,
                "findings_count": r.findings_count} for r in data["runs"]],
        },
        "findings": [fdump(f) for f in data["findings"]],
    }



class _PdfReport:
    """Minimal professional PDF via fpdf2 with severity color coding."""

    SEV_RGB = {
        "CRITICAL": (127, 29, 29), "HIGH": (198, 40, 40),
        "MEDIUM": (230, 126, 0), "LOW": (30, 136, 229),
        "INFORMATIONAL": (96, 125, 139),
    }
    INK = (26, 32, 44)
    ACCENT = (11, 87, 208)

    def __init__(self):
        from fpdf import FPDF

        self.pdf = FPDF(format="A4")
        self.pdf.set_auto_page_break(auto=True, margin=16)
        self.pdf.set_margins(18, 18, 18)
        self._body_font = 10

    # ---- low-level helpers (all writes go through these) ----
    @staticmethod
    def _safe(text) -> str:
        '''Core helvetica font is latin-1 only; replace exotic chars.'''
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    def _para(self, text: str, size: float | None = None, style: str = "",
              h: float = 5.2) -> None:
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
            ("Assessment ID", assessment.id),
            ("Target", assessment.target),
            ("Filesystem scope", assessment.source_path or "n/a"),
            ("Modules", ", ".join(assessment.modules)),
            ("Authorization",
             "CONFIRMED - local lab" if assessment.authorized else "NOT CONFIRMED"),
            ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            ("Total findings", str(sum(data["counts"].values()))),
        ]
        for label, value in rows:
            self._kv_row(label + ":", value)
        p.ln(6)
        p.set_font("helvetica", "B", 12)
        p.set_x(p.l_margin)
        p.cell(0, 8, "Severity distribution", new_x="LMARGIN", new_y="NEXT")
        for sev in SEV_ORDER:
            p.set_x(p.l_margin)
            p.set_font("helvetica", "B", 11)
            p.set_text_color(*self.SEV_RGB[sev])
            p.cell(36, 7, sev.title())
            p.set_text_color(*self.INK)
            p.set_font("helvetica", "", 11)
            p.cell(0, 7, f"{data['counts'][sev]}", new_x="LMARGIN", new_y="NEXT")

    # ---- document assembly ----
    def build(self, db: Session, assessment: Assessment) -> bytes:
        data = _collect(db, assessment)
        self._cover(assessment, data)
        total = sum(data["counts"].values())

        self._section("1. Executive Summary")
        self._para(
            f"An authorized security assessment of {assessment.target} was performed using the "
            f"World Monitor platform. {len(data['runs'])} scanner module(s) executed "
            f"{sum(r.checks_total for r in data['runs'])} checks in total and identified "
            f"{total} finding(s): {data['counts']['CRITICAL']} critical, {data['counts']['HIGH']} high, "
            f"{data['counts']['MEDIUM']} medium, {data['counts']['LOW']} low and "
            f"{data['counts']['INFORMATIONAL']} informational. All activity was restricted to the "
            "explicitly authorized local lab environment.", size=10.5)

        self._section("2. Scope & Methodology")
        for r in data["runs"]:
            self._para(f"*  {r.scanner}: {r.status}; {r.checks_total} checks; "
                       f"{r.checks_safe} passed; {r.findings_count} findings.")

        self._section("3. Findings Detail")
        ordered = sorted(data["findings"], key=lambda x: -SEV_ORDER.index(x.severity))
        if not ordered:
            self._para("No findings were recorded for this assessment.")
        for idx, f in enumerate(ordered, 1):
            rgb = self.SEV_RGB[f.severity]
            if self.pdf.get_y() > 235:
                self.pdf.add_page()
            p = self.pdf
            p.set_x(p.l_margin)
            p.set_fill_color(*rgb)
            p.set_text_color(255, 255, 255)
            p.set_font("helvetica", "B", 11)
            p.cell(0, 7.5, self._safe(f"  {idx}. [{f.severity}] {f.title[:86]}"),
                   fill=True, new_x="LMARGIN", new_y="NEXT")
            p.ln(1.5)
            p.set_text_color(*self.INK)
            self._para(
                f"CVSS v{f.cvss_version}: {f.cvss_score}   Vector: {f.cvss_vector}\n"
                f"Component: {f.affected_component}   Scanner: {f.scanner} ({f.check_id})\n"
                f"Status: {f.status}"
                + (f"   Retest: {f.retest_status}" if f.retest_status else ""),
                size=9)
            self._label("Description")
            self._para(f.description, size=9.5)
            if f.impact:
                self._label("Impact")
                self._para(f.impact, size=9.5)
            if f.business_impact:
                self._label("Business impact")
                self._para(f.business_impact, size=9.5)
            if f.reproduction:
                self._label("Controlled reproduction (lab only)")
                for step in f.reproduction:
                    self._para("  -  " + step, size=9.5)
            self._label("Remediation")
            self._para(f.remediation, size=9.5)
            if f.severity_rationale:
                self._para(f"Why this score: {f.severity_rationale}", size=8.5, style="I")
            p.ln(4)

        self._section("4. Evidence & Retest Statement")
        self._para(
            f"{data['evidence_count']} sanitized evidence document(s) are archived under the "
            "platform evidence store for this assessment. Sensitive values (tokens, cookies, "
            "API keys) are masked before storage. Retest results are recorded per finding and "
            "retained alongside the original evidence.")

        self._section("5. Conclusion")
        self._para(
            "All findings were reproduced against the intentionally vulnerable World Monitor "
            "lab. Prioritize remediation by CVSS score, apply fixes, then execute the built-in "
            "retest to verify resolution before sign-off.")
        return bytes(self.pdf.output())


def generate_report(db: Session, assessment: Assessment, fmt: str,
                    generated_by: str = "") -> Report:
    out_dir = Path(settings.REPORT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        payload = build_json_report(db, assessment)
        fname = f"report_{assessment.id}_{stamp}.json"
        path = out_dir / fname
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "csv":
        import csv as _csv

        fname = f"report_{assessment.id}_{stamp}.csv"
        path = out_dir / fname
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["title", "severity", "cvss_score", "cvss_vector",
                        "category", "owasp", "affected_component",
                        "scanner", "check_id", "status", "retest_status"])
            data_csv = _collect(db, assessment)
            ordered_csv = sorted(data_csv["findings"],
                                 key=lambda x: -SEV_ORDER.index(x.severity))
            for f_ in ordered_csv:
                w.writerow([f_.title, f_.severity, f_.cvss_score, f_.cvss_vector,
                            f_.category, OWASP_BY_CATEGORY.get(f_.category, ""),
                            f_.affected_component, f_.scanner, f_.check_id,
                            f_.status, f_.retest_status])
    elif fmt == "md":
        fname = f"report_{assessment.id}_{stamp}.md"
        path = out_dir / fname
        path.write_text(build_markdown(db, assessment), encoding="utf-8")
    else:
        fname = f"report_{assessment.id}_{stamp}.pdf"
        path = out_dir / fname
        pdf_bytes = _PdfReport().build(db, assessment)
        path.write_bytes(pdf_bytes)
    from ..models import AuditLog

    report = Report(assessment_id=assessment.id, format=fmt, path=fname,
                    generated_by=generated_by)
    db.add(report)
    db.add(AuditLog(user_email=generated_by or "system", action="report.generated",
                    target=assessment.target, detail={"format": fmt, "file": fname}))
    db.commit()
    return report