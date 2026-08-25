"""World Monitor unified CLI — drives the SAME engine as the web UI (spec §4/§37).

Examples:
  python cli/world_monitor.py status
  python cli/world_monitor.py scan --lab
  python cli/world_monitor.py scan --target http://127.0.0.1:8080 --module headers --module secrets
  python cli/world_monitor.py findings
  python cli/world_monitor.py report <assessment_id> --format pdf
  python cli/world_monitor.py retest <finding_id>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import typer  # noqa: E402
from sqlalchemy import select  # noqa: E402

from backend.app.config import settings  # noqa: E402
from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.engine.authorization_gate import AuthorizationError  # noqa: E402
from backend.app.engine.orchestration import (  # noqa: E402
    _run_assessment,
    create_assessment,
    retest_finding,
)
from backend.app.engine.reporting import generate_report  # noqa: E402
from backend.app.models import Assessment, Finding  # noqa: E402
from backend.app.main import _seed_users  # noqa: E402
from backend.app.scanners.registry import load_registry  # noqa: E402

app = typer.Typer(help="World Monitor Security Assessment Platform", no_args_is_help=True)
SEV_COLORS = {"CRITICAL": typer.colors.RED, "HIGH": typer.colors.RED,
              "MEDIUM": typer.colors.YELLOW, "LOW": typer.colors.CYAN}


@app.command()
def status() -> None:
    """Show platform configuration and toolchain readiness."""
    init_db()
    portia = (settings.BIN_DIR / "portia.exe").exists()
    bomber = (settings.BIN_DIR / "bomber.exe").exists()
    typer.echo(f"App           : {settings.APP_NAME} v{settings.VERSION}")
    typer.echo(f"LAB_MODE      : {settings.LAB_MODE}")
    typer.echo(f"Lab URL       : {settings.LAB_APP_URL}")
    typer.echo(f"Database      : {settings.DATABASE_URL}")
    typer.echo(f"portia binary : {'OK' if portia else 'MISSING (scripts/build_go_tools.ps1)'}")
    typer.echo(f"bomber binary : {'OK' if bomber else 'MISSING (scripts/build_go_tools.ps1)'}")


@app.command()
def scan(
    target: str = typer.Option("", help="Authorized http(s) target URL"),
    module: list[str] = typer.Option([], help="Module key (repeatable)"),
    all_modules: bool = typer.Option(False, "--all", help="Run every module"),
    lab: bool = typer.Option(False, "--lab", help="Shortcut: full assessment of the local lab"),
    source_path: str = typer.Option("", help="Filesystem scope for secrets/dependencies"),
    token: str = typer.Option("", help="Optional lab demo JWT for authenticated checks"),
    user: str = typer.Option("cli@worldmonitor.local", "--as-user"),
) -> None:
    """Create + run an assessment synchronously (same engine as the UI)."""
    init_db()
    load_registry()
    if lab:
        target = settings.LAB_APP_URL
        modules = ["authentication", "authorization", "api", "input_validation",
                   "headers", "tls", "secrets", "dependencies"]
        if not source_path:
            source_path = str(settings.LAB_SOURCE_DIR)
    elif all_modules:
        modules = ["authentication", "authorization", "api", "input_validation",
                   "headers", "tls", "secrets", "dependencies"]
    elif not module:
        typer.secho("Provide --module ... , --all or --lab", fg=typer.colors.RED)
        raise typer.Exit(2)
    else:
        modules = list(module)

    db = SessionLocal()
    try:
        try:
            assessment = create_assessment(
                db, user_email=user, target=target, modules=modules,
                authorized=True, source_path=source_path or None,
            )
        except AuthorizationError as exc:
            typer.secho(f"AUTHORIZATION GATE: {exc}", fg=typer.colors.RED)
            raise typer.Exit(3) from exc
        typer.echo(f"Assessment {assessment.id} created -> running ...")
        _run_assessment(assessment.id, auth_token=token or None)
        db.expire_all()
        fresh = db.get(Assessment, assessment.id)
        runs = fresh.scan_runs
        findings = db.scalars(select(Finding).where(Finding.assessment_id == assessment.id)).all()
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        typer.echo("")
        for r in runs:
            icon = {"completed": "[OK]", "failed": "[!!]", "skipped": "[--]"}.get(r.status, "[..]")
            typer.echo(f"  {icon} {r.scanner:<18} {r.status:<10} "
                       f"checks={r.checks_total:>3} safe={r.checks_safe:>3} findings={r.findings_count}")
        typer.echo("")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            if counts.get(sev):
                typer.secho(f"  {sev:<13} {counts[sev]}", fg=SEV_COLORS[sev])
        typer.echo(f"\nTotal findings: {len(findings)}")
        typer.echo(f"Next: world-monitor report {assessment.id} --format pdf")
    finally:
        db.close()


@app.command()
def findings(
    severity: str = typer.Option("", "--severity"),
    category: str = typer.Option("", "--category"),
) -> None:
    """List stored findings."""
    init_db()
    db = SessionLocal()
    try:
        q = select(Finding).order_by(Finding.created_at.desc()).limit(100)
        if severity:
            q = q.where(Finding.severity == severity.upper())
        if category:
            q = q.where(Finding.category == category.upper())
        rows = db.scalars(q).all()
        if not rows:
            typer.echo("No findings stored.")
            return
        for f in rows:
            color = SEV_COLORS.get(f.severity, typer.colors.WHITE)
            typer.secho(f"[{f.severity:^12}] {f.cvss_score if f.cvss_score is not None else ' -':>4}  "
                        f"{f.title[:76]}", fg=color)
            typer.echo(f"               id={f.id} scanner={f.scanner} status={f.status}"
                       + (f" retest={f.retest_status}" if f.retest_status else ""))
    finally:
        db.close()


@app.command()
def report(
    assessment_id: str,
    format: str = typer.Option("pdf", "--format"),
) -> None:
    """Generate PDF/JSON/Markdown report for an assessment."""
    init_db()
    db = SessionLocal()
    try:
        assessment = db.get(Assessment, assessment_id)
        if assessment is None:
            typer.secho("Assessment not found", fg=typer.colors.RED)
            raise typer.Exit(1)
        rep = generate_report(db, assessment, format.lower(), generated_by="cli")
        typer.echo(f"{format.upper()} report written: {settings.REPORT_DIR / rep.path}")
    finally:
        db.close()


@app.command()
def retest(finding_id: str) -> None:
    """Re-check a single finding after remediation."""
    init_db()
    load_registry()
    db = SessionLocal()
    try:
        result = retest_finding(db, finding_id, user_email="cli@worldmonitor.local")
        color = typer.colors.GREEN if result["retest_status"] == "FIXED" else typer.colors.RED
        typer.secho(json.dumps(result, indent=2), fg=color)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(1) from exc
    finally:
        db.close()


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the web platform (UI + API)."""
    init_db()
    import uvicorn

    from backend.main import app as fastapi_app

    uvicorn.run(fastapi_app, host=host, port=port)


if __name__ == "__main__":
    _seed_users()
    app()
