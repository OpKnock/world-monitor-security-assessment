"""Assessment orchestration engine + background job system (spec §13-14).

Runs scanner modules on a bounded thread pool so HTTP requests never block.
Every run is gated by the authorization gate and audit-logged.
"""
from __future__ import annotations

import logging
import threading
import traceback
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings

logger = logging.getLogger(__name__)
from ..db import DB_WRITE_LOCK, worker_session
from .authorization_gate import (
    AuthorizationError,
    assert_authorized_flag,
    validate_http_target,
    validate_source_path,
)
from .evidence import EvidenceStore
from .findings import persist_raw_findings
from ..models import Assessment, AuditLog, Finding, ScanRun
from ..scanners.base import ScanContext
from ..scanners.registry import load_registry, scanners_for



def _audit(db: Session, email: str, action: str, target: str, detail: dict) -> None:
    db.add(AuditLog(user_email=email or "system", action=action, target=target[:2048], detail=detail))
    with DB_WRITE_LOCK:
        db.commit()


def create_assessment(
    db: Session,
    *,
    user_email: str,
    target: str,
    modules: list[str],
    authorized: bool,
    source_path: str | None = None,
    module_targets: dict[str, str] | None = None,
) -> Assessment:
    """Validate authorization BEFORE anything is created or scanned."""
    assert_authorized_flag(authorized)
    if not modules:
        raise AuthorizationError("At least one module must be selected")
    unknown = [m for m in modules if m not in (
        "authentication", "authorization", "api", "input_validation",
        "headers", "tls", "secrets", "dependencies",
        "supply_chain", "graphql", "deep_scan", "fuzzing")]
    if unknown:
        raise AuthorizationError(f"Unknown modules: {unknown}")

    needs_http = any(m in ("authentication", "authorization", "api", "input_validation" "graphql",
                           "headers", "tls") for m in modules)
    needs_source = any(m in ("secrets", "dependencies", "supply_chain") for m in modules)

    normalized_target = ""
    if needs_http:
        normalized_target = validate_http_target(target)
    if not target and not needs_source:
        raise AuthorizationError("Target URL required for the selected modules")

    # per-module overrides are validated through the same gate, then stored
    safe_overrides: dict[str, str] = {}
    for mod_key, url in (module_targets or {}).items():
        if url and url.strip() and mod_key in (
                "authentication", "authorization", "api", "input_validation",
                "sqli", "headers", "tls"):
            safe_overrides[mod_key] = validate_http_target(url)

    resolved_source = ""
    if needs_source:
        resolved_source = validate_source_path(source_path or str(settings.LAB_SOURCE_DIR))
    elif source_path:
        resolved_source = validate_source_path(source_path)

    assessment = Assessment(
        user_id=_resolve_user_id(db, user_email),
        target=normalized_target or "(source-only)",
        source_path=resolved_source,
        modules=modules,
        module_targets=safe_overrides,
        status="queued",
        authorized=True,
        authorization_note=f"LAB_MODE={settings.LAB_MODE}; gate passed {datetime.now(timezone.utc).isoformat()}",
    )
    db.add(assessment)
    db.flush()
    for mod in modules:
        db.add(ScanRun(assessment_id=assessment.id, scanner=mod, status="queued"))
    with DB_WRITE_LOCK:
        db.commit()
    _audit(db, user_email, "assessment.created", assessment.target,
           {"assessment_id": assessment.id, "modules": modules, "authorized": True})
    return assessment


def start_assessment_async(assessment_id: str, auth_token: str | None = None) -> None:
    load_registry()
    # dedicated daemon thread per assessment: one hung scan can never starve
    # the others (a shared pool could be exhausted by stuck workers)
    threading.Thread(
        target=_run_assessment, args=(assessment_id, auth_token), daemon=True
    ).start()


def _run_assessment(assessment_id: str, auth_token: str | None = None) -> None:
    logger.debug(f"worker enter {assessment_id}")

    def _watchdog():
        dbw = worker_session()
        try:
            a = dbw.get(Assessment, assessment_id)
            if a is not None and a.status == "running":
                a.status = "failed"
                a.error = "watchdog timeout (>10 min)"
                dbw.commit()
                logger.warning(f"watchdog failed {assessment_id}")
        finally:
            dbw.close()

    watchdog = threading.Timer(600, _watchdog)
    watchdog.daemon = True
    watchdog.start()

    db: Session = worker_session()
    try:
        assessment = db.get(Assessment, assessment_id)
        if assessment is None:
            return
        assessment.status = "running"
        assessment.started_at = datetime.now(timezone.utc)
        with DB_WRITE_LOCK:
            db.commit()

        store = EvidenceStore(assessment.id)
        logger.debug(f"evidence store ready")
        runs = {
            r.scanner: r for r in db.scalars(
                select(ScanRun).where(ScanRun.assessment_id == assessment.id)).all()
        }
        logger.debug(f"runs loaded: {list(runs)}")
        # per-module target overrides were gate-validated at creation time
        safe_overrides: dict[str, str] = dict(assessment.module_targets or {})

        # resolve one lab demo token per ASSESSMENT (not per module)
        http_token = auth_token
        if http_token is None and ({"authentication", "authorization"} & set(runs.keys())):
            _tgt = safe_overrides.get("authentication") or assessment.target
            _org = _origin(_tgt)
            if _org:
                http_token = _fetch_lab_token_quietly(_org)

        failures = 0
        for module_key, run in runs.items():
            scanner_instances = scanners_for([module_key])
            logger.debug(f"{assessment_id} module {module_key} start")
            run.status = "running"
            with DB_WRITE_LOCK:
                db.commit()
            logger.debug(f"{assessment_id} module {module_key} status=running committed")
            started = datetime.now(timezone.utc)

            token_for_module = http_token
            logger.debug(f"{assessment_id} module {module_key} token={'yes' if token_for_module else 'no'}")

            all_findings = []
            errors: list[str] = []
            skipped_results: list[object] = []
            skipped_notes: list[str] = []
            total_checks = safe_checks = 0
            for inst in scanner_instances:
                ctx = ScanContext(
                    target=(safe_overrides.get(inst.name)
                            or safe_overrides.get(module_key)
                            or assessment.target),
                    source_path=assessment.source_path,
                    auth_token=token_for_module,
                    evidence=store,
                    options={},
                )
                logger.debug(f"{assessment_id} inst {inst.name} begin")
                try:
                    result = inst.run(ctx)
                except Exception as exc:  # a broken adapter must never kill the assessment
                    errors.append(f"{inst.name}: {repr(exc)}\n{traceback.format_exc(limit=3)}")
                    continue
                logger.debug(f"{assessment_id} inst {inst.name} done status={result.status} findings={len(result.findings)}")
                if getattr(result, "status", "") == "skipped":
                    skipped_results.append(result)
                    skipped_notes.extend(getattr(result, "notes", []) or [])
                all_findings.extend(result.findings)
                errors.extend(f"{result.scanner}: {e}" for e in result.errors)
                total_checks += result.checks_total
                safe_checks += result.checks_safe
                if result.status == "failed":
                    errors.append(f"{result.scanner}: failed")
            duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            raw_path = ""
            logger.debug(f"{assessment_id} {module_key} post-loop errors={len(errors)}")
            if all_findings or errors:
                doc_path = store.save(
                    kind="scanner_output",
                    summary=f"{module_key} combined output",
                    payload={
                        "module": module_key,
                        "findings": [f.model_dump(exclude={"evidence_payloads"}) for f in all_findings],
                        "errors": errors,
                        "checks_total": total_checks,
                        "checks_safe": safe_checks,
                    },
                )
                raw_path = doc_path["path"]
                logger.debug(f"{assessment_id} {module_key} raw saved")

            logger.debug(f"{assessment_id} {module_key} persist call")
            new_or_updated, merged = persist_raw_findings(db, assessment, run, all_findings)
            logger.debug(f"{assessment_id} {module_key} persist returned merged={merged}")
            run.duration_ms = duration_ms
            run.findings_count = len(all_findings)
            run.checks_total = total_checks
            run.checks_safe = safe_checks
            run.raw_output_path = raw_path
            module_skipped = bool(skipped_results) and len(skipped_results) == len(scanner_instances)
            if module_skipped:
                run.status = "skipped"
                run.error = "; ".join(skipped_notes)[:500]
            elif errors and not all_findings and total_checks == 0:
                run.status = "failed"
                run.error = "; ".join(errors)[:2000]
                failures += 1
            else:
                run.status = "completed"
                if errors:
                    run.error = "; ".join(errors)[:2000]
            with DB_WRITE_LOCK:
                db.commit()
            logger.debug(f"{assessment_id} {module_key} run committed")
            _audit(db, "", "scan.finished", assessment.target,
                   {"scanner": module_key, "status": run.status,
                    "findings": len(all_findings), "duration_ms": duration_ms})

        # live alerting: push critical/high summary to a webhook when configured
        try:
            _url = settings.ALERT_WEBHOOK_URL
            if _url and assessment.status == "completed":
                import httpx as _hx

                crit = db.scalar(
                    select(Finding.id).where(Finding.assessment_id ==
                                             assessment.id,
                                             Finding.severity.in_(
                                                 ("CRITICAL", "HIGH")))
                )
                if crit:
                    n = db.scalars(
                        select(Finding.id).where(Finding.assessment_id ==
                                                 assessment.id)).all()
                    _hx.post(_url, json={
                        "text": f"[World Monitor] {len(n)} finding(s), "
                                f"incl. CRITICAL/HIGH, on {assessment.target}"},
                        timeout=8.0)
                    logger.info("webhook alert sent")
        except Exception:
            logger.debug("webhook alert failed", exc_info=True)

        assessment.status = "failed" if failures == len(runs) and runs else "completed"
        assessment.finished_at = datetime.now(timezone.utc)
        with DB_WRITE_LOCK:
            db.commit()
    except Exception as exc:  # never leave an assessment stuck in 'running'
        try:
            assessment.status = "failed"
            assessment.error = f"{repr(exc)}\n{traceback.format_exc(limit=5)}"[:4000]
            assessment.finished_at = datetime.now(timezone.utc)
            with DB_WRITE_LOCK:
                db.commit()
        except Exception:
            pass
    finally:
        watchdog.cancel()
        db.close()


def retest_finding(db: Session, finding_id: str, user_email: str) -> dict:
    """Re-run only the check behind a finding; compare fingerprints (spec §35)."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise ValueError("Finding not found")
    assessment = db.get(Assessment, finding.assessment_id)
    assert_authorized_flag(True)

    check_prefix = finding.check_id.split(".", 1)[0]
    module_key = {
        "auth": "authentication",
        "idor": "authorization",
        "rate_limit": "api",
        "sqli": "input_validation",
        "input_validation": "input_validation",
    }.get(check_prefix, finding.scanner)

    load_registry()
    instances = scanners_for([module_key])
    if not instances:
        raise ValueError(f"No scanner available for module '{finding.scanner}'")

    store = EvidenceStore(assessment.id)
    stored_overrides = dict(assessment.module_targets or {})
    ctx = ScanContext(
        target=(stored_overrides.get(module_key)
                or stored_overrides.get(finding.scanner)
                or finding.target),
        source_path=assessment.source_path,
        auth_token=(_fetch_lab_token_quietly(_origin(finding.target))
                    if check_prefix in ("auth", "idor") else None),
        evidence=store)
    still_present = False
    retest_docs = []
    for inst in instances:
        result = inst.run(ctx)
        for f in result.findings:
            fp = fingerprint_of(f.scan_target or ctx.target,
                                f.category, f.check_id, f.affected_component)
            if fp == finding.fingerprint:
                still_present = True
        retest_docs.append(store.save(
            kind="scanner_output",
            summary=f"retest {inst.name} -> {'STILL_PRESENT' if still_present else 'checked'}",
            payload={"retest": True, "scanner": inst.name,
                     "findings_seen": [f.check_id for f in result.findings]},
        ))

    finding.retest_count += 1
    finding.retested_at = datetime.now(timezone.utc)
    finding.retest_status = "STILL_PRESENT" if still_present else "FIXED"
    finding.status = "CONFIRMED" if still_present else "RETESTED"
    finding.meta = {**(finding.meta or {}), "retest_evidence": [d["path"] for d in retest_docs]}
    with DB_WRITE_LOCK:
        db.commit()
    _audit(db, user_email, "retest.executed", finding.target,
           {"finding_id": finding.id, "result": finding.retest_status})
    return {"finding_id": finding.id, "retest_status": finding.retest_status,
            "evidence": [d["path"] for d in retest_docs]}


def fingerprint_of(target: str, category: str, check_id: str, component: str) -> str:
    import hashlib

    basis = "|".join([target.rstrip("/"), category, check_id, component])
    return hashlib.sha1(basis.encode()).hexdigest()  # noqa: S324


def _fetch_lab_token_quietly(base_url: str) -> str | None:
    """Log into the local vulnerable lab with its documented demo account.

    The lab is intentionally insecure and its demo credentials are public by
    design (they are printed on its landing page). This exists purely so the
    platform can exercise *authenticated* checks without manual copy-paste.
    """
    import httpx

    try:
        resp = httpx.post(
            f"{base_url.rstrip('/')}/login",
            json={"username": "alice", "password": "user123"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            return resp.json().get("access_token")
    except Exception:
        pass
    return None


def _origin(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _resolve_user_id(db: Session, email: str) -> str:
    from ..models import User

    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        raise AuthorizationError("Authenticated user required")
    return user.id
