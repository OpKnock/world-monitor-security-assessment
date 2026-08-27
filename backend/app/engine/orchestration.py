"""Assessment orchestration engine + background job system (spec §13-14).

Runs scanner modules on a bounded thread pool so HTTP requests never block.
Every run is gated by the authorization gate and audit-logged.
"""
from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import socket
import threading
import traceback
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings

logger = logging.getLogger(__name__)

from ..db import DB_WRITE_LOCK, worker_session
from .authorization_gate import (
    AuthorizationError,
    assert_authorized_flag,
    is_explicitly_allowed_target,
    resolve_target_ips,
    validate_http_target,
    validate_source_path,
)
from .evidence import EvidenceStore
from .findings import persist_raw_findings
from ..models import Assessment, AuditLog, Finding, ScanRun
from ..scanners.base import ScanContext
from ..scanners.registry import load_registry, scanners_for

# Thread pool for assessment execution (enforces MAX_SCAN_WORKERS)
_ASSESSMENT_EXECUTOR: ThreadPoolExecutor | None = None
_ASSESSMENT_EXECUTOR_LOCK = threading.Lock()
_ASSESSMENT_QUEUE_CAPACITY: threading.BoundedSemaphore | None = None
_DNS_PIN_LOCK = threading.Lock()
_DNS_PIN_INSTALLED = False
_DNS_PIN_TLS = threading.local()
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def _pinned_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> list[tuple]:
    """Resolve a scanner's pinned hostname to its validated addresses."""
    pin = getattr(_DNS_PIN_TLS, "pin", None)
    normalized_host = str(host).rstrip(".").lower() if host is not None else ""
    if pin is None or normalized_host != pin[0]:
        return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)
    results: list[tuple] = []
    for ip in pin[1]:
        # Ask the original resolver for the correct sockaddr shape, family,
        # and requested stream/datagram flags, but never resolve the hostname.
        results.extend(_ORIGINAL_GETADDRINFO(ip, port, *args, **kwargs))
    if not results:
        raise socket.gaierror(socket.EAI_NONAME, "pinned host has no addresses")
    return results


def _install_dns_pin_resolver() -> None:
    global _DNS_PIN_INSTALLED
    if _DNS_PIN_INSTALLED:
        return
    with _DNS_PIN_LOCK:
        if not _DNS_PIN_INSTALLED:
            socket.getaddrinfo = _pinned_getaddrinfo
            _DNS_PIN_INSTALLED = True


@contextmanager
def _pin_target_dns(target: str, ips: list[str]):
    """Pin hostname resolution for one scanner invocation on this thread."""
    host = urlparse(target).hostname if target else None
    if not host or not ips:
        yield
        return
    _install_dns_pin_resolver()
    previous = getattr(_DNS_PIN_TLS, "pin", None)
    _DNS_PIN_TLS.pin = (host.rstrip(".").lower(), tuple(ips))
    try:
        yield
    finally:
        if previous is None:
            try:
                del _DNS_PIN_TLS.pin
            except AttributeError:
                pass
        else:
            _DNS_PIN_TLS.pin = previous


def _revalidate_scan_target(target: str) -> tuple[str, dict[str, Any]]:
    """Re-check DNS immediately before a scanner makes network requests.

    The original hostname is deliberately retained. Replacing it with an IP
    breaks HTTPS certificate/SNI validation and virtual-host routing. The
    orchestration layer pins ``getaddrinfo`` for the scanner's thread so the
    URL keeps its hostname while connections use these validated addresses.
    """
    if not settings.LAB_MODE or not target or target == "(source-only)":
        return target, {}
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return target, {}
    ips = resolve_target_ips(host, allow_public=is_explicitly_allowed_target(target))
    return target, {"resolved_host": host, "resolved_ips": ips}


def _get_assessment_executor() -> ThreadPoolExecutor:
    """Get or create the thread pool executor for assessments."""
    global _ASSESSMENT_EXECUTOR, _ASSESSMENT_QUEUE_CAPACITY
    with _ASSESSMENT_EXECUTOR_LOCK:
        if _ASSESSMENT_EXECUTOR is None:
            max_workers = max(1, settings.MAX_SCAN_WORKERS)
            _ASSESSMENT_EXECUTOR = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="assessment-")
            # Bound both active and queued work. A small queue absorbs normal
            # bursts without allowing unbounded memory growth under load.
            _ASSESSMENT_QUEUE_CAPACITY = threading.BoundedSemaphore(max_workers * 2)
        return _ASSESSMENT_EXECUTOR


# Module keys recognized by the platform – keep in sync with scanners.base.AVAILABLE_MODULES
KNOWN_MODULES = frozenset(
    {
        "authentication",
        "authorization",
        "api",
        "input_validation",
        "headers",
        "tls",
        "secrets",
        "dependencies",
        "supply_chain",
        "graphql",
        "deep_scan",
        "fuzzing",
    }
)

# Modules that require an HTTP target
HTTP_MODULES = frozenset(
    {
        "authentication",
        "authorization",
        "api",
        "input_validation",
        "graphql",
        "headers",
        "tls",
        "deep_scan",
        "fuzzing",
    }
)

# Modules that require a filesystem source path
SOURCE_MODULES = frozenset({"secrets", "dependencies", "supply_chain"})

# Per-module target override keys that are meaningful – others are ignored
OVERRIDE_MODULE_KEYS = frozenset(
    {
        "authentication",
        "authorization",
        "api",
        "input_validation",
        "sqli",
        "headers",
        "tls",
        "graphql",
        "deep_scan",
        "fuzzing",
    }
)


def _audit(
    db: Session,
    email: str,
    action: str,
    target: str,
    detail: dict[str, Any],
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Append an audit log entry; commits immediately under write lock."""
    try:
        entry = AuditLog(
            user_email=(email or "system")[:255],
            action=action[:64],
            target=(target or "")[:2048],
            detail=dict(detail) if isinstance(detail, dict) else {"detail": str(detail)[:4000]},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.add(entry)
        with DB_WRITE_LOCK:
            db.commit()
    except Exception as exc:
        logger.warning("Audit log failed for action %s: %s", action, exc)
        try:
            db.rollback()
        except Exception:
            pass


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

    if not isinstance(modules, list) or not modules:
        raise AuthorizationError("At least one module must be selected")

    # Normalize modules: strip, lower, dedupe preserving order
    seen: set[str] = set()
    normalized_modules: list[str] = []
    for m in modules:
        if not isinstance(m, str):
            raise AuthorizationError(f"Invalid module entry: {m!r}")
        key = m.strip().lower()
        if not key:
            continue
        if key not in seen:
            seen.add(key)
            normalized_modules.append(key)
    modules = normalized_modules
    if not modules:
        raise AuthorizationError("At least one module must be selected")

    unknown = [m for m in modules if m not in KNOWN_MODULES]
    if unknown:
        raise AuthorizationError(f"Unknown modules: {unknown}")

    needs_http = any(m in HTTP_MODULES for m in modules)
    needs_source = any(m in SOURCE_MODULES for m in modules)

    # Target validation
    normalized_target = ""
    if needs_http:
        if not isinstance(target, str) or not target.strip():
            raise AuthorizationError("Target URL required for the selected modules")
        normalized_target = validate_http_target(target)
    else:
        # Source-only assessments may omit target; if provided still validate
        if target and target.strip():
            try:
                normalized_target = validate_http_target(target)
            except AuthorizationError:
                # For source-only mode, allow "(source-only)" sentinel without HTTP target
                normalized_target = target.strip()[:2048]

    if not target and not needs_source:
        raise AuthorizationError("Target URL required for the selected modules")
    if not target.strip() and needs_http:
        raise AuthorizationError("Target URL required for the selected modules")

    # Per-module overrides are validated through the same gate
    safe_overrides: dict[str, str] = {}
    for mod_key, url in (module_targets or {}).items():
        if not isinstance(mod_key, str) or not isinstance(url, str):
            continue
        mk = mod_key.strip().lower()
        uv = url.strip()
        if not uv or mk not in OVERRIDE_MODULE_KEYS:
            continue
        # Only allow overrides for modules actually selected (or their aliases)
        # but still gate-validate even if not selected to avoid storing malicious URLs
        try:
            safe_overrides[mk] = validate_http_target(uv)
        except AuthorizationError as exc:
            raise AuthorizationError(f"Invalid override target for '{mk}': {exc}") from exc

    resolved_source = ""
    if needs_source:
        src = source_path or str(settings.LAB_SOURCE_DIR)
        resolved_source = validate_source_path(src)
    elif source_path and source_path.strip():
        resolved_source = validate_source_path(source_path)

    # Resolve user
    user_id = _resolve_user_id(db, user_email)

    assessment = Assessment(
        user_id=user_id,
        target=normalized_target or "(source-only)",
        source_path=resolved_source,
        modules=modules,
        module_targets=safe_overrides,
        status="queued",
        authorized=True,
        authorization_note=f"LAB_MODE={settings.LAB_MODE}; gate passed {datetime.now(timezone.utc).isoformat()}",
    )
    db.add(assessment)
    try:
        db.flush()
    except Exception as exc:
        db.rollback()
        raise AuthorizationError(f"Failed to create assessment: {exc}") from exc

    for mod in modules:
        db.add(ScanRun(assessment_id=assessment.id, scanner=mod, status="queued"))

    try:
        with DB_WRITE_LOCK:
            db.commit()
    except Exception as exc:
        db.rollback()
        raise IOError(f"Failed to persist assessment: {exc}") from exc

    _audit(
        db,
        user_email,
        "assessment.created",
        assessment.target,
        {"assessment_id": assessment.id, "modules": modules, "authorized": True},
    )
    return assessment


def start_assessment_async(assessment_id: str, auth_token: str | None = None) -> None:
    """Submit assessment to bounded thread pool (MAX_SCAN_WORKERS)."""
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise ValueError("assessment_id must be a non-empty string")
    try:
        load_registry()
    except Exception as exc:
        logger.error("Failed to load scanner registry: %s", exc)
    executor = _get_assessment_executor()
    capacity = _ASSESSMENT_QUEUE_CAPACITY
    if capacity is None or not capacity.acquire(blocking=False):
        raise RuntimeError("assessment queue is full; retry after active scans finish")
    try:
        executor.submit(_run_assessment_with_capacity, assessment_id, auth_token)
    except Exception:
        capacity.release()
        raise


def _run_assessment_with_capacity(assessment_id: str, auth_token: str | None = None) -> None:
    """Run one assessment and release its active/queued capacity slot."""
    try:
        _run_assessment(assessment_id, auth_token)
    finally:
        if _ASSESSMENT_QUEUE_CAPACITY is not None:
            _ASSESSMENT_QUEUE_CAPACITY.release()


def _run_assessment(assessment_id: str, auth_token: str | None = None) -> None:
    logger.info("Starting assessment %s", assessment_id)

    def _watchdog() -> None:
        dbw = worker_session()
        try:
            a = dbw.get(Assessment, assessment_id)
            if a is not None and a.status == "running":
                a.status = "failed"
                a.error = "watchdog timeout (>10 min)"
                with DB_WRITE_LOCK:
                    dbw.commit()
                logger.warning("watchdog failed %s", assessment_id)
                _audit(dbw, "", "scan.watchdog", a.target, {"assessment_id": assessment_id})
        except Exception as exc:
            logger.warning("watchdog error for %s: %s", assessment_id, exc)
            try:
                dbw.rollback()
            except Exception:
                pass
        finally:
            try:
                dbw.close()
            except Exception:
                pass
            # Dispose engine if worker_session created a throwaway engine
            try:
                bind = getattr(dbw, "bind", None)
                if bind is not None:
                    bind.dispose()
            except Exception:
                pass

    watchdog = threading.Timer(settings.SCAN_TIMEOUT_SECONDS, _watchdog)
    watchdog.daemon = True
    watchdog.start()

    db: Session = worker_session()
    try:
        assessment = db.get(Assessment, assessment_id)
        if assessment is None:
            logger.warning("Assessment %s not found, aborting run", assessment_id)
            return
        assessment.status = "running"
        assessment.started_at = datetime.now(timezone.utc)
        try:
            with DB_WRITE_LOCK:
                db.commit()
        except Exception as exc:
            logger.error("Failed to mark assessment %s running: %s", assessment_id, exc)
            db.rollback()
            return

        try:
            store = EvidenceStore(assessment.id)
        except Exception as exc:
            logger.error("Failed to create evidence store for %s: %s", assessment_id, exc)
            assessment.status = "failed"
            assessment.error = f"evidence store init failed: {exc}"
            assessment.finished_at = datetime.now(timezone.utc)
            with DB_WRITE_LOCK:
                db.commit()
            return

        logger.debug("evidence store ready for %s", assessment_id)
        try:
            runs_list = db.scalars(select(ScanRun).where(ScanRun.assessment_id == assessment.id)).all()
        except Exception as exc:
            logger.error("Failed to load scan runs for %s: %s", assessment_id, exc)
            assessment.status = "failed"
            assessment.error = f"failed to load scan runs: {exc}"
            assessment.finished_at = datetime.now(timezone.utc)
            with DB_WRITE_LOCK:
                db.commit()
            return

        runs = {r.scanner: r for r in runs_list}
        logger.info("Loaded %d scan runs for %s: %s", len(runs), assessment_id, list(runs))

        # Per-module target overrides were gate-validated at creation time
        safe_overrides: dict[str, str] = dict(assessment.module_targets or {})

        # Resolve one lab demo token per ASSESSMENT (not per module)
        http_token = auth_token
        if http_token is None and ({"authentication", "authorization"} & set(runs.keys())):
            _tgt = safe_overrides.get("authentication") or assessment.target
            _org = _origin(_tgt)
            if _org and _org != "(source-only)":
                try:
                    http_token = _fetch_lab_token_quietly(_org)
                except Exception:
                    http_token = None

        failures = 0
        for module_key, run in runs.items():
            try:
                scanner_instances = scanners_for([module_key])
            except Exception as exc:
                logger.error("scanners_for failed for %s: %s", module_key, exc)
                scanner_instances = []
            logger.info("Starting module %s with %d scanner(s) for assessment %s", module_key, len(scanner_instances), assessment_id)
            run.status = "running"
            run.started_at = datetime.now(timezone.utc)
            try:
                with DB_WRITE_LOCK:
                    db.commit()
            except Exception as exc:
                logger.warning("Failed to mark run %s running: %s", module_key, exc)
                db.rollback()
            logger.debug("%s module %s status=running committed", assessment_id, module_key)
            started = datetime.now(timezone.utc)

            token_for_module = http_token
            logger.debug("%s module %s token=%s", assessment_id, module_key, "yes" if token_for_module else "no")

            all_findings: list[Any] = []
            errors: list[str] = []
            skipped_results: list[Any] = []
            skipped_notes: list[str] = []
            total_checks = 0
            safe_checks = 0

            for inst in scanner_instances:
                # Resolve target for this scanner instance
                target_for_ctx = (
                    safe_overrides.get(getattr(inst, "name", ""))
                    or safe_overrides.get(module_key)
                    or assessment.target
                )
                # ---- DNS rebinding protection: re-resolve at scan time (LAB_MODE) ----
                if settings.LAB_MODE:
                    try:
                        target_for_ctx, target_options = _revalidate_scan_target(target_for_ctx)
                    except AuthorizationError as exc:
                        logger.error("DNS re-validation failed for %s: %s", target_for_ctx, exc)
                        errors.append(f"{getattr(inst, 'name', '?')}: DNS re-validation failed: {exc}")
                        continue
                    except Exception as exc:
                        logger.error("DNS re-validation error for %s: %s", target_for_ctx, exc)
                        errors.append(f"{getattr(inst, 'name', '?')}: DNS re-validation error: {exc}")
                        continue
                else:
                    target_options = {}
                ctx = ScanContext(
                    target=target_for_ctx,
                    source_path=assessment.source_path or "",
                    auth_token=token_for_module,
                    evidence=store,
                    options=target_options,
                )
                logger.debug("%s inst %s begin target=%s", assessment_id, getattr(inst, "name", "?"), target_for_ctx)
                try:
                    with _pin_target_dns(target_for_ctx, target_options.get("resolved_ips", [])):
                        result = inst.run(ctx)
                except Exception as exc:  # a broken adapter must never kill the assessment
                    errors.append(f"{getattr(inst, 'name', '?')}: {repr(exc)}\n{traceback.format_exc(limit=3)}")
                    logger.warning("Scanner %s failed: %s", getattr(inst, "name", "?"), exc, exc_info=True)
                    continue
                logger.debug(
                    "%s inst %s done status=%s findings=%d",
                    assessment_id,
                    getattr(inst, "name", "?"),
                    getattr(result, "status", "?"),
                    len(getattr(result, "findings", []) or []),
                )
                if getattr(result, "status", "") == "skipped":
                    skipped_results.append(result)
                    skipped_notes.extend(getattr(result, "notes", []) or [])
                    # Also count as not failed
                    errors.extend(getattr(result, "errors", []) or [])
                all_findings.extend(getattr(result, "findings", []) or [])
                errors.extend(f"{getattr(result, 'scanner', '?')}: {e}" for e in getattr(result, "errors", []) or [])
                total_checks += int(getattr(result, "checks_total", 0) or 0)
                safe_checks += int(getattr(result, "checks_safe", 0) or 0)
                if getattr(result, "status", "") == "failed":
                    errors.append(f"{getattr(result, 'scanner', '?')}: failed")

            duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            raw_path = ""
            logger.debug("%s %s post-loop errors=%d findings=%d", assessment_id, module_key, len(errors), len(all_findings))
            if all_findings or errors:
                try:
                    doc_path = store.save(
                        kind="scanner_output",
                        summary=f"{module_key} combined output",
                        payload={
                            "module": module_key,
                            "findings": [
                                f.model_dump(exclude={"evidence_payloads"}) if hasattr(f, "model_dump") else str(f)
                                for f in all_findings
                            ],
                            "errors": errors,
                            "checks_total": total_checks,
                            "checks_safe": safe_checks,
                        },
                    )
                    raw_path = doc_path["path"]
                    logger.debug("%s %s raw saved %s", assessment_id, module_key, raw_path)
                except Exception as exc:
                    logger.warning("Failed to save combined output for %s: %s", module_key, exc)

            logger.debug("%s %s persist call", assessment_id, module_key)
            try:
                new_or_updated, merged = persist_raw_findings(db, assessment, run, all_findings)
            except Exception as exc:
                logger.error("persist_raw_findings failed for %s: %s", module_key, exc, exc_info=True)
                run.status = "failed"
                run.error = f"persist failed: {exc}"[:2000]
                run.duration_ms = duration_ms
                failures += 1
                try:
                    with DB_WRITE_LOCK:
                        db.commit()
                except Exception:
                    db.rollback()
                continue
            logger.debug("%s %s persist returned merged=%d", assessment_id, module_key, merged)
            run.duration_ms = duration_ms
            run.findings_count = len(all_findings)
            run.checks_total = total_checks
            run.checks_safe = safe_checks
            run.raw_output_path = raw_path or ""
            run.finished_at = datetime.now(timezone.utc)
            module_skipped = bool(skipped_results) and len(skipped_results) == len(scanner_instances) and len(scanner_instances) > 0
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
            try:
                with DB_WRITE_LOCK:
                    db.commit()
            except Exception as exc:
                logger.error("Failed to commit run %s: %s", module_key, exc)
                db.rollback()
            logger.info("Module %s completed for %s: status=%s findings=%d duration_ms=%d", module_key, assessment_id, run.status, len(all_findings), duration_ms)
            _audit(
                db,
                "",
                "scan.finished",
                assessment.target,
                {"scanner": module_key, "status": run.status, "findings": len(all_findings), "duration_ms": duration_ms},
            )

        # Live alerting: push critical/high summary to a webhook when configured
        try:
            _url = (settings.ALERT_WEBHOOK_URL or "").strip()
            # Success means not every module failed
            is_success = (failures != len(runs) or not runs)
            if _url and is_success:
                import httpx as _hx

                crit = db.scalar(
                    select(Finding.id).where(
                        Finding.assessment_id == assessment.id,
                        Finding.severity.in_(("CRITICAL", "HIGH")),
                    )
                )
                if crit is not None:
                    all_ids = db.scalars(select(Finding.id).where(Finding.assessment_id == assessment.id)).all()
                    try:
                        _hx.post(
                            _url,
                            json={
                                "text": f"[World Monitor] {len(all_ids)} finding(s), "
                                f"incl. CRITICAL/HIGH, on {assessment.target}"
                            },
                            timeout=settings.ALERT_WEBHOOK_TIMEOUT,
                        )
                        logger.info("webhook alert sent for %s", assessment_id)
                    except Exception as exc:
                        logger.debug("webhook POST failed for %s: %s", assessment_id, exc)

        except Exception:
            logger.debug("webhook alert failed for %s", assessment_id, exc_info=True)

        # Determine final assessment status – skipped modules are not failures
        non_skipped_runs = [r for r in runs.values() if r.status != "skipped"]
        if not runs:
            assessment.status = "completed"
        elif non_skipped_runs and failures == len(non_skipped_runs):
            assessment.status = "failed"
        elif failures == len(runs) and runs:
            # All runs either failed or skipped – if any skipped, consider completed
            if any(r.status == "skipped" for r in runs.values()):
                assessment.status = "completed"
            else:
                assessment.status = "failed"
        else:
            assessment.status = "completed"
        assessment.finished_at = datetime.now(timezone.utc)
        assessment.total_duration_ms = sum(r.duration_ms for r in runs.values())
        assessment.total_findings = sum(r.findings_count for r in runs.values())
        try:
            with DB_WRITE_LOCK:
                db.commit()
        except Exception as exc:
            logger.error("Failed to commit final assessment status for %s: %s", assessment_id, exc)
            db.rollback()
        logger.info("Assessment %s completed: status=%s total_findings=%d total_duration_ms=%d",
                    assessment_id, assessment.status, assessment.total_findings, assessment.total_duration_ms)
    except Exception as exc:  # never leave an assessment stuck in 'running'
        logger.error("Assessment %s crashed: %s", assessment_id, exc, exc_info=True)
        try:
            # Re-fetch assessment in case session is stale
            try:
                assessment = db.get(Assessment, assessment_id)
            except Exception:
                assessment = None
            if assessment is not None:
                assessment.status = "failed"
                assessment.error = f"{repr(exc)}\n{traceback.format_exc(limit=5)}"[:4000]
                assessment.finished_at = datetime.now(timezone.utc)
                with DB_WRITE_LOCK:
                    db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    finally:
        watchdog.cancel()
        try:
            db.close()
        except Exception:
            pass
        try:
            bind = getattr(db, "bind", None)
            if bind is not None:
                bind.dispose()
        except Exception:
            pass


def retest_finding(db: Session, finding_id: str, user_email: str) -> dict[str, Any]:
    """Re-run only the check behind a finding; compare fingerprints (spec §35)."""
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id must be a non-empty string")
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise ValueError("Finding not found")
    assessment = db.get(Assessment, finding.assessment_id)
    if assessment is None:
        raise ValueError("Assessment for finding not found")
    # Authorization – operator must be analyst; flag is implicitly true for retest
    assert_authorized_flag(True)

    check_prefix = finding.check_id.split(".", 1)[0] if finding.check_id else ""
    module_key = {
        "auth": "authentication",
        "idor": "authorization",
        "rate_limit": "api",
        "sqli": "input_validation",
        "input_validation": "input_validation",
        "headers": "headers",
        "tls": "tls",
        "secrets": "secrets",
        "supply_chain": "supply_chain",
        "dependencies": "dependencies",
        "graphql": "graphql",
        "deep_scan": "deep_scan",
        "fuzzing": "fuzzing",
        "privacy": "secrets",
    }.get(check_prefix, finding.scanner)

    load_registry()
    instances = scanners_for([module_key])
    if not instances:
        # Fallback try finding.scanner directly as module key
        instances = scanners_for([finding.scanner])
    if not instances:
        raise ValueError(f"No scanner available for module '{finding.scanner}' / '{module_key}'")

    try:
        store = EvidenceStore(assessment.id)
    except Exception as exc:
        raise IOError(f"Failed to create evidence store: {exc}") from exc

    stored_overrides = dict(assessment.module_targets or {})
    # Resolve target for retest – prefer stored override, then finding target, then assessment target
    target_for_retest = (
        stored_overrides.get(module_key)
        or stored_overrides.get(finding.scanner)
        or (finding.target if finding.target and finding.target != "(source-only)" else "")
        or assessment.target
    )
    if not target_for_retest or target_for_retest == "(source-only)":
        # For source-based findings, use source_path
        target_for_retest = assessment.target if assessment.target != "(source-only)" else "http://127.0.0.1/"

    # Revalidate DNS immediately before any retest network activity. Keep the
    # hostname in the URL so HTTPS SNI/certificate and virtual-host routing
    # remain correct.
    try:
        target_for_retest, target_options = _revalidate_scan_target(target_for_retest)
    except AuthorizationError as exc:
        raise AuthorizationError(f"Retest target failed DNS re-validation: {exc}") from exc

    # Token for auth-gated retests
    token: str | None = None
    if check_prefix in ("auth", "idor"):
        origin = _origin(target_for_retest)
        if origin and origin != "(source-only)":
            try:
                token = _fetch_lab_token_quietly(origin)
            except Exception:
                token = None

    ctx = ScanContext(
        target=target_for_retest,
        source_path=assessment.source_path or "",
        auth_token=token,
        evidence=store,
        options=target_options,
    )
    still_present = False
    successful_scanners = 0
    unsuccessful_scanners = 0
    retest_docs: list[dict[str, str]] = []
    for inst in instances:
        try:
            with _pin_target_dns(target_for_retest, target_options.get("resolved_ips", [])):
                result = inst.run(ctx)
        except Exception as exc:
            unsuccessful_scanners += 1
            logger.warning("Retest scanner %s failed: %s", getattr(inst, "name", "?"), exc)
            retest_docs.append(
                store.save(
                    kind="scanner_output",
                    summary=f"retest {getattr(inst, 'name', '?')} error",
                    payload={"retest": True, "scanner": getattr(inst, "name", "?"), "error": repr(exc)},
                )
            )
            continue
        result_status = getattr(result, "status", "")
        result_errors = list(getattr(result, "errors", []) or [])
        if result_status == "completed" and not result_errors:
            successful_scanners += 1
        else:
            # Failed/skipped results are valid scanner responses, but they do
            # not prove a finding was remediated.
            unsuccessful_scanners += 1
        # Compare fingerprints of findings seen during retest with original
        for f in getattr(result, "findings", []) or []:
            try:
                fp = fingerprint_of(
                    getattr(f, "scan_target", None) or ctx.target,
                    getattr(f, "category", ""),
                    getattr(f, "check_id", ""),
                    getattr(f, "affected_component", ""),
                )
                if fp == finding.fingerprint:
                    still_present = True
                    break
            except Exception:
                continue
        retest_docs.append(
            store.save(
                kind="scanner_output",
                summary=f"retest {getattr(inst, 'name', '?')} -> {'STILL_PRESENT' if still_present else 'checked'}",
                payload={
                    "retest": True,
                    "scanner": getattr(inst, "name", "?"),
                    "status": result_status,
                    "errors": result_errors,
                    "findings_seen": [getattr(f, "check_id", "?") for f in getattr(result, "findings", []) or []],
                },
            )
        )
        if still_present:
            break

    finding.retest_count = int(finding.retest_count or 0) + 1
    finding.retested_at = datetime.now(timezone.utc)
    if successful_scanners == 0 or unsuccessful_scanners > 0:
        finding.retest_status = "INCONCLUSIVE"
        finding.status = "OPEN"
    else:
        finding.retest_status = "STILL_PRESENT" if still_present else "FIXED"
        finding.status = "CONFIRMED" if still_present else "RETESTED"
    # Preserve existing meta and append retest evidence paths
    base_meta = dict(finding.meta or {})
    base_meta["retest_evidence"] = [d["path"] for d in retest_docs]
    base_meta["retest_at"] = finding.retested_at.isoformat()
    finding.meta = base_meta
    try:
        with DB_WRITE_LOCK:
            db.commit()
    except Exception as exc:
        db.rollback()
        raise IOError(f"Failed to persist retest result: {exc}") from exc

    _audit(
        db,
        user_email,
        "retest.executed",
        finding.target,
        {"finding_id": finding.id, "result": finding.retest_status},
    )
    return {"finding_id": finding.id, "retest_status": finding.retest_status, "evidence": [d["path"] for d in retest_docs]}


def fingerprint_of(target: str, category: str, check_id: str, component: str) -> str:
    """Stable fingerprint helper for retest comparison."""
    import hashlib

    # Reuse same normalization as findings.fingerprint_for
    try:
        from .findings import fingerprint_for as _fp

        return _fp(target, category, check_id, component)
    except Exception:
        basis = "|".join([target.rstrip("/") if isinstance(target, str) else str(target), category, check_id, component])
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()  # noqa: S324


def _fetch_lab_token_quietly(base_url: str) -> str | None:
    """Log into the local vulnerable lab with its documented demo account.

    The lab is intentionally insecure and its demo credentials are public by
    design (they are printed on its landing page). This exists purely so the
    platform can exercise *authenticated* checks without manual copy-paste.
    """
    if not isinstance(base_url, str) or not base_url.strip():
        return None
    # Sanitize base_url
    base = base_url.strip().rstrip("/")
    if not base.lower().startswith(("http://", "https://")):
        return None
    import httpx

    try:
        resp = httpx.post(
            f"{base}/login",
            json={"username": "alice", "password": "user123"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                tok = data.get("access_token")
                if isinstance(tok, str) and tok.strip():
                    return tok.strip()
            except Exception:
                return None
    except Exception:
        pass
    return None


def _origin(url: str) -> str:
    """Extract scheme://host[:port] from a URL, or return empty on failure."""
    if not isinstance(url, str) or not url.strip():
        return ""
    if url.strip() == "(source-only)":
        return ""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url.strip())
        if not parts.scheme or not parts.netloc:
            return ""
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
    except Exception:
        return ""


def _resolve_user_id(db: Session, email: str) -> str:
    """Look up the authenticated user's DB id or raise AuthorizationError."""
    if not isinstance(email, str) or not email.strip():
        raise AuthorizationError("Authenticated user required")
    from ..models import User

    try:
        user = db.scalar(select(User).where(User.email == email.strip()))
    except Exception as exc:
        raise AuthorizationError(f"User lookup failed: {exc}") from exc
    if user is None:
        raise AuthorizationError("Authenticated user required")
    return user.id


__all__ = [
    "create_assessment",
    "start_assessment_async",
    "retest_finding",
    "fingerprint_of",
]
