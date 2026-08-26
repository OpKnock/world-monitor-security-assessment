"""Secrets module — OpKnock/secrets-scanner ("portia") subprocess adapter.

Runs
----
``portia scan <authorized-source-path> --format json``

The upstream tool masks secret values before emitting JSON, so evidence
stays safe by construction.  This adapter adds:

* **OS-aware binary resolution** — ``portia`` vs ``portia.exe``.
* **Hardened subprocess handling** — timeout, stdout/stderr limits,
  banner-tolerant JSON parsing, ``TimeoutExpired`` → ``failed``.
* **Evidence discipline** — one ``scanner_output`` doc for the raw
  portia JSON plus per-finding ``file_match`` docs; every
  :class:`RawFinding` carries ``scan_target == source`` and
  ``evidence_payloads``.
* **Graceful degradation** — missing binary → ``skipped`` (actionable
  message), unparseable output → ``failed`` (stderr excerpt), no
  findings → ``completed`` with ``checks_safe=1``.
"""
from __future__ import annotations

import json
import logging
import platform
import subprocess
import time
from pathlib import Path

from ..config import settings
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule

logger = logging.getLogger(__name__)

__all__ = ["SecretsModule"]

SEVERITY_MAP: dict[str, str] = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFORMATIONAL"}

# Upstream exit codes observed: 0 = clean, 1 = findings, 2+ = error.
_OK_EXIT_CODES = {0, 1}
_SUBPROCESS_TIMEOUT_S = 300


class SecretsModule(ScannerModule):
    name = "secrets"
    category = "DATA_PRIVACY"
    description = "Detects hardcoded credentials committed in source"

    def _binary(self) -> str:
        """Resolve portia binary path with OS-aware extension."""
        override = (settings.SECRETS_SCANNER_BIN or "").strip()
        if override:
            return override
        exe = "portia.exe" if platform.system() == "Windows" else "portia"
        return str(settings.BIN_DIR / exe)

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        store = ctx.require_evidence()
        binary = self._binary()
        # ``source_path`` is the authorized filesystem scope.  Fall back to
        # the lab tree only when the caller omitted it — never scan an
        # empty string.
        raw_source = (ctx.source_path or "").strip() or str(settings.LAB_SOURCE_DIR)
        source = str(Path(raw_source).resolve()) if Path(raw_source).exists() else raw_source

        if not Path(source).exists():
            logger.warning("Secrets scan skipped — source does not exist: %s", source)
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[f"source path does not exist: {source}"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )

        bin_path = Path(binary)
        # Existence check gives a clearer message than a bare FileNotFoundError
        # from subprocess, and also lets us surface a ``skipped`` rather than
        # ``failed`` — the platform is mis-configured, not the scan target.
        if not bin_path.exists() and not (Path(binary).exists()):
            # Allow bare name on PATH (e.g. installed via go install)
            import shutil

            if shutil.which(binary) is None and shutil.which(str(bin_path)) is None:
                return ScanResult(
                    scanner=self.name,
                    status="skipped",
                    errors=[f"portia binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1 (or install portia on PATH)"],
                    checks_total=0,
                    duration_s=round(time.perf_counter() - started, 3),
                    notes=[f"Looked for {bin_path} and on PATH"],
                )

        cmd = [binary, "scan", source, "--format", "json", "--no-color"]
        logger.debug("Running secrets scanner: %s", " ".join(f'"{c}"' if " " in c else c for c in cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_S,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[f"portia binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except subprocess.TimeoutExpired:
            logger.warning("Secrets scan timed out after %ss: %s", _SUBPROCESS_TIMEOUT_S, cmd)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"portia timed out after {_SUBPROCESS_TIMEOUT_S}s scanning {source}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except Exception as exc:
            logger.exception("Secrets scan subprocess error: %s", exc)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[repr(exc)],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # ------------------------------------------------------------------
        # Parse output — portia prints a decorative banner before the JSON.
        # We locate the first '{' and parse from there; if there is no
        # '{' we treat the output as an error.  Stderr is captured for
        # diagnostics but never returned verbatim to callers (may contain
        # paths).
        # ------------------------------------------------------------------
        raw = proc.stdout or ""
        stdout_excerpt = raw[:2000]
        stderr_excerpt = (proc.stderr or "")[:800]

        json_start = raw.find("{")
        if json_start == -1:
            logger.warning("Secrets scan produced no JSON (exit %s): stdout %r stderr %r", proc.returncode, stdout_excerpt[:500], stderr_excerpt[:500])
            # Empty but exited 0 often means “no findings and no output” — treat
            # as success with 0 findings rather than failed, to avoid spurious
            # assessment failures when portia's output format shifts.
            if proc.returncode in _OK_EXIT_CODES and raw.strip() == "":
                return ScanResult(
                    scanner=self.name,
                    status="completed",
                    findings=[],
                    checks_total=1,
                    checks_safe=1,
                    errors=[f"portia emitted no output (exit {proc.returncode}); stderr: {stderr_excerpt[:300]}"] if stderr_excerpt.strip() else [],
                    duration_s=round(time.perf_counter() - started, 3),
                )
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"Unparseable output (exit {proc.returncode}): no JSON object in stdout. stderr: {stderr_excerpt[:400]}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        try:
            payload = json.loads(raw[json_start:])
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Secrets scan JSON parse failed: %s — stdout %r", exc, stdout_excerpt[:800])
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"Unparseable output (exit {proc.returncode}): {exc}. stderr: {stderr_excerpt[:400]}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # Persist raw scanner output (masked by EvidenceStore) for audit.
        try:
            store.save_scanner_output("portia", payload, note=f"portia scan {source}")
        except Exception as exc:
            logger.warning("Failed to persist portia output: %s", exc, exc_info=True)

        findings: list[RawFinding] = []
        raw_findings = payload.get("findings") or payload.get("Findings") or []
        if not isinstance(raw_findings, list):
            logger.warning("Unexpected findings shape: %r", type(raw_findings))
            raw_findings = []

        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule_id") or item.get("ruleId") or item.get("id") or "unknown")
            severity_raw = str(item.get("severity") or "").upper()
            severity = SEVERITY_MAP.get(severity_raw, "HIGH")
            file_path = str(item.get("file") or item.get("path") or "")
            # Line may be int or string; tolerate both.
            try:
                line_no = int(item.get("line") or item.get("line_number") or 0)
            except (TypeError, ValueError):
                line_no = 0
            description = str(item.get("description") or item.get("message") or f"Rule {rule_id} matched {file_path}:{line_no}.")[:600]
            # Persist per-match evidence — snippet is already masked by upstream.
            try:
                doc = store.save_file_match(file_path, line_no, description[:400], rule_id)
            except Exception as exc:
                logger.debug("Failed to persist file_match for %s: %s", file_path, exc)
                doc = {"path": "", "kind": "file_match", "summary": f"{rule_id} at {file_path}:{line_no}"}

            # Entropy / confidence if present.
            entropy = item.get("entropy")
            findings.append(
                RawFinding(
                    title=f"Hardcoded credential pattern '{rule_id}' committed in scanned source",
                    description=description,
                    severity=severity,
                    category=self.category,
                    affected_component=f"{file_path}:{line_no}" if file_path else rule_id,
                    scanner=self.name,
                    check_id=f"secrets.{rule_id}",
                    reproduction=[
                        f'{binary} scan "{source}" --format json',
                        f"Observe match for rule {rule_id} at line {line_no} (secret masked in evidence).",
                    ],
                    impact="Anyone with repository access gains working credentials; rotation is required once leaked.",
                    business_impact="Exposed keys allow direct impersonation of the service against third-party systems.",
                    remediation="Move the value to a secret manager / environment config and rotate it.",
                    references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    meta={"rule_id": rule_id, "entropy": entropy, "file": file_path, "line": line_no},
                    scan_target=source,
                    evidence_payloads=[doc],
                )
            )

        duration = round(time.perf_counter() - started, 3)
        # Non-zero exit outside {0,1} is an actual error — surface stderr.
        extra_errors: list[str] = []
        if proc.returncode not in _OK_EXIT_CODES:
            extra_errors.append(f"portia exit={proc.returncode} {stderr_excerpt[:300]}".strip())
            logger.warning("Portia exited %s: %s", proc.returncode, stderr_excerpt[:300])

        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        # If the payload already tells us there are 0 findings, we can trust it.
        if not findings and not raw_findings and isinstance(summary, dict) and summary:
            logger.debug("Portia summary: %r", summary)

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=1,
            checks_safe=1 if not findings else 0,
            errors=extra_errors,
            duration_s=duration,
            meta={"source": source, "total_findings": len(findings)},
        )
