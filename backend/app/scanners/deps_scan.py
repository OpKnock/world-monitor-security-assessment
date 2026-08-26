"""Dependencies module — OpKnock/sbom-generator-vulnerability-matcher ("bomber").

Runs
----
``bomber vuln <authorized-project-dir> --format json``

The upstream tool marshals Go iota enums as integers::

    Ecosystem: 0 = go, 1 = node, 2 = python
    Severity : 0 = NONE, 1 = LOW, 2 = MEDIUM, 3 = HIGH, 4 = CRITICAL

This adapter:

* Resolves the ``bomber`` binary with correct ``.exe`` handling.
* Executes with a 10-minute wall-clock budget.
* Parses both ``Matches`` / ``matches`` payload shapes.
* Enriches ``Severity == 0`` / ``UNKNOWN`` entries from ``api.osv.dev``
  (best-effort, 8 s HTTP timeout, never fails the scan if offline).
* Emits one :class:`RawFinding` per matched vulnerability with
  ``scan_target == source`` and linked ``scanner_output`` evidence.
"""
from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..config import settings
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule

logger = logging.getLogger(__name__)

__all__ = ["DependenciesModule"]

ECOSYSTEMS: dict[int, str] = {0: "go", 1: "node", 2: "python"}
SEVERITIES: dict[int, str] = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

_SUBPROCESS_TIMEOUT_S = 600
_OSV_TIMEOUT_S = 8.0


class DependenciesModule(ScannerModule):
    name = "dependencies"
    category = "DEPENDENCIES"
    description = "SBOM generation + OSV vulnerability matching"

    def _binary(self) -> str:
        override = (settings.SBOM_SCANNER_BIN or "").strip()
        if override:
            return override
        exe = "bomber.exe" if platform.system() == "Windows" else "bomber"
        return str(settings.BIN_DIR / exe)

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        store = ctx.require_evidence()
        binary = self._binary()
        raw_source = (ctx.source_path or "").strip() or str(settings.LAB_SOURCE_DIR)
        source = str(Path(raw_source).resolve()) if Path(raw_source).exists() else raw_source

        if not Path(source).exists():
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[f"source path does not exist: {source}"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # Binary availability — skipped, not failed (platform mis-config).
        bin_exists = Path(binary).exists() or shutil.which(binary) is not None
        if not bin_exists:
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[f"bomber binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )

        cmd = [binary, "vuln", source, "--format", "json"]
        logger.debug("Running dependencies scanner: %s", " ".join(f'"{c}"' if " " in c else c for c in cmd))

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
                errors=[f"bomber binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except subprocess.TimeoutExpired:
            logger.warning("Dependencies scan timed out after %ss", _SUBPROCESS_TIMEOUT_S)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"bomber timed out after {_SUBPROCESS_TIMEOUT_S}s scanning {source}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except Exception as exc:
            logger.exception("Dependencies scan subprocess error: %s", exc)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[repr(exc)],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        raw_stdout = proc.stdout or ""
        stderr_excerpt = (proc.stderr or "")[:600]

        try:
            payload: dict[str, Any] = json.loads(raw_stdout or "{}")
        except json.JSONDecodeError as exc:
            logger.warning("Dependencies scan JSON parse failed: %s — stdout %r", exc, raw_stdout[:500])
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"Unparseable output (exit {proc.returncode}): {exc}. stderr: {stderr_excerpt[:400]}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        # Persist raw output for audit (masked by EvidenceStore).
        try:
            store.save_scanner_output("bomber", payload, note=f"bomber vuln {source}")
        except Exception as exc:
            logger.warning("Failed to persist bomber output: %s", exc, exc_info=True)

        # Normalise vulnerability matches — upstream has used both capitalised
        # and lower-case keys across versions.
        vulns_raw: dict[str, Any] = {}
        if isinstance(payload.get("vulnerabilities"), dict):
            vulns_raw = payload["vulnerabilities"]  # type: ignore[assignment]
        elif isinstance(payload.get("Vulnerabilities"), dict):
            vulns_raw = payload["Vulnerabilities"]  # type: ignore[assignment]
        else:
            # Some builds put Matches at top-level.
            vulns_raw = payload if isinstance(payload.get("Matches"), list) or isinstance(payload.get("matches"), list) else {}

        vulns: list[dict[str, Any]] = []
        if isinstance(vulns_raw.get("Matches"), list):
            vulns = vulns_raw["Matches"]  # type: ignore[assignment]
        elif isinstance(vulns_raw.get("matches"), list):
            vulns = vulns_raw["matches"]  # type: ignore[assignment]
        elif isinstance(payload.get("Matches"), list):
            vulns = payload["Matches"]  # type: ignore[assignment]
        elif isinstance(payload.get("matches"), list):
            vulns = payload["matches"]  # type: ignore[assignment]

        # ------------------------------------------------------------------
        # OSV enrichment — bomber collapses unknown severities to 0, so we
        # re-query OSV for the real severity/CVSS when possible.  This is
        # best-effort; offline / rate-limited environments must still return
        # findings (with fallback LOW severity).
        # ------------------------------------------------------------------
        osv_severity: dict[str, tuple[str | None, str | None, float | None]] = {}
        # De-duplicate CVE ids to avoid hammering the API.
        ids = [str((m.get("Vulnerability") or {}).get("ID") or (m.get("vulnerability") or {}).get("id") or "") for m in vulns]
        unique_ids = list(dict.fromkeys(i for i in ids if i and i != "UNKNOWN"))
        if unique_ids:
            try:
                import httpx

                with httpx.Client(timeout=_OSV_TIMEOUT_S) as hc:
                    for vid in unique_ids:
                        try:
                            vr = hc.get(f"https://api.osv.dev/v1/vulns/{vid}")
                            if vr.status_code != 200:
                                continue
                            vj = vr.json()
                            vec: str | None = None
                            score: float | None = None
                            # CVSS_V3 vector extraction.
                            for s in vj.get("severity", []) or []:
                                if isinstance(s, dict) and s.get("type") == "CVSS_V3":
                                    vec = s.get("score")
                                    break
                            db_spec = vj.get("database_specific") or {}
                            sev_name = (db_spec.get("severity") or "").upper() or None
                            # Some advisories expose score via database_specific or top-level.
                            cvss_base = vj.get("cvss") if isinstance(vj.get("cvss"), dict) else {}
                            if isinstance(cvss_base, dict):
                                try:
                                    score = float(cvss_base.get("score")) if cvss_base.get("score") is not None else None
                                except (TypeError, ValueError):
                                    score = None
                            if vec and score is None:
                                try:
                                    import cvss as _cvss  # type: ignore[import-not-found]

                                    score = float(_cvss.CVSS3(vec).base_score)
                                except Exception:
                                    score = None
                            # Normalise legacy severity labels.
                            label = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(sev_name or "", sev_name) if sev_name else None
                            # Only keep enrichment if we learnt something useful.
                            if label or vec or score is not None:
                                # Clamp label to allowed values.
                                if label and label not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                                    label = None
                                osv_severity[vid] = (label, vec, float(score) if score is not None else None)
                        except Exception:
                            # Per-CVE failure must not abort enrichment for others.
                            continue
            except ImportError:
                logger.debug("httpx not available — skipping OSV enrichment")
            except Exception as exc:
                logger.debug("OSV enrichment failed: %s", exc)

        findings: list[RawFinding] = []
        for match in vulns:
            if not isinstance(match, dict):
                continue
            pkg = match.get("Package") or match.get("package") or {}
            vuln = match.get("Vulnerability") or match.get("vulnerability") or {}
            if not isinstance(pkg, dict):
                pkg = {}
            if not isinstance(vuln, dict):
                vuln = {}

            cve = str(vuln.get("ID") or vuln.get("id") or "UNKNOWN")
            # Upstream Severity may be int or string label.
            sev_raw = vuln.get("Severity")
            if sev_raw is None:
                sev_raw = vuln.get("severity")
            try:
                sev_int = int(sev_raw) if sev_raw is not None else 0
            except (TypeError, ValueError):
                # String label like "HIGH" — map directly.
                sev_label = str(sev_raw).upper()
                sev_int = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev_label, 0)

            severity = SEVERITIES.get(sev_int)
            olabel, ovec, oscore = osv_severity.get(cve, (None, None, None))
            if olabel:
                severity = olabel
            if not severity:
                severity = "LOW"

            # Ecosystem may be int or string.
            eco_raw = pkg.get("Ecosystem")
            if eco_raw is None:
                eco_raw = pkg.get("ecosystem")
            try:
                eco = ECOSYSTEMS.get(int(eco_raw), str(eco_raw).lower() if isinstance(eco_raw, str) else "unknown")
            except (TypeError, ValueError):
                eco = str(eco_raw).lower() if isinstance(eco_raw, str) else "unknown"

            name = str(pkg.get("Name") or pkg.get("name") or "?")
            version = str(pkg.get("Version") or pkg.get("version") or "?")
            fix_version = str(vuln.get("FixVersion") or vuln.get("FixedVersion") or vuln.get("fixedVersion") or "")
            summary_text = str(vuln.get("Summary") or vuln.get("summary") or vuln.get("Description") or f"{cve} affects {name} {version}.")[:800]

            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"{cve} on {name}@{version}",
                    payload={"match": match, "cve": cve, "package": f"{name}@{version}"},
                )
            except Exception as exc:
                logger.debug("Failed to persist dep finding %s: %s", cve, exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"{cve} on {name}@{version}"}

            # Build CVE reference list — OSV is the canonical anchor.
            refs = [f"https://osv.dev/vulnerability/{cve}"] if cve != "UNKNOWN" else []
            if not fix_version:
                refs.append("https://github.com/advisories")

            # Resolve CVSS vector/score — prefer OSV-enriched values.
            cvss_vec = ovec  # may be None
            cvss_score: float | None = oscore
            if cvss_score is None:
                try:
                    cvss_score = float(vuln.get("Score") or vuln.get("score") or 0) or None
                except (TypeError, ValueError):
                    cvss_score = None

            findings.append(
                RawFinding(
                    title=f"Vulnerable dependency: {name}@{version} ({cve})",
                    description=summary_text,
                    severity=severity,
                    category=self.category,
                    affected_component=f"{eco}:{name}@{version}",
                    scanner=self.name,
                    check_id=f"dependencies.{cve}",
                    reproduction=[f'{binary} vuln "{source}" --format json'],
                    impact="A known vulnerability in a shipped library is reachable from the application.",
                    business_impact="Known-exploitable CVEs are the easiest initial-access path for attackers.",
                    remediation=(f"Upgrade {name} to {fix_version}" if fix_version else f"Upgrade or replace {name}; no fixed version published yet."),
                    references=refs,
                    cvss_vector=cvss_vec,
                    meta={"cvss_score": cvss_score, "aliases": vuln.get("Aliases") or vuln.get("aliases"), "purl": pkg.get("PURL") or pkg.get("purl"), "direct": pkg.get("Direct") if "Direct" in pkg else pkg.get("direct")},
                    scan_target=source,
                    evidence_payloads=[doc],
                )
            )

        # Total package count for coverage metrics — fall back to payload scan
        # info if the vulnerabilities wrapper did not include it.
        total_pkgs: int = 0
        try:
            total_pkgs = int(vulns_raw.get("TotalPkgs") or (payload.get("scan") or {}).get("TotalPkgs") or 0)
        except (TypeError, ValueError):
            total_pkgs = 0
        if total_pkgs == 0:
            # Rough fallback: number of distinct packages seen in matches.
            total_pkgs = max(len({str((m.get("Package") or {}).get("Name")) for m in vulns}) or 1, 1)

        duration = round(time.perf_counter() - started, 3)
        errors: list[str] = []
        if proc.returncode != 0:
            # bomber may exit non-zero even with valid findings; only surface
            # the message when it looks like a real error (empty findings).
            if not findings:
                errors.append(f"bomber exit={proc.returncode} {stderr_excerpt[:400]}".strip())
            elif stderr_excerpt.strip():
                logger.debug("bomber stderr (with findings, exit %s): %s", proc.returncode, stderr_excerpt[:400])

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=max(total_pkgs, 1),
            checks_safe=max(total_pkgs - len(findings), 0),
            errors=errors,
            duration_s=duration,
            meta={"source": source, "total_packages": total_pkgs, "osv_enriched": len(osv_severity)},
        )
