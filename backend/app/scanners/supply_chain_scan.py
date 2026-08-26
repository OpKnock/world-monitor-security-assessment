"""Supply-chain hygiene module — OpKnock/supply-chain-security-analyzer adapter.

Runs
----
``chainscanner -dir <authorized-source> -format json``

Produces findings for:

* **Typosquat candidates** — packages whose names are suspiciously close
  to well-known libraries (common dependency-confusion vector).
* **Unpinned dependency ratio** — ``unpinned / total > 0.5`` triggers a
  LOW finding (non-reproducible builds).
* **Unknown-license exposure** — informational count of deps with
  missing license metadata.

OS, subprocess and parsing fixes vs the previous adapter

* Binary path uses ``platform.system()`` to pick the correct extension
  (``chainscanner`` vs ``chainscanner.exe``) so the scanner also works
  when the platform runs on Linux containers.
* ``subprocess.TimeoutExpired`` is caught explicitly and mapped to
  ``ScanResult(status="failed")`` instead of bubbling into the worker.
* JSON parsing is banner-tolerant (searches for the first ``{``) and
  validates the resulting shape before indexing into it.
* ``scan_target`` is always set (never empty) and every finding carries
  ``evidence_payloads`` linked to a persisted evidence document.
* ``source_path`` existence is validated early → ``skipped`` when the
  path is missing rather than a cryptic subprocess error.
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

__all__ = ["SupplyChainModule"]

_SUBPROCESS_TIMEOUT_S = 300


class SupplyChainModule(ScannerModule):
    name = "supply_chain"
    category = "DEPENDENCIES"
    description = "Detects typosquat, unpinned and license gaps in the dependency tree"

    def _binary(self) -> str:
        """Resolve chainscanner binary with OS-aware extension."""
        override = getattr(settings, "SUPPLY_CHAIN_SCANNER_BIN", "") or ""
        if isinstance(override, str) and override.strip():
            return override.strip()
        exe = "chainscanner.exe" if platform.system() == "Windows" else "chainscanner"
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

        bin_exists = Path(binary).exists() or shutil.which(binary) is not None
        if not bin_exists:
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=["chainscanner not built (scripts/build_go_tools.ps1) — binary not found at '{}'".format(binary)],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )

        cmd = [binary, "-dir", source, "-format", "json"]
        logger.debug("Running supply-chain scanner: %s", " ".join(f'"{c}"' if " " in c else c for c in cmd))

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
                errors=["chainscanner not built (scripts/build_go_tools.ps1)"],
                checks_total=0,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except subprocess.TimeoutExpired:
            logger.warning("Supply-chain scan timed out after %ss", _SUBPROCESS_TIMEOUT_S)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"chainscanner timed out after {_SUBPROCESS_TIMEOUT_S}s scanning {source}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )
        except Exception as exc:
            logger.exception("Supply-chain subprocess error: %s", exc)
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[repr(exc)],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        stdout = proc.stdout or ""
        stderr_excerpt = (proc.stderr or "")[:600]
        start = stdout.find("{")
        if start == -1:
            logger.warning("Supply-chain scan produced no JSON (exit %s): stdout %r stderr %r", proc.returncode, stdout[:400], stderr_excerpt[:400])
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"no JSON output (exit {proc.returncode}) {stderr_excerpt[:300]}".strip() or "chainscanner produced no JSON output"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        try:
            payload: dict[str, Any] = json.loads(stdout[start:])
        except json.JSONDecodeError as exc:
            logger.warning("Supply-chain JSON parse failed: %s — stdout %r", exc, stdout[start:start + 800])
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"unparseable output: {exc}"],
                checks_total=1,
                duration_s=round(time.perf_counter() - started, 3),
            )

        try:
            store.save_scanner_output("chainscanner", payload, note=f"supply-chain {source}")
        except Exception as exc:
            logger.warning("Failed to persist chainscanner output: %s", exc, exc_info=True)

        # Normalise shape — upstream may return summary at top-level or under
        # a nested key; manifests is always a list.
        summary: dict[str, Any] = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        # Some versions use "Summary" capitalised.
        if not summary and isinstance(payload.get("Summary"), dict):
            summary = payload["Summary"]  # type: ignore[assignment]
        manifests: list[dict[str, Any]] = payload.get("manifests") or payload.get("Manifests") or []
        if not isinstance(manifests, list):
            manifests = []

        deps: list[dict[str, Any]] = []
        for m in manifests:
            if isinstance(m, dict):
                for d in (m.get("dependencies") or m.get("Dependencies") or []):
                    if isinstance(d, dict):
                        deps.append(d)
        # Fallback: some builds emit a flat dependency list at top-level.
        if not deps and isinstance(payload.get("dependencies"), list):
            deps = [d for d in payload["dependencies"] if isinstance(d, dict)]

        total = 0
        try:
            total = int(summary.get("dependencies") or summary.get("total") or len(deps) or 0)
        except (TypeError, ValueError):
            total = len(deps)
        if total == 0:
            total = max(len(deps), 1)

        findings: list[RawFinding] = []

        # ------------------------------------------------------------------
        # Typosquat candidates
        # ------------------------------------------------------------------
        typos = [d for d in deps if d.get("typosquat_hits") or d.get("typosquatHits")]
        if typos:
            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"{len(typos)} typosquat candidates",
                    payload={
                        "candidates": [
                            {"name": t.get("name"), "version": t.get("version"), "hits": t.get("typosquat_hits") or t.get("typosquatHits")}
                            for t in typos
                        ]
                    },
                )
            except Exception as exc:
                logger.debug("Failed to persist typosquat evidence: %s", exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"{len(typos)} typosquat candidates"}
            names = ", ".join(str(t.get("name")) for t in typos[:8])
            findings.append(
                RawFinding(
                    title=f"Typosquat-suspect packages in dependency tree ({len(typos)})",
                    description=(
                        f"Package names closely resemble well-known libraries "
                        f"({names}). Typosquatting is a common supply-chain attack vector."
                    ),
                    severity="HIGH",
                    category=self.category,
                    affected_component=source,
                    scanner=self.name,
                    check_id="supply_chain.typosquat_candidates",
                    scan_target=source,
                    reproduction=[f'{binary} -dir "{source}" -format json'],
                    impact="A mistyped/malicious package can execute arbitrary code at install or runtime.",
                    business_impact="Supply-chain compromise leads to full application takeover.",
                    remediation="Verify each candidate against the canonical package; pin exact versions from trusted registries.",
                    meta={"candidates": [t.get("name") for t in typos]},
                    evidence_payloads=[doc],
                )
            )

        # ------------------------------------------------------------------
        # Unpinned dependency ratio
        # ------------------------------------------------------------------
        unpinned: int | None = None
        for key in ("unpinned", "Unpinned", "unpinned_count"):
            if isinstance(summary.get(key), int):
                unpinned = summary[key]  # type: ignore[assignment]
                break
        # Some builds expose unpinned as part of manifests stats — derive from
        # deps if summary did not include it.
        if unpinned is None and deps:
            # Count deps with a range-like version (caret, tilde, star, etc.).
            range_prefixes = ("^", "~", ">", "<", "*", ">=", "<=")
            try:
                unpinned = sum(1 for d in deps if str(d.get("version") or "").strip().startswith(range_prefixes) or str(d.get("version") or "").strip() == "")
            except Exception:
                unpinned = None

        if isinstance(unpinned, int) and total and unpinned / total > 0.5:
            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"{unpinned}/{total} dependencies unpinned",
                    payload={"summary": summary, "unpinned": unpinned, "total": total},
                )
            except Exception as exc:
                logger.debug("Failed to persist unpinned evidence: %s", exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"{unpinned}/{total} dependencies unpinned"}
            findings.append(
                RawFinding(
                    title=f"{unpinned}/{total} dependencies are not version-pinned",
                    description="Most manifest entries use floating version ranges, so builds are not reproducible and updates enter unreviewed.",
                    severity="LOW",
                    category=self.category,
                    affected_component=source,
                    scanner=self.name,
                    check_id="supply_chain.unpinned_dependencies",
                    scan_target=source,
                    reproduction=[f'{binary} -dir "{source}" -format json'],
                    impact="Non-reproducible builds; a compromised upstream release flows in automatically.",
                    business_impact="Silent supply-chain drift between audits.",
                    remediation="Pin exact versions (or lockfiles) and update via reviewed PRs.",
                    meta={"unpinned": unpinned, "total": total},
                    evidence_payloads=[doc],
                )
            )

        # ------------------------------------------------------------------
        # Unknown-license exposure
        # ------------------------------------------------------------------
        unknown_lic: int | None = None
        for key in ("licenses_unknown", "licensesUnknown", "unknown_licenses", "UnknownLicenses"):
            if isinstance(summary.get(key), int):
                unknown_lic = summary[key]  # type: ignore[assignment]
                break
        if isinstance(unknown_lic, int) and unknown_lic > 0:
            try:
                doc_lic = store.save(
                    kind="scanner_output",
                    summary=f"{unknown_lic} dependencies with unknown/missing license metadata",
                    payload={"summary": summary, "unknown_licenses": unknown_lic},
                )
            except Exception as exc:
                logger.debug("Failed to persist license evidence: %s", exc)
                doc_lic = {"path": "", "kind": "scanner_output", "summary": f"{unknown_lic} unknown licenses"}
            findings.append(
                RawFinding(
                    title=f"{unknown_lic} dependencies with unknown/missing license metadata",
                    description="License obligations cannot be verified for these packages.",
                    severity="INFORMATIONAL",
                    category=self.category,
                    affected_component=source,
                    scanner=self.name,
                    check_id="supply_chain.unknown_licenses",
                    scan_target=source,
                    reproduction=[f'{binary} -dir "{source}" -format json'],
                    impact="Potential licensing-compliance gaps in shipped product.",
                    business_impact="Legal exposure during commercial distribution.",
                    remediation="Audit each package's LICENSE file and record approved licenses.",
                    meta={"unknown_licenses": unknown_lic},
                    evidence_payloads=[doc_lic],
                )
            )

        # ------------------------------------------------------------------
        # Overall risk level from summary (risky but not a finding itself —
        # included as meta for dashboard consumption).
        # ------------------------------------------------------------------
        risk_level = summary.get("risk_level") or summary.get("RiskLevel")
        duration = round(time.perf_counter() - started, 3)
        errors: list[str] = []
        if proc.returncode != 0:
            # Non-zero may still carry valid findings; only add error when no
            # findings were produced to avoid marking partial successes as failed.
            if not findings and proc.returncode not in (0, 1):
                errors.append(f"chainscanner exit={proc.returncode} {stderr_excerpt[:300]}".strip())

        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=max(total, 1),
            checks_safe=max(total - len(findings), 0),
            errors=errors,
            duration_s=duration,
            meta={"risk_level": risk_level, "total": total, "source": source} if risk_level else {"total": total, "source": source},
        )
