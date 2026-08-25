"""Dependencies module — OpKnock/sbom-generator-vulnerability-matcher ("bomber").

Runs:  bomber vuln <authorized-project-dir> --format json
Upstream marshals Go iota enums as integers; this adapter maps them:
  Ecosystem: 0=go, 1=node, 2=python
  Severity : 0=NONE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..config import settings
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule

ECOSYSTEMS = {0: "go", 1: "node", 2: "python"}
SEVERITIES = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class DependenciesModule(ScannerModule):
    name = "dependencies"
    category = "DEPENDENCIES"

    def _binary(self) -> str:
        return settings.SBOM_SCANNER_BIN or str(settings.BIN_DIR / "bomber.exe")

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        binary = self._binary()
        source = ctx.source_path or str(settings.LAB_SOURCE_DIR)
        if not Path(source).exists():
            return ScanResult(scanner=self.name, status="skipped",
                              errors=[f"source path does not exist: {source}"])
        cmd = [binary, "vuln", source, "--format", "json"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[
                    f"bomber binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1"
                ],
            )
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, status="failed",
                              errors=[f"Unparseable output (exit {proc.returncode}): {proc.stderr[:400]}"])

        store.save_scanner_output("bomber", payload, note=f"bomber vuln {source}")

        findings: list[RawFinding] = []
        vulns_raw = payload.get("vulnerabilities") or {}
        vulns = vulns_raw.get("Matches") or vulns_raw.get("matches") or []
        # ---- enrich severities from OSV (bomber collapses unknown labels to 0) ----
        osv_severity: dict[str, tuple[str | None, str | None, float | None]] = {}
        try:
            import httpx

            ids = [str(m.get("Vulnerability", {}).get("ID") or "") for m in vulns]
            with httpx.Client(timeout=8.0) as hc:
                for vid in dict.fromkeys(i for i in ids if i):
                    try:
                        vr = hc.get(f"https://api.osv.dev/v1/vulns/{vid}")
                        if vr.status_code != 200:
                            continue
                        vj = vr.json()
                        sev_name = None
                        vec = None
                        score = None
                        for s in vj.get("severity", []):
                            if s.get("type") == "CVSS_V3":
                                vec = s.get("score")
                        db_spec = vj.get("database_specific", {}) or {}
                        sev_name = (db_spec.get("severity") or "").upper() or None
                        cvss_base = (vj.get("cvss") or {})
                        if isinstance(cvss_base, dict):
                            score = cvss_base.get("score")
                        if vec and not score:
                            try:
                                import cvss as _cvss
                                score = _cvss.CVSS3(vec).base_score
                            except Exception:
                                score = None
                        label = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(
                            sev_name or "", sev_name)
                        if label:
                            osv_severity[vid] = (label, vec, float(score) if score else None)
                    except Exception:
                        continue
        except Exception:
            pass
        for match in vulns:
            pkg = match.get("Package", {})
            vuln = match.get("Vulnerability", {})
            cve = str(vuln.get("ID") or "UNKNOWN")
            sev_int = int(vuln.get("Severity", 0))
            severity = SEVERITIES.get(sev_int)
            olabel, ovec, oscore = osv_severity.get(cve, (None, None, None))
            if olabel:
                severity = olabel
            if not severity:
                severity = "LOW"
            eco = ECOSYSTEMS.get(int(pkg.get("Ecosystem", -1)), "unknown")
            name = str(pkg.get("Name", "?"))
            version = str(pkg.get("Version", "?"))
            fix_version = str(vuln.get("FixVersion") or "")
            doc = store.save(
                kind="scanner_output",
                summary=f"{cve} on {name}@{version}",
                payload={"match": match},
            )
            findings.append(RawFinding(
                title=f"Vulnerable dependency: {name}@{version} ({cve})",
                description=str(vuln.get("Summary") or f"{cve} affects {name} {version}."),
                severity=severity,
                category=self.category,
                affected_component=f"{eco}:{name}@{version}",
                scanner=self.name,
                check_id=f"dependencies.{cve}",
                reproduction=[f"{binary} vuln \"{source}\" --format json"],
                impact=f"A known vulnerability in a shipped library is reachable from the application.",
                business_impact="Known-exploitable CVEs are the easiest initial-access path for attackers.",
                remediation=(f"Upgrade {name} to {fix_version}" if fix_version
                             else f"Upgrade or replace {name}; no fixed version published yet."),
                references=[f"https://osv.dev/vulnerability/{cve}", *(["https://github.com/advisories"] if not fix_version else [])],
                cvss_vector=ovec,
                meta={"cvss_score": oscore or vuln.get("Score"), "aliases": vuln.get("Aliases"),
                      "purl": pkg.get("PURL"), "direct": pkg.get("Direct")},
                scan_target=source,
                evidence_payloads=[doc],
            ))
        total_pkgs = ((vulns_raw.get("TotalPkgs"))
                      or (payload.get("scan") or {}).get("TotalPkgs") or 0)
        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=max(total_pkgs, 1),
                          checks_safe=max(total_pkgs - len(findings), 0),
                          errors=[] if proc.returncode == 0 else [f"exit={proc.returncode} {proc.stderr[:200]}"])
