"""Supply-chain hygiene module — OpKnock/supply-chain-security-analyzer adapter.

Runs:  chainscanner -dir <authorized-source> -format json
Produces findings for typosquat candidates, high-risk packages, unpinned
dependency ratio and unknown-license exposure.
"""
from __future__ import annotations

import json
import subprocess

from ..config import settings
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule


class SupplyChainModule(ScannerModule):
    name = "supply_chain"
    category = "DEPENDENCIES"

    def _binary(self) -> str:
        return str(settings.BIN_DIR / "chainscanner.exe")

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        binary = self._binary()
        source = ctx.source_path or str(settings.LAB_SOURCE_DIR)
        cmd = [binary, "-dir", source, "-format", "json"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=300, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ScanResult(scanner=self.name, status="skipped",
                              errors=["chainscanner not built (scripts/build_go_tools.ps1)"])

        start = proc.stdout.find("{")
        if start == -1:
            return ScanResult(scanner=self.name, status="failed",
                              errors=[f"no JSON output (exit {proc.returncode}) {proc.stderr[:150]}"])
        try:
            payload = json.loads(proc.stdout[start:])
        except json.JSONDecodeError as exc:
            return ScanResult(scanner=self.name, status="failed",
                              errors=[f"unparseable output: {exc}"])

        store.save_scanner_output("chainscanner", payload, note=f"supply-chain {source}")
        summary = payload.get("summary", {})
        manifests = payload.get("manifests") or []
        deps = [d for m in manifests for d in (m.get("dependencies") or [])]

        findings: list[RawFinding] = []

        typos = [d for d in deps if d.get("typosquat_hits")]
        if typos:
            doc = store.save(kind="scanner_output",
                             summary=f"{len(typos)} typosquat candidates",
                             payload={"candidates": [
                                 {"name": t.get("name"), "version": t.get("version"),
                                  "hits": t.get("typosquat_hits")} for t in typos]})
            names = ", ".join(str(t.get("name")) for t in typos[:8])
            findings.append(RawFinding(
                title=f"Typosquat-suspect packages in dependency tree ({len(typos)})",
                description=(
                    f"Package names closely resemble well-known libraries "
                    f"({names}). Typosquatting is a common supply-chain attack vector."
                ),
                severity="HIGH", category=self.category,
                affected_component=source, scanner=self.name,
                check_id="supply_chain.typosquat_candidates",
                reproduction=[f"{binary} -dir \"{source}\" -format json"],
                impact="A mistyped/malicious package can execute arbitrary code at install or runtime.",
                business_impact="Supply-chain compromise leads to full application takeover.",
                remediation="Verify each candidate against the canonical package; pin exact versions from trusted registries.",
                meta={"candidates": [t.get("name") for t in typos]},
                evidence_payloads=[doc],
            ))

        unpinned = summary.get("unpinned")
        total = summary.get("dependencies") or len(deps)
        if isinstance(unpinned, int) and total and unpinned / total > 0.5:
            doc = store.save(kind="scanner_output",
                             summary=f"{unpinned}/{total} dependencies unpinned",
                             payload={"summary": summary})
            findings.append(RawFinding(
                title=f"{unpinned}/{total} dependencies are not version-pinned",
                description="Most manifest entries use floating version ranges, so builds are not reproducible and updates enter unreviewed.",
                severity="LOW", category=self.category,
                affected_component=source, scanner=self.name,
                check_id="supply_chain.unpinned_dependencies",
                reproduction=[f"{binary} -dir \"{source}\" -format json"],
                impact="Non-reproducible builds; a compromised upstream release flows in automatically.",
                business_impact="Silent supply-chain drift between audits.",
                remediation="Pin exact versions (or lockfiles) and update via reviewed PRs.",
                meta={"unpinned": unpinned, "total": total},
                evidence_payloads=[doc],
            ))

        unknown_lic = summary.get("licenses_unknown")
        if isinstance(unknown_lic, int) and unknown_lic:
            findings.append(RawFinding(
                title=f"{unknown_lic} dependencies with unknown/missing license metadata",
                description="License obligations cannot be verified for these packages.",
                severity="INFORMATIONAL", category=self.category,
                affected_component=source, scanner=self.name,
                check_id="supply_chain.unknown_licenses",
                reproduction=[f"{binary} -dir \"{source}\" -format json"],
                impact="Potential licensing-compliance gaps in shipped product.",
                business_impact="Legal exposure during commercial distribution.",
                remediation="Audit each package's LICENSE file and record approved licenses.",
            ))

        risk_level = summary.get("risk_level")
        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=max(total, 1),
            checks_safe=max(total - len(findings), 0),
            errors=[] if proc.returncode == 0 else [f"exit={proc.returncode}"],
        )
