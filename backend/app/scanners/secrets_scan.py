"""Secrets module — OpKnock/secrets-scanner ("portia") subprocess adapter.

Runs:  portia scan <authorized-source-path> --format json
The upstream tool masks secret values before emitting JSON, so evidence stays
safe by construction.
"""
from __future__ import annotations

import json
import subprocess

from ..config import settings
from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule

SEVERITY_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


class SecretsModule(ScannerModule):
    name = "secrets"
    category = "DATA_PRIVACY"

    def _binary(self) -> str:
        return settings.SECRETS_SCANNER_BIN or str(settings.BIN_DIR / "portia.exe")

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        binary = self._binary()
        source = ctx.source_path or str(settings.LAB_SOURCE_DIR)
        cmd = [binary, "scan", source, "--format", "json", "--no-color"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return ScanResult(
                scanner=self.name,
                status="skipped",
                errors=[
                    f"portia binary not found at '{binary}'. Build it: scripts/build_go_tools.ps1"
                ],
            )
        try:
            # portia prints a decorative banner before the JSON document;
            # parse from the first '{' to stay robust against banner changes
            raw = proc.stdout or ""
            payload = json.loads(raw[raw.index("{"):])
        except (json.JSONDecodeError, ValueError):
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=[f"Unparseable output (exit {proc.returncode}): {proc.stderr[:400]}"],
            )
        store.save_scanner_output("portia", payload, note=f"portia scan {source}")
        findings: list[RawFinding] = []
        for item in payload.get("findings", []):
            rule_id = str(item.get("rule_id") or "unknown")
            severity = SEVERITY_MAP.get(str(item.get("severity", "")).upper(), "HIGH")
            file_path = str(item.get("file") or "")
            line_no = int(item.get("line") or 0)
            doc = store.save_file_match(file_path, line_no,
                                        str(item.get("description", ""))[:400], rule_id)
            findings.append(RawFinding(
                title=f"Hardcoded credential pattern '{rule_id}' committed in scanned source",
                description=str(item.get("description") or f"Rule {rule_id} matched {file_path}:{line_no}."),
                severity=severity,
                category=self.category,
                affected_component=f"{file_path}:{line_no}",
                scanner=self.name,
                check_id=f"secrets.{rule_id}",
                reproduction=[
                    f"{binary} scan \"{source}\" --format json",
                    f"Observe match for rule {rule_id} at line {line_no} (secret masked in evidence).",
                ],
                impact=(
                    "Anyone with repository access gains working credentials; "
                    "rotation is required once leaked."
                ),
                business_impact="Exposed keys allow direct impersonation of the service against third-party systems.",
                remediation="Move the value to a secret manager / environment config and rotate it.",
                references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                meta={"rule_id": rule_id, "entropy": item.get("entropy")},
                scan_target=source,
                evidence_payloads=[doc],
            ))
        summary = payload.get("summary", {})
        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=1, checks_safe=1 if not findings else 0,
                          errors=[] if proc.returncode in (0, 1) else [f"exit={proc.returncode} {proc.stderr[:200]}"])
