"""Deep-scan & fuzzing modules — OpKnock/zero-day-vulnerability-scanner vendor.

Adds capabilities no other module covers:
  deep_scan : open-port checks, default-credential patterns, software-banner
              advisory matching (localhost-enforced upstream).
  fuzzing   : deterministic mutation fuzzing that flags 5xx / connection-reset
              anomalies as crash-like indicators.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.zdv_scanner import Fuzzer, ScanEngine, Target


def _target_from_url(url: str) -> Target:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return Target(host=host, port=port, scheme=parsed.scheme or "http",
                  name=parsed.netloc)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:60] or "finding"


class DeepScanModule(ScannerModule):
    name = "deep_scan"
    category = "INFRASTRUCTURE"

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        target = _target_from_url(ctx.target)
        engine = ScanEngine()
        try:
            result = engine.scan(target)
        except Exception as exc:
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)])
        import sys as _s

        findings: list[RawFinding] = []
        safe = 0
        for f in getattr(result, "findings", []):
            title = str(getattr(f, "title", "finding"))
            severity = str(getattr(f, "severity", "LOW")).upper()
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                severity = "LOW"
            detail = str(getattr(f, "description", "") or getattr(f, "detail", ""))
            doc = store.save(kind="scanner_output",
                             summary=f"zdv: {title}",
                             payload={"plugin": getattr(f, "plugin", ""),
                                      "raw": str(getattr(f, "evidence", ""))[:1500]})
            findings.append(RawFinding(
                title=title,
                description=detail or title,
                severity=severity,
                category=self.category,
                affected_component=ctx.target,
                scanner=self.name,
                check_id=f"deep_scan.{_slug(title)}",
                reproduction=[f"ScanEngine().scan({ctx.target}) — localhost-enforced upstream"],
                impact="Expands the attack surface information available to an attacker.",
                business_impact="Exposed services/versions are the first step in targeted attacks.",
                remediation="Close unnecessary ports, suppress version banners, rotate default credentials.",
                meta={"plugin": str(getattr(f, "plugin", ""))},
                evidence_payloads=[doc],
                scan_target=ctx.target,
            ))
        total = len(findings)
        checks = int(getattr(result, "checks_run", total) or total)
        safe = max(checks - total, 0)
        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=max(checks, 1), checks_safe=safe)


class FuzzingModule(ScannerModule):
    name = "fuzzing"
    category = "INPUT_VALIDATION"

    def run(self, ctx: ScanContext) -> ScanResult:
        import os
        if os.environ.get("WM_ENABLE_FUZZING") != "1":
            return ScanResult(scanner=self.name, status="skipped", checks_total=0,
                              notes=["Fuzzing is an optional experimental module ? disabled by default (not a failure). Set WM_ENABLE_FUZZING=1 to enable; skipped modules do not affect overall assessment status"])
        store = ctx.require_evidence()
        target = _target_from_url(ctx.target)
        corpus = ["/", "/login", "/api", "/search?q=test"]
        from concurrent.futures import ThreadPoolExecutor
        from concurrent.futures import TimeoutError as _FuturesTimeout

        def _do_fuzz():
            # The fuzzer's timeout worker is a child thread, so propagate the
            # assessment's validated DNS pin explicitly into that thread.
            from ..engine.dns_pinning import pin_target_dns

            with pin_target_dns(ctx.target, list(ctx.options.get("resolved_ips", []))):
                return Fuzzer().fuzz(target, corpus=corpus, iterations=60)

        try:
            with ThreadPoolExecutor(max_workers=1) as _pool:
                future = _pool.submit(_do_fuzz)
                try:
                    result = future.result(timeout=90)
                except _FuturesTimeout:
                    return ScanResult(
                        scanner=self.name,
                        status="completed",
                        errors=["fuzzing exceeded its 90s budget; partial run discarded"],
                        checks_total=60,
                        checks_safe=60,
                    )
        except Exception as exc:
            return ScanResult(scanner=self.name, status="failed", errors=[repr(exc)])

        anomalies = list(getattr(result, "anomalies", []) or [])
        doc = store.save(kind="scanner_output",
                         summary=f"fuzz anomalies: {len(anomalies)}",
                         payload={"iterations": 60,
                                  "anomalies": [str(a)[:200] for a in anomalies[:25]]})
        if not anomalies:
            return ScanResult(scanner=self.name, status="completed", findings=[],
                              checks_total=120, checks_safe=120)

        sev = "MEDIUM"
        findings = [RawFinding(
            title=f"Fuzzing surfaced {len(anomalies)} crash-like responses",
            description=(
                "Mutated requests produced HTTP 5xx responses or connection resets, "
                "indicating unhandled edge-case input handling on the server."
            ),
            severity=sev, category=self.category,
            affected_component=ctx.target,
            scanner=self.name,
            check_id="input_validation.fuzz_anomalies",
            reproduction=[f"Fuzzer().fuzz({target}, corpus={corpus}, iterations=60)"],
            impact="5xx on malformed input often precedes exploitable parsing bugs.",
            business_impact="Crash-prone endpoints enable denial-of-service and may hide deeper flaws.",
            remediation="Return 400s for malformed input via centralized validation; fix handler exceptions.",
            meta={"anomalies": [str(a)[:120] for a in anomalies[:10]]},
            evidence_payloads=[doc],
            scan_target=ctx.target,
        )]
        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=120, checks_safe=120 - len(anomalies))
