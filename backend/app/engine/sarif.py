"""SARIF 2.1.0 output — exports findings for CI/CD integration."""
import json
import hashlib
from datetime import datetime, timezone
from typing import Any

SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "note",
}

def to_sarif(findings: list, assessment_id: str = "") -> dict:
    """Convert findings to SARIF 2.1.0 format."""
    results = []
    for f in findings:
        rule_id = getattr(f, "check_id", "") or getattr(f, "id", "")
        message = getattr(f, "title", "") or getattr(f, "description", "")
        severity = getattr(f, "severity", "MEDIUM")
        level = SEVERITY_TO_LEVEL.get(severity, "warning")
        
        # Location info
        file_path = getattr(f, "affected_component", "") or getattr(f, "file", "") or "unknown"
        line_start = getattr(f, "line_start", None) or getattr(f, "lineStart", None)
        line_end = getattr(f, "line_end", None) or getattr(f, "lineEnd", None)
        
        locations = []
        if file_path and file_path != "unknown":
            loc: dict = {"physicalLocation": {"artifactLocation": {"uri": file_path}}}
            if line_start:
                loc["physicalLocation"]["region"] = {"startLine": int(line_start)}
                if line_end:
                    loc["physicalLocation"]["region"]["endLine"] = int(line_end)
            locations.append(loc)
        
        # Fingerprint for deduplication
        fingerprint = getattr(f, "fingerprint", "") or hashlib.sha256(
            f"{rule_id}|{file_path}|{line_start}".encode()
        ).hexdigest()[:32]
        
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": locations,
            "partialFingerprints": {"findingFingerprint": fingerprint},
            "properties": {
                "severity": severity,
                "category": getattr(f, "category", ""),
                "scanner": getattr(f, "scanner", ""),
                "cvssScore": getattr(f, "cvss_score", None),
                "cvssVector": getattr(f, "cvss_vector", ""),
                "cwe": getattr(f, "cwe", []),
                "cve": getattr(f, "cve", []),
                "status": getattr(f, "status", "OPEN"),
                "lifecycle": getattr(f, "lifecycle", "NEW"),
            },
        })
    
    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "world-monitor",
                    "version": "1.0",
                    "informationUri": "https://github.com/OpKnock/world-monitor-security-assessment",
                    "rules": [{"id": r["ruleId"], "name": r["ruleId"], "shortDescription": {"text": r["message"]["text"][:100]}} for r in results],
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }]
    }

def to_sarif_json(findings: list, assessment_id: str = "") -> str:
    return json.dumps(to_sarif(findings, assessment_id), indent=2)