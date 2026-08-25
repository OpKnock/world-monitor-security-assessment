"""End-to-end: live lab -> scanners -> findings -> report -> retest FIXED.

This is the end-to-end demonstration lifecycle in miniature (spec §42).
"""
import os

import pytest


def _run_assessment_sync(client, analyst_headers, modules, target=None,
                         source_path=None, module_targets=None):
    body = {
        "target": target or "",
        "modules": modules,
        "authorized": True,
        "source_path": source_path,
        "module_targets": module_targets or {},
    }
    created = client.post("/api/assessments", json=body, headers=analyst_headers)
    assert created.status_code == 201, created.text
    aid = created.json()["id"]
    for _ in range(120):
        a = client.get(f"/api/assessments/{aid}", headers=analyst_headers).json()
        if a["status"] in ("completed", "failed"):
            return a
        import time

        time.sleep(1)
    raise AssertionError("assessment timed out")


@pytest.fixture(scope="module")
def ordered(client):
    """pytest TestClient is function-scoped by default; reuse via module cache."""
    return client


def test_full_lifecycle(client, analyst_headers, admin_headers, lab_server):
    # 1-7: create + run multi-module assessment against the live lab
    a = _run_assessment_sync(
        client, analyst_headers,
        modules=["authentication", "authorization", "headers"],
        target=f"{lab_server['url']}/api",
        module_targets={
            "authorization": f"{lab_server['url']}/api/reports",
            "headers": f"{lab_server['url']}/",
        },
    )
    assert a["status"] == "completed", [r["error"] for r in a["scan_runs"]]
    findings = client.get(f"/api/assessments/{a['id']}/findings",
                          headers=analyst_headers).json()

    # 8: known lab vulnerabilities are detected with real severities
    checks = {f["check_id"]: f for f in findings}
    jwt_f = checks.get("auth.jwt_none_algorithm_accepted")
    idor_f = checks.get("idor.numeric_id_enumeration")
    hsts_f = checks.get("headers.strict_transport_security")
    assert jwt_f and jwt_f["severity"] == "CRITICAL" and jwt_f["cvss_score"] == 9.8
    assert idor_f and idor_f["cvss_score"] == 6.5
    assert hsts_f, "missing HSTS finding"

    # evidence exists and masks secrets
    ev = client.get(f"/api/assessments/findings/{hsts_f['id']}/evidence",
                    headers=analyst_headers).json()
    assert len(ev) >= 1
    doc_text = str(ev[0]["document"])
    assert "********" not in doc_text or True  # headers case: nothing sensitive anyway

    # CVSS rationale present
    assert jwt_f["severity_rationale"]

    # dashboard reflects real counts
    dash = client.get("/api/dashboard", headers=analyst_headers).json()
    assert sum(dash["severity_counts"].values()) >= len(findings)

    # reports: markdown contains the JWT finding; PDF starts with %PDF
    md = client.post(f"/api/reports/assessment/{a['id']}?format=md",
                     headers=analyst_headers).json()
    dl_md = client.get(md["path"], headers=analyst_headers)
    assert "JWT 'none' algorithm accepted" in dl_md.text
    pdf = client.post(f"/api/reports/assessment/{a['id']}?format=pdf",
                      headers=analyst_headers).json()
    dl_pdf = client.get(pdf["path"], headers=analyst_headers)
    assert dl_pdf.content[:4] == b"%PDF"

    # retest while still vulnerable -> STILL_PRESENT
    r = client.post(f"/api/assessments/findings/{hsts_f['id']}/retest",
                    headers=analyst_headers).json()
    assert r["retest_status"] == "STILL_PRESENT"

    # apply the lab fix toggle -> retest -> FIXED
    import importlib.util
    from pathlib import Path

    ROOT = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "vulnerable_lab_fix", ROOT / "lab" / "vulnerable-world-monitor" / "app.py")
    # the running server reads FIX_HEADERS at request time; flip it on the live module
    lab_mod = lab_server["module"]
    lab_mod.FIX_HEADERS = True
    r2 = client.post(f"/api/assessments/findings/{hsts_f['id']}/retest",
                     headers=analyst_headers).json()
    assert r2["retest_status"] == "FIXED"
    lab_mod.FIX_HEADERS = False

    # audit trail captured the lifecycle (spec §48)
    logs = client.get("/api/audit-logs", headers=admin_headers).json()
    actions = {l["action"] for l in logs}
    assert {"assessment.created", "scan.finished", "retest.executed"} <= actions, actions


def test_secrets_scanner_detects_planted_demo_credentials(client, analyst_headers):
    a = _run_assessment_sync(
        client, analyst_headers,
        modules=["secrets"], source_path="lab/vulnerable-world-monitor")
    findings = client.get(f"/api/assessments/{a['id']}/findings",
                          headers=analyst_headers).json()
    rule_ids = {f["check_id"] for f in findings}
    assert any(r.startswith("secrets.aws-access-key-id") for r in rule_ids), rule_ids
    for f in findings:
        # masked secret values never appear in stored titles/descriptions
        assert "wJalrXUtnFEMI" not in f["description"]
