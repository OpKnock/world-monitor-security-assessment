import importlib.util
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_deep_scan_and_fuzzing_modules(client, analyst_headers, lab_server):
    """zdv modules complete against the live lab and map real findings."""
    r = client.post("/api/assessments", json={
        "target": f"{lab_server['url']}/",
        "modules": ["deep_scan", "fuzzing"],
        "authorized": True}, headers=analyst_headers)
    assert r.status_code == 201
    aid = r.json()["id"]
    for _ in range(90):
        d = client.get(f"/api/assessments/{aid}", headers=analyst_headers).json()
        if d["status"] in ("completed", "failed"):
            break
        time.sleep(1)
    assert d["status"] == "completed", d["scan_runs"]
    checks = {f["check_id"] for f in
              client.get(f"/api/assessments/{aid}/findings", headers=analyst_headers).json()}
    # the lab leaks version banner 'WorldMonitor-Lab/0.9-flask' + open port + headers
    assert any(c.startswith("deep_scan.") for c in checks), checks
