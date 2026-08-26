"""FULL LIVE VERIFICATION - all targets, all modules, all operations."""
import json, sys, time
sys.path.insert(0, r"C:\Users\wagde\Desktop\world-monitor-security-assessment")
import httpx

BASE = "http://127.0.0.1:8000/api"
c = httpx.Client(timeout=60)
t = c.post(f"{BASE}/auth/login", json={"email": "admin@example.com", "password": "admin"}).json()["access_token"]
c.headers["Authorization"] = f"Bearer {t}"
lab_tok = c.post(f"{BASE}/lab/token").json()["access_token"]

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" | {detail}" if detail and not cond else ""))

# ── 1. Run all three targets ──
targets = [
    ("REAL APP", {"target": "http://127.0.0.1:3000",
                  "modules": ["authentication", "api", "headers", "tls", "deep_scan"],
                  "authorized": True}, 60),
    ("PLAYGROUND", {"target": "http://127.0.0.1:8080/api",
                    "modules": ["authentication", "authorization", "api", "input_validation", "headers"],
                    "authorized": True, "auth_token": lab_tok,
                    "module_targets": {
                        "authorization": "http://127.0.0.1:8080/api/reports",
                        "api": "http://127.0.0.1:8080/api/monitor",
                        "sqli": "http://127.0.0.1:8080/api/search?id=1",
                        "input_validation": "http://127.0.0.1:8080/greet"}}, 90),
    ("REAL SOURCE", {"target": "(source-static)",
                     "modules": ["secrets", "dependencies", "supply_chain"],
                     "authorized": True,
                     "source_path": "targets/real-world-monitor"}, 120),
]

results = {}
for name, body, timeout in targets:
    aid = c.post(f"{BASE}/assessments", json=body).json()["id"]
    for _ in range(timeout // 3):
        time.sleep(3)
        d = c.get(f"{BASE}/assessments/{aid}").json()
        if d["status"] in ("completed", "failed"):
            break
    total = sum(d["severity_counts"].values())
    failed_runs = [r["scanner"] for r in d["scan_runs"] if r["status"] == "failed"]
    check(f"{name}: completed", d["status"] == "completed",
          f"status={d['status']} failed_runs={failed_runs}")
    check(f"{name}: has findings", total > 0, f"total={total}")
    results[name] = {"aid": aid, "findings": total, "data": d}
    print(f"         -> {total} findings, {len(d['scan_runs'])} modules")

# ── 2. Dashboard consistency ──
dash = c.get(f"{BASE}/dashboard").json()
total_dash = sum(dash["severity_counts"].values())
expected_total = sum(r["findings"] for r in results.values())
check("Dashboard: total matches", dash["total_findings"] == total_dash,
      f"dash={dash['total_findings']} expected={total_dash}")
check("Dashboard: has categories", len(dash["categories"]) > 0)

# ── 3. Findings detail page loads ──
first_aid = list(results.values())[0]["aid"]
fs = c.get(f"{BASE}/assessments/{first_aid}/findings").json()
if fs:
    fid = fs[0]["id"]
    detail = c.get(f"{BASE}/assessments/findings/{fid}")
    check("Finding detail: loads by ID", detail.status_code == 200)
    ev = c.get(f"{BASE}/assessments/findings/{fid}/evidence")
    check("Finding evidence: loads", ev.status_code == 200)

# ── 4. Reports: all 4 formats ──
for fmt in ("pdf", "json", "md", "csv"):
    rp = c.post(f"{BASE}/reports/assessment/{first_aid}?format={fmt}").json()
    dl = c.get(f"{BASE}{rp['path']}" if not rp["path"].startswith("http") else rp["path"])
    if fmt == "pdf":
        check(f"Report {fmt}: PDF magic", dl.content[:4] == b"%PDF")
    elif fmt == "json":
        j = json.loads(dl.text)
        check(f"Report {fmt}: valid JSON with findings", len(j.get("findings", [])) > 0)
    elif fmt == "csv":
        check(f"Report {fmt}: has header row", "title" in dl.text.splitlines()[0])
    else:
        check(f"Report {fmt}: has content", len(dl.text) > 100)

# ── 5. Delete cascade ──
del_aid = list(results.values())[0]["aid"]
fs_before = c.get(f"{BASE}/assessments/{del_aid}/findings").json()
if fs_before:
    fid = fs_before[0]["id"]
    r = c.delete(f"{BASE}/findings/{fid}")
    check("Delete finding: 200", r.status_code == 200)
    after = c.get(f"{BASE}/assessments/{del_aid}/findings").json()
    check("Delete finding: gone from list", all(x["id"] != fid for x in after))

# delete assessment
rp = c.post(f"{BASE}/reports/assessment/{del_aid}?format=md").json()
r = c.delete(f"{BASE}/assessments/{del_aid}")
check("Delete assessment: 200", r.status_code == 200)
check("Delete assessment: 404 after", c.get(f"{BASE}/assessments/{del_aid}").status_code == 404)
check("Report 404 after assessment delete", c.get(f"{BASE}{rp['path']}").status_code == 404)

# ── 6. Audit trail has deletions ──
logs = c.get(f"{BASE}/audit-logs").json()
actions = {l["action"] for l in logs}
check("Audit: has deletion records", "assessment.deleted" in actions or "finding.deleted" in actions)

# ── 7. RBAC ──
vr = c.post(f"{BASE}/auth/register", json={"email": f"v{time.time():.0f}@example.com", "password": "Viewer_Pass_1"})
vH = {"Authorization": f"Bearer {vr.json()['access_token']}"}
check("RBAC: viewer can't create assessment",
      c.post(f"{BASE}/assessments", json={"target": "http://127.0.0.1:8080", "modules": ["headers"], "authorized": True}, headers=vH).status_code == 403)
check("RBAC: viewer can't delete",
      c.delete(f"{BASE}/reports/00000000000000000000000000000000", headers=vH).status_code == 403)

# ── 8. Gate ──
check("Gate: public target refused",
      c.post(f"{BASE}/assessments", json={"target": "https://evil.example.com", "modules": ["headers"], "authorized": True}).status_code == 403)
check("Gate: unauthorized refused",
      c.post(f"{BASE}/assessments", json={"target": "http://127.0.0.1:8080", "modules": ["headers"], "authorized": False}).status_code == 403)

# ── FINAL ──
print(f"\n{'='*60}")
print(f"RESULTS: {len(PASS)} PASSED, {len(FAIL)} FAILED")
if FAIL:
    print("FAILURES:")
    for f in FAIL:
        print(f"  -> {f}")
    sys.exit(1)
else:
    print("ALL CHECKS PASSED - SYSTEM IS FULLY OPERATIONAL")
