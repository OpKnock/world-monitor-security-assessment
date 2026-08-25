"""Delete/cascade system: findings, assessments, reports + audit purge."""
import time


def _wait(client, aid, H):
    for _ in range(90):
        d = client.get(f"/api/assessments/{aid}", headers=H).json()
        if d["status"] in ("completed", "failed"):
            return d
        time.sleep(1)
    raise AssertionError("timeout")


def test_delete_finding_and_assessment_cascade(client, analyst_headers, lab_server):
    r = client.post("/api/assessments", json={
        "target": f"{lab_server['url']}/",
        "modules": ["headers"], "authorized": True}, headers=analyst_headers)
    assert r.status_code == 201
    aid = r.json()["id"]
    d = _wait(client, aid, analyst_headers)
    assert d["status"] == "completed"
    fs = client.get(f"/api/assessments/{aid}/findings", headers=analyst_headers).json()
    assert len(fs) >= 1

    # viewer cannot delete
    vr = client.post("/api/auth/register", json={
        "email": "delviewer@example.com", "password": "Viewer_Pass_1"})
    assert vr.status_code == 201, vr.text
    vH = {"Authorization": f"Bearer {vr.json()['access_token']}"}
    assert client.delete(f"/api/findings/{fs[0]['id']}",
                         headers=vH).status_code == 403

    # delete one finding -> gone everywhere
    fid = fs[0]["id"]
    assert client.delete(f"/api/findings/{fid}",
                         headers=analyst_headers).status_code == 200
    rest = client.get(f"/api/assessments/{aid}/findings", headers=analyst_headers).json()
    assert all(x["id"] != fid for x in rest)

    # generate a stored report then delete the whole assessment
    rp = client.post(f"/api/reports/assessment/{aid}?format=json",
                     headers=analyst_headers).json()
    assert client.get(rp["path"], headers=analyst_headers).status_code == 200
    assert client.delete(f"/api/assessments/{aid}",
                         headers=analyst_headers).status_code == 200
    assert client.get(f"/api/assessments/{aid}",
                      headers=analyst_headers).json()["detail"] == "assessment not found"
    assert client.get(rp["path"], headers=analyst_headers).status_code == 404

    # audit trail: deletions recorded, purged rows for the removed entities are gone
    logs = client.get("/api/audit-logs", headers={"Authorization": "Bearer " +
                      _admin_token(client)}).json()
    actions = {l["action"] for l in logs}
    assert {"assessment.deleted", "finding.deleted"} <= actions, actions
    assert "report.generated" not in actions, (
        "audit rows referencing deleted reports must be purged too")


def _admin_token(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "ChangeMe_Admin_2026!"})
    return r.json()["access_token"]
