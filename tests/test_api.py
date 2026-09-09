"""Platform API: auth, RBAC, gate refusals, scanner metadata."""
import pytest


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["lab_mode"] is True


def test_register_login_me(client):
    r = client.post("/api/auth/register", json={
        "email": "analyst1@example.com", "password": "AnalystPass_123"})
    assert r.status_code == 201
    assert r.json()["role"] == "analyst"
    tok = r.json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.json()["role"] == "analyst"


def test_registration_disabled_rejected(client, monkeypatch):
    from backend.app.config import settings
    monkeypatch.setattr(settings, "REGISTRATION_ENABLED", False)
    r = client.post("/api/auth/register", json={
        "email": "nobody@example.com", "password": "NobodyPass_123"})
    assert r.status_code == 403


def test_duplicate_register_rejected(client):
    body = {"email": "dup@example.com", "password": "Whatever_123"}
    assert client.post("/api/auth/register", json=body).status_code == 201
    assert client.post("/api/auth/register", json=body).status_code == 409


def test_weak_password_rejected(client):
    r = client.post("/api/auth/register", json={
        "email": "weak@example.com", "password": "short"})
    assert r.status_code == 422


def test_assessment_requires_auth(client):
    assert client.post("/api/assessments", json={
        "target": "http://127.0.0.1/x", "modules": ["headers"],
        "authorized": True}).status_code == 401


def test_viewer_cannot_create_assessment(client, analyst_headers, viewer_headers):
    # viewer role lacks analyst rights -> 403 on writes
    assert client.post("/api/assessments", json={
        "target": "http://127.0.0.1/x", "modules": ["headers"], "authorized": True},
        headers=viewer_headers).status_code == 403


def test_viewer_can_read(client, analyst_headers, viewer_headers):
    # viewer role can read assessments, findings, reports, settings
    assert client.get("/api/assessments?limit=5", headers=viewer_headers).status_code == 200
    assert client.get("/api/assessments/-/findings?limit=5",
                      headers=viewer_headers).status_code == 200
    assert client.get("/api/settings", headers=viewer_headers).status_code == 200
    assert client.get("/api/scanners", headers=viewer_headers).status_code == 200
    assert client.get("/api/dashboard", headers=viewer_headers).status_code == 200


def test_unconfirmed_authorization_refused(client, analyst_headers):
    r = client.post("/api/assessments", json={
        "target": "http://127.0.0.1:8080/api", "modules": ["headers"],
        "authorized": False}, headers=analyst_headers)
    assert r.status_code == 403 and "authorized" in r.json()["detail"].lower()


def test_public_target_refused_by_gate(client, analyst_headers):
    r = client.post("/api/assessments", json={
        "target": "https://scanning-not-allowed.example.com",
        "modules": ["headers"], "authorized": True}, headers=analyst_headers)
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert ("LAB_MODE" in detail) or ("Cannot resolve" in detail), detail


def test_scanners_metadata_lists_all_modules(client, admin_headers):
    data = client.get("/api/scanners", headers=admin_headers).json()
    keys = {m["key"] for m in data["modules"]}
    assert {"authentication", "authorization", "api", "input_validation",
            "headers", "tls", "secrets", "dependencies"} <= keys


def test_findings_search_pagination_and_total(client, analyst_headers):
    from backend.app.db import SessionLocal
    from backend.app.models import Assessment, Finding, User

    db = SessionLocal()
    user = db.query(User).filter(User.email == "analyst@example.com").one()
    a = Assessment(user_id=user.id, target="http://127.0.0.1/pagination-probe",
                   modules=["headers"], status="completed", authorized=True)
    db.add(a)
    db.commit()
    seeds = [("CRITICAL", "pagination probe alpha"), ("HIGH", "pagination probe beta"),
             ("MEDIUM", "unrelated gamma")]
    for sev, title in seeds:
        db.add(Finding(assessment_id=a.id, title=title, severity=sev, category="TEST",
                       scanner="pytest", check_id=f"PYTEST-{sev}", fingerprint=f"fp-{sev}-{a.id}"))
    db.commit()
    db.close()

    base = "/api/assessments/-/findings"
    r = client.get(base, params={"q": "pagination probe", "limit": 1, "offset": 0},
                   headers=analyst_headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Total-Count") == "2"
    assert len(r.json()) == 1
    r2 = client.get(base, params={"q": "pagination probe", "limit": 1, "offset": 1},
                    headers=analyst_headers)
    assert len(r2.json()) == 1
    assert r2.json()[0]["id"] != r.json()[0]["id"]
    r3 = client.get(base, params={"severity": "critical"}, headers=analyst_headers)
    assert r3.status_code == 200
    assert all(f["severity"] == "CRITICAL" for f in r3.json())


def test_audit_log_admin_only(client, analyst_headers):
    assert client.get("/api/audit-logs", headers=analyst_headers).status_code == 403
    assert client.get("/api/audit-logs", headers={
        "Authorization": "Bearer bogus"}).status_code in (401, 403)
