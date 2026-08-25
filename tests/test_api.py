"""Platform API: auth, RBAC, gate refusals, scanner metadata."""
import pytest


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["lab_mode"] is True


def test_register_login_me(client):
    r = client.post("/api/auth/register", json={
        "email": "viewer1@example.com", "password": "ViewerPass_123"})
    assert r.status_code == 201
    tok = r.json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.json()["role"] == "viewer"


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


def test_viewer_cannot_create_assessment(client, analyst_headers):
    # viewer role lacks analyst rights -> 403
    v = client.post("/api/auth/login", json={
        "email": "viewer1@example.com", "password": "ViewerPass_123"}).json()
    headers = {"Authorization": f"Bearer {v['access_token']}"}
    assert client.post("/api/assessments", json={
        "target": "http://127.0.0.1/x", "modules": ["headers"], "authorized": True},
        headers=headers).status_code == 403


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


def test_audit_log_admin_only(client, analyst_headers):
    assert client.get("/api/audit-logs", headers=analyst_headers).status_code == 403
    assert client.get("/api/audit-logs", headers={
        "Authorization": "Bearer bogus"}).status_code in (401, 403)
