"""Shared fixtures: isolated DB/dirs, live vulnerable-lab server on a real socket."""
import importlib.util
import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="wm_tests_"))
os.environ["WM_TEST_TMP"] = str(_TMP)
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["EVIDENCE_DIR"] = str(_TMP / "evidence")
os.environ["REPORT_DIR"] = str(_TMP / "reports")
os.environ["LAB_MODE"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production-000"
os.environ["ADMIN_PASSWORD"] = "ChangeMe_Admin_2026!"
os.environ["ANALYST_PASSWORD"] = "ChangeMe_Analyst_2026!"

ROOT = Path(__file__).resolve().parents[1]

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.main import create_app  # noqa: E402
from backend.app.security import hash_password  # noqa: E402


@pytest.fixture(scope="session")
def lab_server():
    """Run the intentionally-vulnerable lab on an ephemeral local port."""
    spec = importlib.util.spec_from_file_location(
        "vulnerable_lab", ROOT / "lab" / "vulnerable-world-monitor" / "app.py")
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)

    dbfile = ROOT / "lab" / "vulnerable-world-monitor" / "lab.db"
    if dbfile.exists():
        dbfile.unlink()
    lab.init_db()

    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", 0, lab.app)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {"url": f"http://127.0.0.1:{server.server_port}", "module": lab}
    server.shutdown()


@pytest.fixture(scope="session")
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers(client):
    r = client.post("/api/auth/login", json={
        "email": "admin@example.com", "password": "ChangeMe_Admin_2026!"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def analyst_headers(client):
    from backend.app.db import SessionLocal
    from backend.app.models import User

    db = SessionLocal()
    existing = db.query(User).filter(User.email == "analyst@example.com").one_or_none()
    if existing is None:
        db.add(User(email="analyst@example.com",
                    password_hash=hash_password("ChangeMe_Analyst_2026!"), role="analyst"))
        db.commit()
    db.close()
    r = client.post("/api/auth/login", json={
        "email": "analyst@example.com", "password": "ChangeMe_Analyst_2026!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
