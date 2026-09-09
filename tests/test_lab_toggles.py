"""Lab runtime fix-toggles: flip without restart, behavior follows, state resets."""
import pytest

KEYS = ["PATCH_IDOR", "PATCH_SQLI", "RATELIMIT", "FIX_HEADERS"]


@pytest.fixture()
def lab_client(lab_server):
    client = lab_server["module"].app.test_client()
    yield client
    # Always leave the shared lab fully vulnerable for other tests.
    client.post("/lab/toggles", json={k: False for k in KEYS})


def test_toggle_defaults_off(lab_client):
    assert lab_client.get("/lab/toggles").get_json() == {k: False for k in KEYS}


def test_toggle_flip_changes_behavior(lab_client):
    probe = {"id": "'"}  # unbalanced quote: sqlite error when vulnerable
    r = lab_client.get("/api/search", query_string=probe)
    assert r.status_code == 500 and "Traceback" in r.get_data(as_text=True)

    r = lab_client.post("/lab/toggles", json={"PATCH_SQLI": True})
    assert r.get_json()["PATCH_SQLI"] is True

    r = lab_client.get("/api/search", query_string=probe)
    assert r.is_json and "Traceback" not in r.get_data(as_text=True)

    r = lab_client.post("/lab/toggles", json={"PATCH_SQLI": False})
    assert r.get_json()["PATCH_SQLI"] is False
    assert lab_client.get("/api/search", query_string=probe).status_code == 500


def test_toggle_unknown_key_rejected(lab_client):
    assert lab_client.post("/lab/toggles", json={"NOPE": True}).status_code == 400


def test_health_reflects_runtime_toggles(lab_client):
    lab_client.post("/lab/toggles", json={"FIX_HEADERS": True})
    assert lab_client.get("/health").get_json()["toggles"]["FIX_HEADERS"] is True
