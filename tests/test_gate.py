"""Authorization gate + evidence masking (spec §12/§18/§47)."""
import pytest

from backend.app.engine.authorization_gate import (
    AuthorizationError,
    assert_authorized_flag,
    validate_http_target,
    validate_source_path,
)


def test_public_target_rejected_in_lab_mode():
    with pytest.raises(AuthorizationError):
        validate_http_target("https://example.com/api")


def test_localhost_allowed():
    assert validate_http_target("http://127.0.0.1:8080/api").startswith("http://127.0.0.1")


def test_private_range_allowed():
    assert validate_http_target("http://192.168.1.50:9000/") is not None


def test_metadata_endpoint_blocked():
    with pytest.raises(AuthorizationError):
        validate_http_target("http://169.254.169.254/latest/meta-data/")


def test_non_http_scheme_rejected():
    with pytest.raises(AuthorizationError):
        validate_http_target("file:///etc/passwd")


def test_unauthorized_flag_refused():
    with pytest.raises(AuthorizationError):
        assert_authorized_flag(False)


def test_source_path_jail():
    inside = str(validate_source_path("lab/vulnerable-world-monitor"))
    assert "vulnerable-world-monitor" in inside
    with pytest.raises(AuthorizationError):
        validate_source_path("C:/Windows/System32")
