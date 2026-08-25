"""Evidence engine masking guarantees."""
from backend.app.engine.evidence import mask_body, mask_headers, mask_text


def test_authorization_header_masked_with_scheme():
    out = mask_headers({"Authorization": "Bearer abc.def.ghi"})
    assert out["Authorization"] == "Bearer ********"


def test_cookie_and_api_key_masked():
    out = mask_headers([("Set-Cookie", "session=xyz"), ("X-Api-Key", "k123")])
    assert out["Set-Cookie"] == "********"
    assert out["X-Api-Key"] == "********"


def test_normal_headers_untouched():
    out = mask_headers({"Content-Type": "application/json"})
    assert out["Content-Type"] == "application/json"


def test_body_password_masked():
    masked = mask_body('{"username":"alice","password":"SuperSecret123"}')
    assert "SuperSecret123" not in masked
    assert "********" in masked


def test_aws_key_pattern_masked():
    masked = mask_text("key=AKIAIOSFODNN7EXAMPLE end")
    assert "AKIAIOSFODNN7EXAMPLE" not in masked


def test_github_token_masked():
    masked = mask_text("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ000000")
    assert "ghp_" not in masked.replace("token: ", "")


def test_private_key_block_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    masked = mask_text(pem)
    assert "MIIabc" not in masked
