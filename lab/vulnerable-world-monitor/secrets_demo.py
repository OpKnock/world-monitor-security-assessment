"""
DEMO SECRETS — 100% FAKE VALUES FOR THE LOCAL LAB SCAN DEMO.

These strings intentionally match well-known secret-detection rule shapes so
that the secrets module can demonstrate finding hardcoded credentials in
source control. None of these values are real, none authenticate anywhere,
and every one is prefixed/suffixed with an obvious demo marker.
"""
import os

# --- FAKE AWS-style key (canonical documentation example format) ---
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # fake — AWS docs example id
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # fake

# --- FAKE GitHub-style token (pattern only, invalid checksum usage) ---
GITHUB_DEMO_TOKEN = "ghp_DEMOTOKEN0000000000000000000000000000"  # fake

# --- Fake private-key block (never a real key; generated junk) ---
DEMO_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBADMxk9FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA
KEFAKEFAKEFAKEFAKEFAKEFAKECAwEAAQJBAKFAKEFAKEFAKEFAKEFAKEFAKEFAKE
FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKECIQDFAKE=
-----END RSA PRIVATE KEY-----"""

# The CORRECT way (what remediation looks like):
DATABASE_URL = os.environ.get("WM_LAB_DATABASE_URL", "sqlite:///lab.db")
