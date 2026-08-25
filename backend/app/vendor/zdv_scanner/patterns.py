from .advisories import match_advisory

DEFAULT_CREDENTIAL_PATTERNS = [
    "password{0,20}(admin|root|default|toor)",
    "(user|login|username)[:= ]{0,8}(admin|root)",
    "default (password|credentials|login)",
    "admin.{0,40}(admin|toor|changeme)",
]

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "strict-transport-security": None,
    "content-security-policy": None,
    "x-frame-options": None,
    "referrer-policy": None,
}

BANNER_PATTERNS = [
    ("Apache httpd", r"apache/(\d+(?:\.\d+)*)", "apache"),
    ("nginx", r"nginx/(\d+(?:\.\d+)*)", "nginx"),
    ("Apache Tomcat", r"tomcat/?(\d+(?:\.\d+)*)", "tomcat"),
    ("OpenSSL", r"openssl/(\d+(?:\.\d+)*)", "openssl"),
]


def parse_banner(banner):
    for product, pattern, _ in BANNER_PATTERNS:
        import re

        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return product, match.group(1)
    return None


def check_banner_advisories(banner):
    parsed = parse_banner(banner)
    if parsed is None:
        return []
    product, version = parsed
    return match_advisory(product, version)
