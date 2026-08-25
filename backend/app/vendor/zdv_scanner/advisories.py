from dataclasses import dataclass


@dataclass
class Advisory:
    cve_id: str
    product: str
    affected_versions: tuple
    description: str
    cvss_score: float
    severity: str

    def matches(self, version):
        for affected in self.affected_versions:
            if version == affected:
                return True
            if affected.endswith("*") and version.startswith(affected[:-1]):
                return True
            if version.startswith(affected + "."):
                return True
        return False


ADVISORY_DB = [
    Advisory(
        "CVE-2021-41773",
        "Apache httpd",
        ("2.4.49",),
        "Path traversal and file disclosure in Apache HTTP Server 2.4.49",
        9.8,
        "critical",
    ),
    Advisory(
        "CVE-2019-0211",
        "Apache httpd",
        ("2.4.17", "2.4.18", "2.4.20", "2.4.21", "2.4.22", "2.4.23", "2.4.24", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29", "2.4.30", "2.4.31", "2.4.32", "2.4.33", "2.4.34", "2.4.35", "2.4.36", "2.4.37", "2.4.38"),
        "Apache HTTP Server privilege escalation via scoreboard memory corruption",
        8.8,
        "high",
    ),
    Advisory(
        "CVE-2021-23017",
        "nginx",
        ("1.20.0", "1.21.0", "1.21.1"),
        "Off-by-one heap write in nginx DNS resolver",
        8.1,
        "high",
    ),
    Advisory(
        "CVE-2021-44228",
        "Apache Log4j",
        ("2.14.1", "2.13.3", "2.12.2", "2.11.2", "2.10.0"),
        "Log4Shell: JNDI remote code injection in Apache Log4j",
        10.0,
        "critical",
    ),
    Advisory(
        "CVE-2014-0160",
        "OpenSSL",
        ("1.0.1*",),
        "Heartbleed: information disclosure in OpenSSL TLS heartbeat extension",
        7.5,
        "high",
    ),
    Advisory(
        "CVE-2017-12615",
        "Apache Tomcat",
        ("7.0.79", "7.0.78", "7.0.77", "7.0.76", "7.0.75", "7.0.74", "7.0.73", "7.0.72"),
        "Remote code execution via PUT method in Apache Tomcat on Windows",
        9.8,
        "critical",
    ),
]

PRODUCT_ALIASES = {
    "apache": "Apache httpd",
    "apache/2": "Apache httpd",
    "httpd": "Apache httpd",
    "apache tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "nginx": "nginx",
    "openssl": "OpenSSL",
    "log4j": "Apache Log4j",
}


def normalize_product(product):
    key = product.strip().lower()
    return PRODUCT_ALIASES.get(key, product.strip())


def match_advisory(product, version):
    normalized = normalize_product(product)
    return [
        advisory
        for advisory in ADVISORY_DB
        if advisory.product.lower() == normalized.lower() and advisory.matches(version)
    ]
