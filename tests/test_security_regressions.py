"""Regression tests for assessment authorization and retest safety."""
from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from backend.app.engine import authorization_gate
from backend.app.engine import dns_pinning
from backend.app.engine.dns_pinning import pin_target_dns
from backend.app.engine import orchestration
from backend.app.scanners.base import ScanResult
from backend.app.vendor.api_security_scanner.base_scanner import BaseScanner


def test_dns_pin_keeps_hostname_but_controls_resolution():
    with pin_target_dns("https://scanner.example.test/api", ["127.0.0.1"]):
        infos = socket.getaddrinfo("scanner.example.test", 443, type=socket.SOCK_STREAM)
    assert infos
    assert {info[4][0] for info in infos} == {"127.0.0.1"}


def test_allowlisted_public_target_still_rejects_special_ip(monkeypatch):
    # Ensure the process-wide resolver wrapper is installed even when this
    # test is run in isolation.
    with pin_target_dns("https://seed.example.test/", ["127.0.0.1"]):
        pass
    monkeypatch.setattr(
        dns_pinning,
        "_ORIGINAL_GETADDRINFO",
        lambda *args, **kwargs: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 0, 0, 0))],
    )
    with pytest.raises(authorization_gate.AuthorizationError, match="blocked special-purpose"):
        authorization_gate.resolve_target_ips("public.example", allow_public=True)


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_retest_non_completed_result_is_inconclusive(monkeypatch, status):
    finding = SimpleNamespace(
        id="finding-1",
        assessment_id="assessment-1",
        check_id="headers.strict_transport_security",
        scanner="headers",
        target="http://127.0.0.1:8080/",
        fingerprint="not-present",
        retest_count=0,
        retested_at=None,
        retest_status=None,
        status="OPEN",
        meta={},
    )
    assessment = SimpleNamespace(
        id="assessment-1",
        target="http://127.0.0.1:8080/",
        source_path="",
        module_targets={},
    )

    class FakeDB:
        def get(self, model, object_id):
            return finding if object_id == finding.id else assessment

        def commit(self):
            return None

        def rollback(self):
            return None

    class FakeStore:
        def __init__(self, assessment_id):
            self.assessment_id = assessment_id

        def save(self, **kwargs):
            return {"path": "retest.json", "kind": "scanner_output"}

    class FakeScanner:
        name = "headers"

        def run(self, ctx):
            return ScanResult(scanner=self.name, status=status)

    monkeypatch.setattr(orchestration, "EvidenceStore", FakeStore)
    monkeypatch.setattr(orchestration, "load_registry", lambda: None)
    monkeypatch.setattr(orchestration, "scanners_for", lambda modules: [FakeScanner()])
    monkeypatch.setattr(orchestration, "_audit", lambda *args, **kwargs: None)

    result = orchestration.retest_finding(FakeDB(), finding.id, "analyst@example.com")

    assert result["retest_status"] == "INCONCLUSIVE"
    assert finding.status == "OPEN"


def test_vendor_requests_do_not_follow_redirects(monkeypatch):
    class DummyScanner(BaseScanner):
        def scan(self):
            return None

    scanner = DummyScanner("http://127.0.0.1:8080/")
    scanner._wait_before_request = lambda: None
    seen = {}

    def request(method, url, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(status_code=200, headers={})

    monkeypatch.setattr(scanner.session, "request", request)
    scanner.make_request("GET", "/")
    assert seen["allow_redirects"] is False


def test_assessment_queue_rejects_saturation(monkeypatch):
    class DummyExecutor:
        def submit(self, *args, **kwargs):
            raise AssertionError("submit must not run when capacity is exhausted")

    monkeypatch.setattr(orchestration, "load_registry", lambda: None)
    monkeypatch.setattr(orchestration, "_ASSESSMENT_EXECUTOR", DummyExecutor())
    monkeypatch.setattr(orchestration, "_ASSESSMENT_QUEUE_CAPACITY", __import__("threading").BoundedSemaphore(0))
    with pytest.raises(RuntimeError, match="queue is full"):
        orchestration.start_assessment_async("assessment-1")
