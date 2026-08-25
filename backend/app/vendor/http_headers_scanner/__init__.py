"""Vendored copy of OpKnock/http-headers-scanner (AGPL-3.0), file scanner.py.

Upstream: https://github.com/OpKnock/http-headers-scanner
Imported verbatim; the adapter layer serializes its ScanReport dataclasses
into the World Monitor common finding format. The rich-based CLI renderer
is unused in-process.
"""
from .scanner import ScanReport, scan, evaluate_header, RULES

__all__ = ["ScanReport", "scan", "evaluate_header", "RULES"]
