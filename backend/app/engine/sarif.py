"""SARIF output — minimal stub."""
import json

def to_sarif(findings: list) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "world-monitor"}}, "results": []}]}
