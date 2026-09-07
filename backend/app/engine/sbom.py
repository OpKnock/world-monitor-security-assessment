"""SBOM generation (CycloneDX) — minimal stub for hardening."""
from pathlib import Path
import json

def generate_sbom(assessment_id: str) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "assessment": assessment_id, "components": []}
