# Contributing

## Setup
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File scripts/build_go_tools.ps1
Copy-Item .env.example .env
.\.venv\Scripts\python -m pytest tests -q
```

## Ground rules
1. Every scanner module must return the common `RawFinding` schema via
   `ScanResult` (see docs/scanner-development.md).
2. New checks require a CVSS v3.1 preset vector and a remediation-KB entry.
3. Tests must accompany behavior changes; run the full suite before opening a PR.
4. Never commit `.env`, databases, evidence or generated reports.
5. Vendored code stays under `backend/app/vendor/` with NOTICE.md attribution.
6. Keep every scanning path behind the authorization gate - no exceptions.
