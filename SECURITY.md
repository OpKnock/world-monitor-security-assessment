# Security Policy

## Reporting a vulnerability

This repository is itself a security assessment tool intended to run exclusively
against localhost / explicitly authorized targets.

If you discover a vulnerability **in this platform**:

1. Do not open a public issue for exploitable problems.
2. Contact the maintainer directly (see repository profile).
3. Include reproduction steps and impact assessment.

## Scope

- The bundled `lab/vulnerable-world-monitor/` application is intentionally
  vulnerable by design and runs on loopback only. Findings in it are out of scope.
- The platform refuses non-private targets while `LAB_MODE=true`; reports of
  bypasses in `engine/authorization_gate.py` are high priority.

## Hardening defaults

- JWT HS256 with pinned algorithm allow-list; PBKDF2-SHA256 (390k iterations).
- Evidence masking for tokens, cookies, API keys before persistence.
- Audit logging of assessments, scans, retests and reports.
