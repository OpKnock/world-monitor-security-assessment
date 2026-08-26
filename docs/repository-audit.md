# Repository Audit — World Monitor Security Assessment Platform

> Phase 0 program deliverable. Every candidate repository was cloned from GitHub (`OpKnock/*`)
> and its actual source code inspected before any integration decision was made.
> Audit date: 2026-08-24. Host: Windows 11, Python 3.14.6, Go 1.26.4, Node 26 / pnpm 11,
> Rust 1.98. **Docker is NOT installed on the assessment host.**

## Decision legend

| Decision | Meaning |
|---|---|
| KEEP-INTEGRATE | Reused as a working component (vendored library or subprocess adapter) |
| MODIFY | Integrated after non-trivial adaptation |
| OPTIONAL | Wired but not required; enabled only when environment supports it |
| REFERENCE | Not integrated; source of design patterns only |
| DROP | Not integrated; documented reason |

## Master audit table

| # | Repository | Language | Purpose (verified in code) | Platform requirement served | Input | Output | Dependencies | Decision | Integration method |
|---|---|---|---|---|---|---|---|---|---|
| 1 | api-security-scanner | Python 3.13+/FastAPI + React | OWASP API Top-10 scanner app (auth, IDOR, rate-limit, SQLi scanners) + dashboard | Authentication, Authorization, Input validation, API security | `ScanRequest{target_url, auth_token, tests_to_run}` | Per-test result dict w/ evidence JSON | fastapi/sqlalchemy/requests; **Postgres required** | **KEEP-INTEGRATE (scanner modules only)** — web layer DROPPED (see notes) | Vendored scanner classes behind adapter; Postgres-specific config shimmed out |
| 2 | http-headers-scanner | Python ≥3.13 single file | Grades 6 security headers (HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy), A–F score | Client-side security controls | URL | Rich terminal table + `ScanReport` dataclass (**no JSON mode**) | httpx, rich | **KEEP-INTEGRATE** | Vendored as library; adapter serializes dataclasses to common Finding format; extended with Set-Cookie flag checks |
| 3 | secrets-scanner ("portia") | Go ≥1.25 CLI | ~110 secret-detection rules over directories AND git history; entropy-gated generics | Data privacy / secrets exposure | path or repo dir | `{"findings":[...],"summary":{...}}` JSON/SARIF/terminal (secrets pre-masked) | cobra, go-git, color | **KEEP-INTEGRATE** | Subprocess adapter on built binary, `-f json`; offline except opt-in HIBP |
| 4 | dlp-scanner | Python ≥3.12 | PII/PHI/financial/credential detection in files/DB/pcap; redaction; compliance tags | Data privacy | files/db-uri/pcap | JSON `{scan_metadata, findings[], summary}` | **19 heavy deps** (pymupdf, pyarrow, extract-msg, db drivers…) | **MODIFY → deferred to Phase 12 (OPTIONAL)** | File-mode only via CLI JSON; MVP uses portia + native masking instead to avoid dependency bloat at demo time |
| 5 | ai-threat-detection | Python FastAPI + ONNX ensemble (ae/rf/if ≈2.9 MB models shipped) | nginx log ingestion → rules+ML threat scoring, WS alerts | AI correlation/prioritization (enhancement) | tailed log file or `POST /ingest/batch` lines | ThreatEvent schema, severity HIGH/MEDIUM/LOW | **Redis hard-required**, asyncpg/SQLModel; runtime ML = onnxruntime+numpy only | **OPTIONAL (Phase 13)** | Run as sidecar service; feed lab access-log lines post-scan; deterministic engine remains authoritative |
| 6 | sbom-generator-vulnerability-matcher ("bomber") | Go ≥1.25 CLI | Parses go.mod/package.json+pnpm-lock/pyproject.toml+uv.lock → SBOM (SPDX/CycloneDX) + OSV CVE matching w/ CVSS v3 scoring | Dependency security | project dir | JSON report (Go default marshaling — numeric enums!) | stdlib + modernc sqlite cache | **KEEP-INTEGRATE** | Subprocess adapter `bomber vuln <lab> -f json`; int→name enum mapping; needs one online OSV pass (24 h SQLite cache) |
| 7 | siem-dashboard | Python Flask + Mongo + Redis + React/visx | Full SIEM: JWT auth, RBAC(admin/analyst), correlation rules, SSE dashboards | Auth/RBAC patterns, dashboard UX | — | — | mongoengine, redis, pwdlib[argon2] | **REFERENCE** (component DROPPED) | Copied concepts: timing-safe Argon2-style verify, role-gated decorators, alert lifecycle statuses, visx-style chart layout — reimplemented natively (SQLite/FastAPI/vanilla JS) |
| 8 | bug-bounty-platform | Python FastAPI | Educational vuln-report tracker; **in-memory storage, no auth, stub CLI** | none for assessment | — | JSON dicts | fastapi/typer | **DROP** | It manages reports, it does not find vulnerabilities; our platform implements persistence + lifecycle itself |
| 9 | simple-vulnerability-scanner ("angela") | Go ≥1.24 | pyproject/requirements CVE check via OSV.dev; terminal-only output | overlaps bomber | python manifests | colored text only | OSV network | **DROP** | Duplicate of #6 with no machine-readable output |
| 10 | graphql-security-tester ("gqlscan") | Python ≥3.9 stdlib | Offline GraphQL depth/complexity/introspection analysis | API security (GraphQL) | query str / introspection dict | dataclasses | none | **OPTIONAL (Phase 12)** | Vendored lib behind adapter if lab exposes a GraphQL endpoint |
| 11 | mobile-app-security-analyzer | Python stdlib | Static APK manifest/source scan | wrong domain | APK/AAB | dicts | none | **DROP** | Mobile static analysis ≠ World Monitor web assessment |
| 12 | docker-security-audit ("docksec") | Go ≥1.25 | CIS Docker Benchmark audit of containers/images/Dockerfiles | Infrastructure | docker daemon | JSON/SARIF findings | docker SDK + **daemon** | **OPTIONAL** | Docker absent on host; wired as optional module that reports "environment unsupported" rather than fake results |
| 13 | linux-cis-hardening-auditor | Bash | 104 CIS Debian/Ubuntu controls; root required | Infrastructure | Linux host | JSON/HTML | root/Linux | **DROP** | Windows host; OS hardening out of scope for web-app assessment demo |
| 14 | ja3-ja4-tls-fingerprinting ("tlsfp") | Rust ed.2024 | JA3/JA4 passive TLS fingerprinting from pcap/live iface | Network forensics | pcap/iface | NDJSON events | **libpcap/Npcap SDK build pain**, admin capture | **DROP** | Build-time Npcap SDK dependency on Windows; forensic scope ≠ assessment scope. TLS posture covered by native checker instead |
| 15 | network-traffic-analyzer ("netanal") | Py≥3.14/C++ | Live capture stats/top talkers | tangential | pcap/iface | JSON/CSV/PNG | scapy + root/Npcap | **DROP** | Requires privileged capture; adds no finding value for authorized lab web testing |
| 16 | firewall-rule-engine ("fwrule") | **V 0.5.1** | iptables/nftables text-file linting | infra hygiene | ruleset text | terminal only | V toolchain | **DROP** | No JSON output, exotic toolchain, host-firewall domain irrelevant to the program |
| 17 | supply-chain-security-analyzer | Go 1.26 | Manifest parsing, license lookup, typosquat heuristics; offline JSON | supply chain | project dir | `{ecosystem, dependencies[], summary}` | stdlib only | **OPTIONAL (Phase 12)** | Clean module; complements bomber's CVE view with license/typosquat posture |
| 18 | credential-rotation-enforcer | **Crystal ≥1.20** | Credential rotation workflows vs AWS/Vault/GitHub; tamper-evident audit | ops tooling | creds store | JSON/TUI | Crystal (**no stable Windows support**) | **DROP** | Unbuildable on this host without WSL; rotation ops ≠ vulnerability assessment |
| 19 | monitor-the-situation-dashboard | Go+React19 | Multi-feed global threat globe SOC dashboard | visual inspiration | external feeds | WebSockets UI | Postgres+Redis+internet feeds | **REFERENCE** | Too heavy, constant internet dependence; dashboard layout inspiration only |
| 20 | api-rate-limiter ("fastapi-420") | Python ≥3.14 lib | Rate-limit middleware library (defense side) | could arm the lab | library | HTTP 420s | redis optional | **DROP (assessment)** | It defends APIs, doesn't assess them. Lab demonstrates *missing* rate limiting natively |

## Duplicate-functionality resolution

* **CVE matching:** `sbom-generator-vulnerability-matcher` (JSON, SBOM export, CVSS v3, tests) beats
  `simple-vulnerability-scanner` (terminal-only). → keep #6, drop #9.
* **Secrets/PII:** MVP uses `secrets-scanner` (#3, zero-install runtime, pre-masked output).
  `dlp-scanner` (#4) is richer but carries 19 heavy deps and DB/pcap modes we cannot use;
  deferred to an optional phase rather than half-integrated.
* **Dashboards:** three candidate frontends exist (siem-dashboard, ai-threat-detection,
  monitor-the-situation). All are coupled to their own backends/databases. One unified SPA is
  built fresh against our unified backend; the candidates serve as UX reference only.
* **Auth engines:** api-security-scanner (bcrypt+jose) and siem-dashboard (Argon2id+pyjwt) both
  implement auth for themselves. We adopt siem-dashboard's safer patterns (timing-safe verify,
  anti-enumeration dummy hash) implemented on stdlib PBKDF2 to avoid compiled deps on Windows.

## Defects found during audit (documented per instruction §54)

1. **api-security-scanner**: Dockerfile copies nonexistent `requirements.txt` (README quick start broken);
   `.env.example` emits an `postgresql+asyncpg://` URL while code uses sync psycopg2; scans run
   synchronously inside async handlers (event-loop blocked); **no target authorization gate whatsoever**
   (SSRF/abuse hazard); unused-but-destructive payload lists shipped (`DROP TABLE`, `xp_cmdshell`);
   AGPL LICENSE file contradicts MIT label in pyproject.
   → Our integration keeps only the four scanner classes, strips destructive payload lists, wraps every
   invocation in the mandatory authorization gate, and runs scanners in worker threads.
2. **ai-threat-detection**: Redis is structurally required (windowed features + pub/sub); parser is
   nginx-combined-only; partial Postgres index dialect. → optional sidecar, sqlite fallback acceptable.
3. **siem-dashboard**: no tests shipped despite pytest config; default SECRET_KEY committed;
   in-memory correlation state lost on restart. → reference only.
4. **bug-bounty-platform**: CLI commands construct throwaway in-memory instances (data never persists).
5. **bomber**: JSON marshals Go iota enums as integers; OSV failures are silently swallowed into empty
   reports; CVSS v3 vectors only. → adapter maps ints↔names, treats empty vulns as "0 matched", documents v3-only.

## Licensing note

Kept components #1,#2,#3,#6 (+optional #4,#10,#12) are **AGPL-3.0**. The master repository therefore
ships under AGPL-3.0-compatible terms with attribution in `NOTICE`. This is acceptable for the
deliverable; commercial redistribution would trigger AGPL network-service obligations.

## Final composition

```
MVP (must work):        headers(#2) + api-scanners(#1: auth/idor/rate-limit/sqli) + secrets(#3)
Core platform:          unified FastAPI backend, SQLite, job runner, finding/evidence/CVSS/
                        remediation/report engines, vanilla-JS SPA, CLI, vulnerable lab
Phase 12 optional:      dependencies(#6), tls(native), input-validation XSS probe(native),
                        graphql(#10), supply-chain licenses(#17), docker-audit(#12)
Phase 13 optional:      ai-threat-detection sidecar (#5)
Dropped (10):           bug-bounty-platform, simple-vulnerability-scanner, mobile-app-security-
                        analyzer, linux-cis-hardening-auditor, ja3-ja4-tls-fingerprinting,
                        network-traffic-analyzer, firewall-rule-engine, credential-rotation-
                        enforcer, api-rate-limiter, monitor-the-situation-dashboard(+siem as ref)
```
