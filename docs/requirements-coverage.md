# Requirement Coverage Mapping

| # | Platform requirement | Platform feature (file/route) | Verified by |
|---|---|---|---|
| 1 | Authentication & session management testing | `authentication` module — missing-auth, JWT none/sig, invalid-token acceptance; cookie-flag audit in headers adapter | e2e test: JWT none-alg CRITICAL detected |
| 2 | Authorization & access control | `authorization` module (IDOR/BOLA) + lab's broken admin route | e2e: numeric ID enumeration HIGH |
| 3 | Input validation & data handling | SQLi scanner + reflected-XSS canary probe + verbose-error check | live run: blind-SQLi CRITICAL, reflection HIGH |
| 4 | API security | rate-limit detection/bypass, excessive-exposure lab findings, OpenAPI exposure noted in reports | live run: no-rate-limit HIGH |
| 5 | Client-side security controls | 6 security headers graded A–F + Set-Cookie flags | e2e: HSTS/CSP/XCTO/XFO findings |
| 6 | Secure communication | TLS module: cert validity/expiry, HTTPS availability/redirect | unit + optional module |
| 7 | Data storage & privacy protections | secrets scanner over lab source; evidence masking engine | e2e: 3 planted credentials found, values masked |
| — | Vulnerability identification | 8 scanner modules, unified registry | tests |
| — | Impact assessment | CVSS v3.1 engine with per-check vectors + plain-language rationale | FIRST-reference vector tests |
| — | Controlled PoC validation | reproduction steps recorded per finding; executed only against authorized lab | gate tests |
| — | Evidence | masked request/response + scanner-output JSON documents | masking unit tests |
| — | Severity / CVSS | cvss.py (FIRST formulas), presets, severity bands | parametrized score tests |
| — | Business impact | remediation KB + per-finding business-impact text | report content |
| — | Remediation recommendations | per-check curated remediation + KB fallbacks | finding detail UI/report |
| — | Real-time monitoring UX | SPA dashboard with live polling progress | manual/e2e status flow |
| — | Analytics | posture matrix (category × worst-severity), distribution donut | dashboard endpoint |
| — | Reporting | PDF (fpdf2) / JSON / Markdown with exec summary → conclusion structure | e2e: `%PDF` + content assertions |
| — | Role-based access control | viewer/analyst/admin enforced server-side | RBAC tests (403s) |
| — | API communication | FastAPI + OpenAPI at `/api/docs` | health/openapi |
| — | Data visualization | custom SVG donut/bars (no chart deps) | served assets |
| — | Retest system | fingerprint-stable recheck, FIXED/STILL_PRESENT, dual evidence | e2e both branches asserted |
| — | CLI | same-engine typer CLI (`scan/findings/report/retest`) | manual verification |

## Definition of Done checklist

[x] Local World Monitor lab runs · [x] Authorization gate works · [x] Assessments
creatable · [x] Multiple scanners execute · [x] Outputs normalized · [x] Findings
stored · [x] Duplicates handled (fingerprint merge) · [x] CVSS calculated ·
[x] Evidence stored safely · [x] Sensitive info masked · [x] Dashboard shows real
results · [x] Remediation attached · [x] Controlled PoC in lab · [x] PDF report ·
[x] Retesting works · [x] CLI works · [x] Tests pass (46) · [x] Docker files
provided (compose validated logically; daemon unavailable on build host — see
deployment notes) · [x] Requirements mapping documented · [x] No arbitrary-target
exploitation by default.
