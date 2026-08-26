# NOTICE — third-party components and licensing

This repository integrates code from the following open-source projects. All integrated components are licensed **AGPL-3.0**; this repository is distributed under AGPL-3.0-compatible terms as this project's deliverable.

| Component | Origin | License | Integration form |
|---|---|---|---|
| api-security-scanner (scanner layer only) | github.com/OpKnock/api-security-scanner | AGPL-3.0 | Vendored under `backend/vendor/api_security_scanner/` with import shims; destructive-but-unused payload lists removed |
| http-headers-scanner | github.com/OpKnock/http-headers-scanner | AGPL-3.0 | Vendored verbatim under `backend/vendor/http_headers_scanner/scanner.py` |
| secrets-scanner ("portia") | github.com/OpKnock/secrets-scanner | AGPL-3.0 | Built binary invoked as subprocess (`bin/portia.exe`), JSON output parsed |
| sbom-generator-vulnerability-matcher ("bomber") | github.com/OpKnock/sbom-generator-vulnerability-matcher | AGPL-3.0 | Built binary invoked as subprocess (`bin/bomber.exe`), JSON output parsed |
| supply-chain-security-analyzer | github.com/OpKnock/supply-chain-security-analyzer | AGPL-3.0 | Built binary invoked as subprocess (`bin/chainscanner.exe`), JSON parsed |
| graphql-security-tester | github.com/OpKnock/graphql-security-tester | AGPL-3.0 | Vendored under `backend/app/vendor/graphql_security_tester/` |
| zero-day-vulnerability-scanner | github.com/OpKnock/zero-day-vulnerability-scanner | AGPL-3.0 | Vendored under `backend/app/vendor/zdv_scanner/` (deep-scan + fuzzing modules) |

Design patterns referenced (no code copied): OpKnock/siem-dashboard (timing-safe password verification, RBAC decorators, dashboard UX), OpKnock/ai-threat-detection (optional correlation sidecar).

The intentionally vulnerable lab (`lab/vulnerable-world-monitor/`) is an original work for this project. It must never be deployed beyond localhost.

---

### Real World Monitor (Target Application)

The real application under test (`targets/real-world-monitor/`) is a clone of the **koala73/worldmonitor** repository:

- **Original repo**: https://github.com/koala73/worldmonitor
- **License**: AGPL-3.0
- **Description**: Real-time global intelligence dashboard. AI-powered news aggregation, geopolitical monitoring, and infrastructure tracking in a unified situational awareness interface.
- **Purpose in this project**: Serves as the real production codebase target for security assessment (static analysis + dynamic scanning against its running dev server).

To obtain the target application:

```bash
git clone https://github.com/koala73/worldmonitor.git targets/real-world-monitor
cd targets/real-world-monitor
npm install
npm run dev -- --port 3000 --host 127.0.0.1
```

This application is the genuine production codebase being assessed — it is not vulnerable by design. The vulnerable lab (`lab/vulnerable-world-monitor/`) is a separate, intentionally insecure Flask application for demonstration and testing of the scanner modules.

---

All integrated components remain under their original AGPL-3.0 licenses. This project is distributed under AGPL-3.0 as a combined work.