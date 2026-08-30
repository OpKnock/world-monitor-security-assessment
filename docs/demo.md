# Demo Script

Total time: ~6 minutes. Everything runs on localhost; nothing contacts external systems except an optional OSV lookup for the dependency module.

## 0. One-time setup (before the demo)

```powershell
.\.venv\Scripts\pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File scripts\build_go_tools.ps1
Copy-Item .env.example .env
```

Confirm binaries: `bin\portia.exe`, `bin\bomber.exe`, `bin\chainscanner.exe` should exist.

## 1. Start both services

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

| Service | URL | Login |
|---|---|---|
| Platform UI + API | http://127.0.0.1:8000 | `admin@example.com` / `ChangeMe_Use_Strong_Password_Here` (override via `ADMIN_PASSWORD` in `.env`) |
| Vulnerable lab | http://127.0.0.1:8080 | `alice` / `user123` · `bob` / `user456` · `admin` / `admin123` |
| Real World Monitor (optional) | http://127.0.0.1:3000 | `npm install` then `npm run dev -- --port 3000` inside `targets/real-world-monitor` |

The lab landing page is clearly labeled **VULNERABLE LAB** and warns against exposing it beyond loopback.

## 2. Show the safety gate first

This is the most important part of the demonstration.

* **New Assessment** → leave authorization **unchecked** → the Start button stays disabled (client-side) and the server would return `403` even if bypassed.
* With authorization **checked**, paste `https://example.com` as target → server refuses with `LAB_MODE permits only localhost/private-lab targets`. The gate is server-enforced via DNS resolution, not a UI hint.

## 3. Run the full assessment

Restore `http://127.0.0.1:8080/api`, keep the pre-filled per-module lab layout, tick authorization, press **Start**. Narrate while scanners stream:

> “Authentication probes JWT handling — watch for the none-algorithm check … Authorization walks object IDs as another user … Rate-limit module fires paced requests and tries IP-spoofing bypasses … Headers grades CSP and HSTS … Input validation tests SQL injection and reflected XSS …”

## 4. Results & drill-down

The dashboard shows real counts (typically 4–5 CRITICAL / 5 HIGH). Open:

* **JWT ‘none’ accepted (9.8)** — evidence shows the forged token exchange.
* **IDOR (6.5)** — `alice` reading `bob`’s and `admin`’s reports, HTTP 200 with cross-user data.
* **Hardcoded credential** — note the secret value is masked to `********` even in evidence.
* **Missing HSTS / CSP** — header grader findings with remediation.

Each finding shows CVSS vector, plain-language rationale, business impact, and step-by-step remediation.

## 5. Retest loop (the verification moment)

1. On *Missing HSTS* click **Retest** → `STILL_PRESENT`.
2. In a second terminal (or the prepared window from `start_all.ps1 -FixHeaders`):
   ```powershell
   $env:WM_LAB_FIX_HEADERS="1"
   python lab\vulnerable-world-monitor\app.py
   ```
   The lab now returns strict security headers.
3. **Retest** the same finding again → `FIXED` — the original evidence and the fresh retest evidence are both retained and linked.

The same flow works for IDOR via `-PatchIdor` / `WM_LAB_PATCH_IDOR=1`.

## 6. Reports

**Reports** page → **Generate** PDF / JSON / Markdown / CSV for the assessment. Open the PDF: cover with severity distribution, executive summary with real counts, methodology, color-coded findings with CVSS vectors and remediation, evidence and retest statement, conclusion. All content is derived from live findings — no templated numbers.

## 7. CLI (same engine)

```powershell
python cli\world_monitor.py scan --lab
python cli\world_monitor.py findings --severity CRITICAL
python cli\world_monitor.py retest <finding-id>
python cli\world_monitor.py report <assessment-id> --format pdf
```

The CLI drives the identical orchestration engine; results appear in the same database and are visible in the UI.

## 8. Real World Monitor target (optional)

1. Ensure `targets/real-world-monitor` is cloned and `npm install` completed.
2. Static sweep: **New Assessment** → modules `secrets`, `dependencies`, `supply_chain` with `source_path` set to `targets/real-world-monitor`.
3. Dynamic sweep: run the real app on `http://127.0.0.1:3000` → assess with `authentication`, `headers`, `tls` against that target.
4. Compare findings between the intentional lab weaknesses and the real codebase posture.
