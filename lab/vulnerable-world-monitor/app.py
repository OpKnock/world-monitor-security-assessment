"""
WORLD MONITOR POC PLAYGROUND - CONTROLLED EXPLOITATION TARGET

*** INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY ***

This small application simulates the World Monitor product so that the
assessment platform has a realistic, isolated target. Every vulnerability
below is deliberate, labeled, and confined to localhost. NEVER deploy this
file outside a local lab, and never point scanners at systems you do not own.

Deliberate weaknesses (mapped to program requirements):
  W01  Broken vertical authorization   GET /api/users        (any user -> admin data)
  W02  Broken horizontal authorization GET /api/reports/<id> (IDOR across users)
  W03  SQL injection (boolean blind)   GET /api/search?id=
  W04  Verbose error disclosure        debug-style tracebacks
  W05  JWT 'none' algorithm accepted   /api token verification
  W06  Session cookie without flags    SESSION_COOKIE_HTTPONLY=False etc.
  W07  Missing security headers        nowhere set (unless WM_LAB_FIX_HEADERS=1)
  W08  Excessive data exposure         password_hash fields, internals leaked
  W09  No rate limiting                all endpoints unlimited (unless WM_LAB_RATELIMIT=1)
  W10  Hardcoded demo secrets          secrets_demo.py (FAKE values)

Fix toggles (used by the retest demo):
  WM_LAB_PATCH_IDOR=1     -> ownership check enforced on /api/reports/<id>
  WM_LAB_FIX_HEADERS=1    -> strict security headers middleware enabled
  WM_LAB_PATCH_SQLI=1     -> parametrized query on /api/search
  WM_LAB_RATELIMIT=1      -> 20 req/min per IP on /api/*
  WM_LAB_JWT_SECRET=...   -> override weak JWT secret (for testing rotation)

Run:  python lab/vulnerable-world-monitor/app.py   (listens on 127.0.0.1:8080)
Environment:
  WM_LAB_HOST, WM_LAB_PORT — bind address (default 127.0.0.1:8080)
  WM_LAB_SESSION_KEY       — Flask secret_key override
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
import traceback
from datetime import datetime, timezone

try:
    from flask import Flask, Response, g, jsonify, request
except ModuleNotFoundError as _e:
    import sys
    sys.stderr.write(
        "\n[lab] ERROR: Flask is not installed.\n"
        "  You are likely not in the project venv or forgot to install requirements.\n"
        "  Fix (Windows):\n"
        "    .venv/Scripts\activate\n"
        "    pip install -r requirements.txt  # includes flask>=3.1,<4 at line 21\n"
        "  Fix (Mac/Linux):\n"
        "    source .venv/bin/activate\n"
        "    pip install -r requirements.txt\n"
        "  Then: python lab/vulnerable-world-monitor/app.py  (or: .venv/Scripts\\python lab/vulnerable-world-monitor/app.py)\n"
        "  See README.md Quick Start - Fresh Clone.\n\n"
    )
    raise

# Configure lab logging — INFO for lab, WARNING for werkzeug noise suppression
logging.basicConfig(level=logging.INFO, format="%(asctime)s [lab] %(levelname)s: %(message)s")
logger = logging.getLogger("worldmonitor.lab")
# Suppress overly verbose werkzeug access logs in lab mode unless DEBUG=1
if os.environ.get("DEBUG") != "1":
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "lab.db")
# Allow override for testing JWT rotation; still weak by default (deliberate)
_JWT_SECRET_RAW = os.environ.get("WM_LAB_JWT_SECRET", "worldmonitor-lab-secret")
JWT_SECRET = _JWT_SECRET_RAW.encode() if isinstance(_JWT_SECRET_RAW, str) else b"worldmonitor-lab-secret"

PATCH_IDOR = os.environ.get("WM_LAB_PATCH_IDOR") == "1"
PATCH_SQLI = os.environ.get("WM_LAB_PATCH_SQLI") == "1"
RATELIMIT = os.environ.get("WM_LAB_RATELIMIT") == "1"

FIX_HEADERS = os.environ.get("WM_LAB_FIX_HEADERS") == "1"

app = Flask(__name__)
# Flask 3.x deprecates SESSION_COOKIE_SAMESITE=None — use "Lax" or omit.
# For W06 we deliberately want no SameSite, but to avoid deprecation warnings
# we set it to None only when not fixing headers; Flask will emit a warning
# in that case which is acceptable for a deliberately vulnerable lab.
app.config.update(
    SECRET_KEY=os.environ.get("WM_LAB_SESSION_KEY", "not-a-real-production-key"),
    SESSION_COOKIE_HTTPONLY=False,   # W06 — deliberately insecure
    SESSION_COOKIE_SAMESITE=None if not FIX_HEADERS else "Lax",
    SESSION_COOKIE_SECURE=False,     # W06 — deliberately insecure
)

USERS = {
    # W-deliberate: weak, documented passwords for demo accounts only
    "alice": {"password": "user123", "email": "alice@lab.local", "role": "user"},
    "bob":   {"password": "user456", "email": "bob@lab.local",   "role": "user"},
    "admin": {"password": "admin123", "email": "admin@lab.local", "role": "admin"},
}


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #
_RL_HITS: dict[str, list[float]] = {}
_RL_WINDOW_S = 60
_RL_MAX = 20  # matches lab default in docs


def db() -> sqlite3.Connection:
    conn = getattr(g, "_db", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL for better concurrency if DB already exists
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
        except Exception:
            pass
        g._db = conn
    return conn


REPORTS = {
    1: ("alice", "Global outage postmortem",
        "CONFIDENTIAL incident timeline for the ACME production region: root cause was a failed "
        "config push at 03:12 UTC, blast radius covered 14 monitoring probes, customer impact "
        "lasted 47 minutes, remediation owner is the platform reliability team, follow-up items "
        "include circuit-breaker rollout and pager escalation policy revision."),
    2: ("alice", "Latency trend Q3",
        "p95 latency analysis across all monitoring probes for the quarter: eu-west-1 degraded "
        "by 18ms after the ingestion refactor, us-east-2 remained stable at 210ms, ap-south-1 "
        "shows diurnal spikes correlated with batch report generation, recommended action is "
        "query-plan review plus an index on the events table partition key."),
    3: ("bob", "Budget forecast",
        "Internal cost projection for the observability stack next fiscal year: retention tiering "
        "saves roughly 23 percent of storage spend, dedicated ingest nodes are projected flat, "
        "alert-delivery costs rise with SMS volume, finance sign-off pending from the director "
        "of infrastructure, do not distribute outside the engineering leadership group."),
    4: ("admin", "Admin master key rotation log",
        "ROOT credential rotation evidence: master API key rotated on schedule via break-glass "
        "procedure, old material destroyed after dual control verification, HSM slot reassigned, "
        "next rotation due in 90 days, this document is restricted to the security administrator "
        "role and must never be readable by ordinary platform users."),
}

TELEMETRY = [
    {"region": "eu-west-1", "cpu": 41, "alerts": 2},
    {"region": "us-east-2", "cpu": 77, "alerts": 5},
]


@app.teardown_appcontext
def close_db(_exc) -> None:
    conn = getattr(g, "_db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    if os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, email TEXT,
                           password TEXT, role TEXT);
        CREATE TABLE audit_log(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT);
        CREATE TABLE reports(id INTEGER PRIMARY KEY, owner TEXT, title TEXT, summary TEXT);
        """
    )
    uid = 0
    for name, info in USERS.items():
        uid += 1
        conn.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (uid, name, info["email"], hashlib.sha256(info["password"].encode()).hexdigest(), info["role"]),
        )
    for rid, (owner, title, summary) in REPORTS.items():
        conn.execute("INSERT INTO reports VALUES(?,?,?,?)", (rid, owner, title, summary))
    conn.commit()
    conn.close()


init_db()


# --------------------------------------------------------------------------- #
# minimal JWT (deliberately vulnerable verifier — W05)
# --------------------------------------------------------------------------- #
def jwt_sign(payload: dict) -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET, f"{header}.{body}".encode(), hashlib.sha256).hexdigest()
    return f"{header}.{body}.{sig}"


def jwt_verify_insecure(token: str):  # noqa: ANN201
    """Returns payload or None. Accepts alg=none (W05) — the vulnerability."""
    try:
        header_b64, body_b64, sig = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
        body = json.loads(base64.urlsafe_b64decode(pad(body_b64)))
        if str(header.get("alg", "")).lower() == "none":
            return body  # !!! vulnerability: unsigned token trusted
        if header.get("alg") == "HS256":
            expected = hmac.new(JWT_SECRET, f"{header_b64}.{body_b64}".encode(),
                                hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, sig):
                if time.time() < float(body.get("exp", 0)):
                    return body
        return None
    except Exception:
        return None


def current_identity():
    """Resolve identity from Bearer JWT or Flask session."""
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        payload = jwt_verify_insecure(authz[7:])
        if payload:
            return {"username": payload.get("sub"), "role": payload.get("role", "user")}
    username = request.cookies.get("wm_lab_user")
    if username:
        info = USERS.get(username)
        if info:
            return {"username": username, "role": info["role"]}
    return None


# --------------------------------------------------------------------------- #
# security headers are ABSENT on purpose (W07) unless fix-toggle is set
# --------------------------------------------------------------------------- #
@app.after_request
def maybe_headers(response: Response) -> Response:
    response.headers["Server"] = "WorldMonitor-Lab/0.9-flask"  # version disclosure (W08)
    if FIX_HEADERS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Harden cookies when fix is enabled — still not Secure without TLS, but HttpOnly + SameSite
        app.config["SESSION_COOKIE_HTTPONLY"] = True
    # Always add request ID for tracing (lab only)
    if not response.headers.get("X-Request-ID"):
        import uuid as _uuid
        response.headers["X-Request-ID"] = _uuid.uuid4().hex[:12]
    return response


@app.errorhandler(404)
def handle_404(e):  # type: ignore[no-untyped-def]
    if request.path.startswith("/api"):
        return jsonify(error="not found", path=request.path), 404
    return e

@app.errorhandler(500)
def handle_500(e):  # type: ignore[no-untyped-def]
    logger.exception("Unhandled error at %s", request.path)
    if request.path.startswith("/api"):
        # W04: verbose disclosure only on /api/search when PATCH_SQLI=0; otherwise generic
        if request.path.startswith("/api/search") and not PATCH_SQLI:
            return Response(traceback.format_exc(), status=500, mimetype="text/plain")
        return jsonify(error="internal server error"), 500
    return e


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>World Monitor Lab — Vulnerable Playground</title>
<style>
:root{--bg:#060a13;--bg-elev:#0f172a;--card:rgba(17,24,39,.85);--border:rgba(31,41,55,.8);--border-bright:rgba(55,65,81,.9);--text:#f8fafc;--text-muted:#94a3b8;--text-dim:#64748b;--cyan:#22d3ee;--cyan-glow:rgba(34,211,238,.4);--green:#10b981;--amber:#f59e0b;--red:#ef4444;--orange:#f97316;--violet:#a855f7;--bg-gradient:radial-gradient(ellipse 80% 60% at 50% -20%,rgba(34,211,238,.15),transparent 60%),radial-gradient(ellipse 60% 50% at 90% 80%,rgba(168,85,247,.1),transparent 55%),radial-gradient(ellipse 40% 30% at 10% 90%,rgba(16,185,129,.06),transparent 50%);}
*{box-sizing:border-box;margin:0;padding:0} html{scroll-behavior:smooth}
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh;background-image:var(--bg-gradient)}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:2px}
code{background:rgba(6,182,212,.15);color:var(--cyan);padding:2px 6px;border-radius:6px;font-size:.85em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:9999px;font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.25)}
.badge.warn{background:rgba(245,158,11,.15);color:#f59e0b;border-color:rgba(245,158,11,.25)}
h1{font-size:1.75rem;font-weight:800;letter-spacing:-.02em;margin:0 0 .5rem;display:flex;align-items:center;gap:.75rem}
.card{background:linear-gradient(165deg,rgba(17,24,39,.95),rgba(17,24,39,.85));border:1px solid var(--border);border-radius:14px;padding:20px;margin:1.25rem 0;box-shadow:0 4px 24px rgba(0,0,0,.35),0 0 0 1px rgba(6,182,212,.05);position:relative;overflow:hidden}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(6,182,212,.25),transparent);opacity:.7}
.warn{background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:10px;padding:14px;margin:1rem 0;display:flex;align-items:flex-start;gap:.75rem}
.warn svg{flex-shrink:0;margin-top:.125rem}
p{margin:.75rem 0;color:#d1d5db} .muted{color:var(--text-muted);font-size:.875rem}
.card-title{font-size:1rem;font-weight:700;margin:0 0 1rem;display:flex;align-items:center;gap:.5rem}
.card-title svg{width:1.25rem;height:1.25rem;color:var(--cyan)}
ul{margin:.5rem 0;padding-left:1.25rem} li{margin:.35rem 0;color:#d1d5db} li code{background:rgba(6,182,212,.12);color:#22d3ee;padding:2px 8px;border-radius:6px}
a{color:var(--cyan);text-decoration:none} a:hover{text-decoration:underline}
input,button,select,textarea{font-family:inherit;font-size:.9375rem}
input[type="text"],input[type="email"],input[type="password"]{width:100%;background:rgba(15,23,42,.8);border:1px solid var(--border);color:#f3f4f6;padding:.625rem .875rem;border-radius:10px;transition:border-color .15s,box-shadow .15s}
input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(6,182,212,.25)}
button{cursor:pointer;font-weight:600;transition:all .15s ease}
.btn-primary{background:linear-gradient(135deg,var(--cyan),#0891b2);color:#fff;border:none;padding:.7rem 1.25rem;border-radius:10px;font-weight:600;box-shadow:0 4px 14px rgba(6,182,212,.3)}
.btn-primary:hover{filter:brightness(1.1);box-shadow:0 6px 20px rgba(6,182,212,.4);transform:translateY(-1px)}
.btn-primary:active{transform:translateY(0) scale(.98)}
.btn-ghost{background:rgba(15,23,42,.6);border:1px solid var(--border-bright);color:var(--text-muted);padding:.55rem 1rem;border-radius:8px;font-weight:500;backdrop-filter:blur(6px)}
.btn-ghost:hover{border-color:var(--cyan);color:var(--cyan);background:rgba(6,182,212,.08)}
label{display:block;font-size:.8rem;font-weight:600;color:#9ca3af;margin-bottom:.375rem}
.help{font-size:.75rem;color:var(--text-dim);margin-top:.375rem;line-height:1.5}
.field{margin-bottom:1rem} .field:last-child{margin-bottom:0}
.input-row{display:flex;gap:.5rem} .input-row > *{flex:1}
pre{background:#0a0f1a;border:1px solid var(--border);border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word;color:var(--text-muted);font-size:.8125rem;line-height:1.6}
.card-title svg{width:1.25rem;height:1.25rem;color:var(--cyan)}
.warn svg{flex-shrink:0;margin-top:.125rem}
@keyframes lab-enter{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes lab-glow{0%,100%{opacity:.6}50%{opacity:1}}
#bg-glow{position:fixed;inset:0;pointer-events:none;background:var(--bg-gradient);animation:lab-glow 8s ease infinite;opacity:.6}
.card{animation:lab-enter .5s cubic-bezier(.21,1.02,.73,1) both}
.card:nth-child(2){animation-delay:.08s}
.card:nth-child(3){animation-delay:.16s}
.card:nth-child(4){animation-delay:.24s}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div id="bg-glow" aria-hidden="true"></div>
<main style="max-width:820px;margin:0 auto;padding:3rem 1.5rem 4rem">
<header style="margin-bottom:2rem">
<h1>World Monitor <span class="badge">VULNERABLE LAB</span></h1>
<p style="color:var(--text-muted);font-size:1.05rem;margin-top:.5rem">Deliberately vulnerable playground · Assessment target · Localhost only</p>
</header>
<div class="warn" role="alert"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L22.11 3.86a2 2 0 0 0-1.71-3H3.71a2 2 0 0 0-1.71 3z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
<div><strong>⚠️ Intentionally insecure playground</strong> — runs on loopback for authorized assessment only. Do not expose beyond localhost.</div>
</div>
<div class="card" style="margin-top:1.5rem">
<div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg><span>Demo accounts</span></div>
<ul>
<li><code>alice / user123</code> <span style="color:var(--text-muted);margin-left:.5rem">— regular user</span></li>
<li><code>bob / user456</code> <span style="color:var(--text-muted);margin-left:.5rem">— regular user</span></li>
<li><code>admin / admin123</code> <span style="color:var(--text-muted);margin-left:.5rem">— administrator</span></li>
</ul>
<div style="margin-top:1rem;display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;font-size:.875rem;color:var(--text-muted)">
<span>API base: <code>/api</code></span><span>Auth: <code>Bearer JWT</code> or cookie <code>wm_lab_user</code></span>
<a href="/health" style="margin-left:auto">Health check</a><span style="margin-left:1rem">·</span><a href="/api/monitor">Monitor</a>
</div>
</div>
<div class="card" style="margin-top:1.5rem">
<div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg><span>Try login (browser)</span></div>
<form id="loginForm" onsubmit="event.preventDefault();const u=document.getElementById('u').value, p=document.getElementById('p').value; fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json().then(d=>({ok:r.ok, d}))).then(({ok,d})=>{const out=document.getElementById('out'); out.textContent= ok && d.access_token ? '✓ token OK — length '+d.access_token.length : '✗ login failed: '+(d.error||JSON.stringify(d))}).catch(e=> document.getElementById('out').textContent='error: '+e)">
<div class="input-row">
<div class="field"><label for="u">Username</label><input type="text" id="u" placeholder="alice" autocomplete="username" required></div>
<div class="field"><label for="p">Password</label><input type="password" id="p" placeholder="user123" autocomplete="current-password" required></div>
</div>
<button type="submit" class="btn-primary" style="width:100%;margin-top:.25rem">Sign in</button>
</form>
<pre id="out" aria-live="polite" style="margin-top:1rem;min-height:3rem">(no request yet)</pre>
<p class="help">Tip: <code>curl -X POST http://127.0.0.1:8080/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"user123"}'</code></p>
</div>
<div class="card" style="margin-top:1.5rem">
<div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><path d="M8 21h8M12 17v-4M12 11l-4-4M12 11h8"></svg><span>Fix toggles (restart lab with env)</span></div>
<pre style="margin-top:.75rem;line-height:1.7">WM_LAB_PATCH_IDOR=1    — enforce ownership on /api/reports/<id>
WM_LAB_FIX_HEADERS=1   — enable security headers (HSTS, CSP, etc.)
WM_LAB_PATCH_SQLI=1    — parametrized query on /api/search
WM_LAB_RATELIMIT=1     — 20 req/min per IP on /api/*
WM_LAB_JWT_SECRET=...  — override weak JWT secret (rotation test)</pre>
</div>
<div class="card" style="margin-top:1.5rem">
<div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><line x1="10" y1="9" x2="18" y2="9"></line></svg><span>API quick ref (Bearer JWT)</span></div>
<pre style="margin-top:.75rem;line-height:1.75">GET  /api/              — API root (auth required)
GET  /api/users         — W01: lists all users + password hashes
GET  /api/reports       — W02: lists own reports (IDOR on /:id)
GET  /api/reports/:id   — W02: IDOR across users
GET  /api/search?id=1   — W03: boolean-blind SQLi
GET  /api/monitor       — telemetry + internals leak
GET  /greet?name=test   — W04: reflected XSS indicator
GET  /health            — health check
POST /login             — issues JWT (weak secret) + cookie
</pre>
</div>
<footer style="margin-top:3rem;padding-top:2rem;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.8rem">
<p>World Monitor Vulnerable Lab · <strong>AGPL-3.0</strong> · <a href="https://github.com/koala73/worldmonitor" target="_blank" rel="noopener">Target upstream: koala73/worldmonitor</a></p>
<p style="margin-top:.5rem">Deliberately vulnerable · Assessment target only · Loopback only · <strong>Do not expose</strong></p>
</footer>
</main>
<script>
// Login form handler with loading state
const form = document.getElementById('loginForm');
const out = document.getElementById('out');
form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const u = document.getElementById('u').value;
  const p = document.getElementById('p').value;
  const btn = form.querySelector('button[type=submit]');
  const orig = btn.innerHTML;
  btn.disabled = true; btn.innerHTML = '<span style="display:inline-block;width:1em;height:1em;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite;margin-right:.5rem;vertical-align:-.125em"></span> Signing in…';
  try {
    const res = await fetch('/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u, password:p})});
    const data = await res.json();
    if (res.ok && data.access_token) {
      out.textContent = '✓ token OK — length ' + data.access_token.length + ' · role: ' + data.role;
    } else {
      out.textContent = '✗ login failed: ' + (data.error || JSON.stringify(data));
    }
  } catch (e) {
    out.textContent = 'error: ' + e.message;
  } finally {
    btn.disabled = false; btn.innerHTML = 'Sign in';
  }
});
const style = document.createElement('style');
style.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
document.head.appendChild(style);
</script>
</body></html>"""


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.before_request
def enforce_rate_limit():  # type: ignore[no-untyped-def]
    if not RATELIMIT:
        return None
    # Only apply to /api/* — allow /health and / always
    if not request.path.startswith('/api'):
        return None
    key = request.remote_addr or request.headers.get("X-Forwarded-For", "?").split(",")[0].strip() or "?"
    now = time.time()
    # Prune old entries and prevent unbounded growth
    window = [t for t in _RL_HITS.get(key, []) if now - t < _RL_WINDOW_S]
    # Also prune stale IPs entirely to bound memory (keep at most 1000 IPs)
    if len(_RL_HITS) > 1000:
        # remove oldest 10% of keys
        for k in list(_RL_HITS.keys())[:100]:
            if k != key:
                _RL_HITS.pop(k, None)
    window.append(now)
    _RL_HITS[key] = window
    if len(window) > _RL_MAX:
        retry_after = max(1, int(_RL_WINDOW_S - (now - window[0])))
        resp = jsonify(error="rate limit exceeded", retry_after_s=retry_after)
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        logger.info("rate limited %s at %s (%d in window)", key, request.path, len(window))
        return resp
    return None


@app.before_request
def log_request():  # type: ignore[no-untyped-def]
    # Light access log for lab debugging
    if request.path.startswith("/api") or request.path in ("/login", "/health"):
        logger.info("%s %s from %s", request.method, request.path, request.remote_addr)


@app.get("/health")
def health() -> Response:
    return jsonify(status="ok", service="world-monitor-lab", version="0.9",
                   toggles={"PATCH_IDOR": PATCH_IDOR, "FIX_HEADERS": FIX_HEADERS, "PATCH_SQLI": PATCH_SQLI, "RATELIMIT": RATELIMIT},
                   time=datetime.now(timezone.utc).isoformat())

@app.get("/")
def index() -> Response:
    # NOTE: rendered verbatim (no str.format) — the page contains JS braces.
    return Response(PAGE, mimetype="text/html")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    info = USERS.get(username)
    if not info or info["password"] != password:  # plaintext comparison (W-deliberate)
        return jsonify(error="invalid credentials"), 401
    resp = jsonify(message="welcome", access_token=jwt_sign(
        {"sub": username, "role": info["role"],
         "exp": time.time() + 3600}))
    resp.set_cookie("wm_lab_user", username)  # W06: no flags at all
    return resp


@app.get("/api/")
@app.get("/api")
def api_root():
    ident = current_identity()
    if ident is None:
        return jsonify(error="unauthorized"), 401
    return jsonify(service="world-monitor-api", version="0.9",
                   identity=ident, server_time=datetime.now(timezone.utc).isoformat())


@app.get("/api/users")
def api_users():
    ident = current_identity()
    if ident is None:
        return jsonify(error="unauthorized"), 401
    # W01: admin check MISSING entirely -> vertical privilege escalation
    rows = db().execute("SELECT * FROM users").fetchall()
    return jsonify(users=[dict(r) for r in rows])  # W08: leaks password hashes


@app.get("/api/reports")
def api_reports():
    ident = current_identity()
    if ident is None:
        return jsonify(error="unauthorized"), 401
    mine = [{"id": rid, "title": t, "summary": s}
            for rid, (owner, t, s) in REPORTS.items() if owner == ident["username"]]
    return jsonify(reports=mine)


@app.get("/api/reports/<int:report_id>")
def api_report(report_id: int):
    ident = current_identity()
    if ident is None:
        return jsonify(error="unauthorized"), 401
    entry = REPORTS.get(report_id)
    if entry is None:
        return jsonify(error="not found"), 404
    owner, title, summary = entry
    if PATCH_IDOR and owner != ident["username"] and ident["role"] != "admin":
        return jsonify(error="forbidden: you do not own this report"), 403  # FIXED behavior
    return jsonify(id=report_id, owner=owner, title=title, summary=summary)


@app.get("/api/search")
def api_search():
    q = request.args.get("id", "")
    conn = db()
    try:
        if PATCH_SQLI:
            rows = conn.execute(
                "SELECT id, title, summary FROM reports WHERE id = ?", (q,)
            ).fetchall()
        else:
            # W03: raw string interpolation -> boolean-based blind SQLi
            rows = conn.execute(
                f"SELECT id, title, summary FROM reports WHERE id = '{q}'"
            ).fetchall()
        return jsonify(results=[dict(r) for r in rows], count=len(rows))
    except Exception:
        if PATCH_SQLI:
            return jsonify(error="invalid request"), 400
        tb = traceback.format_exc()  # W04: full traceback returned to client
        return Response(tb, status=500, mimetype="text/plain")


@app.get("/greet")
def greet():
    # W-deliberate: reflects the 'name' parameter unencoded (XSS indicator
    # for the input-validation probe). Inert canaries only in our scanner.
    name = request.args.get("name", "guest")
    return Response(f"<html><body><h2>Hello {name}</h2>"
                    f"<p>Welcome to World Monitor.</p></body></html>",
                    mimetype="text/html")


@app.get("/api/monitor")
def api_monitor():
    # Public telemetry + internal details (W08/W09: exposed + unthrottled)
    return jsonify(
        telemetry=TELEMETRY,
        internals={
            "db_path": DB_PATH,
            "debug": app.debug,
            "python_build": __import__("sys").version.split()[0],
            "secret_key_hint": app.config["SECRET_KEY"][:4] + "***",
        },
    )


@app.get("/api/profile")
def api_profile():
    ident = current_identity()
    if ident is None:
        return jsonify(error="unauthorized"), 401
    info = USERS[ident["username"]]
    return jsonify(username=ident["username"], email=info["email"], role=info["role"],
                   last_login=datetime.now(timezone.utc).isoformat())


if __name__ == "__main__":
    init_db()
    host = os.environ.get("WM_LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("WM_LAB_PORT", "8080"))
    # Safety: refuse to bind to 0.0.0.0 unless explicitly allowed — lab must stay loopback
    if host == "0.0.0.0" and os.environ.get("WM_LAB_ALLOW_PUBLIC") != "1":
        logger.warning("Refusing to bind lab to 0.0.0.0 without WM_LAB_ALLOW_PUBLIC=1 — falling back to 127.0.0.1")
        host = "127.0.0.1"
    print("=" * 70)
    print("  WORLD MONITOR POC PLAYGROUND - INTENTIONALLY VULNERABLE (localhost only)")
    print(f"  Listening: http://{host}:{port}")
    print("  Demo users: alice/user123  bob/user456  admin/admin123")
    print("  Patch toggles: PATCH_IDOR | FIX_HEADERS | PATCH_SQLI | RATELIMIT | JWT_SECRET")
    print("  Health: /health  ·  Docs: see lab/vulnerable-world-monitor/app.py header")
    print("=" * 70)
    logger.info("Lab starting on %s:%d (PATCH_IDOR=%s FIX_HEADERS=%s PATCH_SQLI=%s RATELIMIT=%s)",
                host, port, PATCH_IDOR, FIX_HEADERS, PATCH_SQLI, RATELIMIT)
    app.run(host=host, port=port, debug=False)
