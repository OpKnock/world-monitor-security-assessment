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


# ═════════════════════════════════════════════════════════════════════════
# PREMIUM DARK TECH THEME — Wix-inspired
# ═════════════════════════════════════════════════════════════════════════
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="theme-color" content="#0E0E10"><title>World Monitor Lab — A deliberately vulnerable playground</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,500;9..144,600;9..144,700&family=Inter+Tight:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--paper:42 28% 93%;--ink:240 7% 6%;--bone:42 30% 87%;--ash:36 7% 33%;--oxblood:0 59% 30%;--border:36 14% 78%;--card:42 32% 96%;--mono:"JetBrains Mono",monospace;--sans:"Inter Tight",system-ui,sans-serif;--display:"Fraunces",serif}
*{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}
body{font-family:var(--sans);background:hsl(var(--paper));color:hsl(var(--ink));line-height:1.6;min-height:100vh;-webkit-font-smoothing:antialiased}
a{color:hsl(var(--ink));text-decoration:none;border-bottom:1px solid hsl(var(--ink)/0.2)}a:hover{border-bottom-color:hsl(var(--ink))}
code{font-family:var(--mono);background:hsl(var(--ink)/0.06);padding:2px 6px;border-radius:2px;font-size:.85em}
.container-editorial{width:100%;max-width:1320px;margin:0 auto;padding:0 1.25rem}
@media(min-width:640px){.container-editorial{padding:0 1.5rem}}
@media(min-width:1024px){.container-editorial{padding:0 2.5rem}}
.meta-mono{font-family:var(--mono);font-size:.6875rem;letter-spacing:.04em;text-transform:uppercase;color:hsl(var(--ash))}
.label-eyebrow{font-family:var(--sans);font-size:.6875rem;font-weight:500;letter-spacing:.18em;text-transform:uppercase;color:hsl(var(--ink))}
.display-italic{font-family:var(--display);font-style:italic;font-weight:300}
.font-display{font-family:var(--display)}
.editorial-rule{height:1px;background:hsl(var(--ink)/0.18);width:100%}
.card{background:hsl(var(--card));border:1px solid hsl(var(--border));padding:20px;border-radius:2px}
header.sticky{position:sticky;top:0;z-index:40;background:hsl(var(--paper)/0.9);backdrop-filter:blur(8px);border-bottom:1px solid hsl(var(--ink)/0.1)}
.grain{position:relative}
.grain::after{content:"";position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2'/%3E%3CfeColorMatrix values='0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.14 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");pointer-events:none;mix-blend-mode:multiply;opacity:.5}
@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
@keyframes imageReveal{from{clip-path:inset(0 0 100% 0)}to{clip-path:inset(0 0 0% 0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.reveal{animation:imageReveal 1.1s cubic-bezier(0.7,0,0.2,1) forwards}
input,button{font-family:inherit}
input[type="text"],input[type="password"]{width:100%;background:hsl(var(--paper));border:1px solid hsl(var(--border));padding:10px 12px;border-radius:2px;color:hsl(var(--ink))}
input:focus{outline:none;border-color:hsl(var(--ink));box-shadow:0 0 0 1px hsl(var(--ink))}
button.btn{cursor:pointer;font-weight:500;transition:all .2s}
.btn-primary{background:hsl(var(--ink));color:hsl(var(--paper));border:1px solid hsl(var(--ink));padding:10px 18px;border-radius:2px}
.btn-primary:hover{background:hsl(var(--ink)/0.92)}
.btn-ghost{background:hsl(var(--paper));color:hsl(var(--ink));border:1px solid hsl(var(--ink));padding:8px 14px;border-radius:2px}
.btn-ghost:hover{background:hsl(var(--ink));color:hsl(var(--paper))}
.warn{border:1px solid hsl(0 70% 42% /0.2);background:hsl(0 70% 42% /0.06);color:hsl(0 70% 42%);padding:14px;border-radius:2px;display:flex;gap:12px}
pre{background:hsl(var(--ink));color:hsl(var(--paper));padding:14px;border-radius:2px;overflow:auto;font-family:var(--mono);font-size:.8rem;white-space:pre-wrap;word-break:break-word}
</style>
</head>
<body>
<header class="sticky">
  <div class="container-editorial">
    <div style="display:flex;align-items:center;justify-content:space-between;height:64px">
      <a href="/" style="display:flex;align-items:baseline;gap:12px;border:none"><span class="font-display" style="font-size:22px;letter-spacing:-0.02em">World<span class="display-italic" style="color:hsl(var(--ink)/0.7);margin:0 4px">&</span>Monitor</span><span class="meta-mono" style="display:none">Est. MMXXIV</span></a>
      <nav style="display:flex;gap:28px" class="meta-mono"><a href="/" style="color:hsl(var(--oxblood));border:none">01 Index</a><a href="/health" style="border:none">02 Health</a><a href="/api/monitor" style="border:none">03 Monitor</a><a href="#demo" style="border:none">04 Demo</a></nav>
      <a href="#login" style="display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border:1px solid hsl(var(--ink));font-size:13px;font-weight:500">Commission <span>↗</span></a>
    </div>
  </div>
</header>
<main>
  <div class="container-editorial" style="padding-top:24px">
    <div style="display:grid;grid-template-columns:repeat(12,1fr);gap:16px;border-bottom:1px solid hsl(var(--ink)/0.15);padding-bottom:12px" class="meta-mono">
      <span style="grid-column:span 2;color:hsl(var(--ink))">W&M</span><span style="grid-column:span 2;color:hsl(var(--ink)/0.7)">Vol. II</span><span style="grid-column:span 3;color:hsl(var(--ink)/0.7)">Independent · Security · Editorial</span><span style="grid-column:span 5;text-align:right;color:hsl(var(--ink))" id="labDate"></span>
    </div>
  </div>
  <div class="container-editorial" style="padding-top:48px;padding-bottom:48px">
    <div style="display:grid;grid-template-columns:repeat(12,1fr);gap:40px">
      <div style="grid-column:span 7;display:flex;flex-direction:column;gap:32px">
        <div style="display:flex;align-items:center;gap:16px"><span class="meta-mono">Issue 02 — Lab</span><span style="display:block;height:1px;width:40px;background:hsl(var(--ink)/0.4)"></span><span class="label-eyebrow">the flaw, the fix, the proof</span></div>
        <h1 class="font-display" style="font-size:clamp(2.8rem,8vw,5.5rem);line-height:0.92;letter-spacing:-0.04em">A deliberately <span class="display-italic" style="color:hsl(var(--ink)/0.85)">vulnerable</span> playground.</h1>
        <p style="max-width:520px;color:hsl(var(--ash));font-size:15px">Isolated World Monitor target for authorized assessment. Every flaw is intentional, labeled, and confined to loopback. Never expose beyond localhost.</p>
        <div style="display:flex;gap:12px;flex-wrap:wrap"><a href="#login" class="btn-primary" style="text-decoration:none">Try login — alice/user123</a><a href="/health" class="btn-ghost" style="text-decoration:none">Health check</a></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;padding-top:16px;border-top:1px solid hsl(var(--ink)/0.1)" class="meta-mono"><div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">10</div>Flaws W01–W10</div><div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">4</div>Patch toggles</div><div><div style="font-family:var(--display);font-size:24px;color:hsl(var(--ink))">127.0.0.1:8080</div>Loopback only</div></div>
      </div>
      <div style="grid-column:span 5">
        <div class="reveal grain" style="aspect-ratio:3/4;background:hsl(var(--ink));color:hsl(var(--paper));position:relative;overflow:hidden;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px;text-align:center">
          <div style="width:80px;height:80px;border:1px solid hsl(var(--paper)/0.2);border-radius:50%;display:grid;place-items:center;margin-bottom:20px"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9v-5z"/><path d="M12 8v8"/><path d="M9 12h6"/></svg></div>
          <div class="label-eyebrow" style="color:hsl(var(--paper)/0.7)">World Monitor Lab</div>
          <div class="font-display" style="font-size:22px;color:hsl(var(--paper));margin-top:8px">Secure by<br><span class="display-italic" style="color:hsl(var(--paper)/0.8)">evidence</span> not assumption.</div>
          <div class="meta-mono" style="color:hsl(var(--paper)/0.5);margin-top:16px">INTENTIONALLY VULNERABLE · LOCAL ONLY</div>
          <div style="position:absolute;bottom:0;left:0;right:0;padding:12px 16px;border-top:1px solid hsl(var(--paper)/0.1);display:flex;justify-content:space-between" class="meta-mono"><span>Est. MMXXIV</span><span>Loopback</span></div>
        </div>
      </div>
    </div>
  </div>
  <div class="container-editorial"><div class="editorial-rule" style="margin-bottom:24px"></div></div>
  <div class="container-editorial" style="display:grid;grid-template-columns:1fr 1fr;gap:20px" id="demo">
    <div class="card">
      <div class="label-eyebrow" style="margin-bottom:12px">Demo accounts</div>
      <ul style="list-style:none;padding:0;margin:0;display:grid;gap:8px;font-size:14px"><li style="display:flex;justify-content:space-between;border-bottom:1px solid hsl(var(--border));padding:8px 0"><code>alice / user123</code><span class="meta-mono">regular user</span></li><li style="display:flex;justify-content:space-between;border-bottom:1px solid hsl(var(--border));padding:8px 0"><code>bob / user456</code><span class="meta-mono">regular user</span></li><li style="display:flex;justify-content:space-between;padding:8px 0"><code>admin / admin123</code><span class="meta-mono">administrator</span></li></ul>
      <div style="margin-top:12px;display:flex;gap:8px;font-size:12px" class="meta-mono"><span>API base: <code>/api</code></span><span>Auth: <code>Bearer JWT</code></span></div>
    </div>
    <div class="card" id="login">
      <div class="label-eyebrow" style="margin-bottom:12px">Try login (browser)</div>
      <form id="loginForm" onsubmit="event.preventDefault();loginSubmit();">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div><label class="meta-mono">Username</label><input type="text" id="u" placeholder="alice" autocomplete="username" required></div>
          <div><label class="meta-mono">Password</label><input type="password" id="p" placeholder="user123" autocomplete="current-password" required></div>
        </div>
        <button type="submit" class="btn-primary" style="width:100%;margin-top:12px" id="loginBtn">Sign in</button>
      </form>
      <pre id="out" style="margin-top:12px;min-height:48px">(no request yet)</pre>
      <p style="font-size:11px;color:hsl(var(--ash));margin-top:8px">Tip: <code>curl -X POST http://127.0.0.1:8080/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"user123"}'</code></p>
    </div>
  </div>
  <div class="container-editorial" style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
    <div class="card">
      <div class="label-eyebrow" style="margin-bottom:12px">Fix toggles (restart lab with env)</div>
      <pre style="background:hsl(var(--paper));color:hsl(var(--ink));border:1px solid hsl(var(--border))">WM_LAB_PATCH_IDOR=1    — enforce ownership on /api/reports/&lt;id&gt;
WM_LAB_FIX_HEADERS=1   — enable security headers (HSTS, CSP, etc.)
WM_LAB_PATCH_SQLI=1    — parametrized query on /api/search
WM_LAB_RATELIMIT=1     — 20 req/min per IP on /api/*
WM_LAB_JWT_SECRET=...  — override weak JWT secret</pre>
    </div>
    <div class="card">
      <div class="label-eyebrow" style="margin-bottom:12px">API quick ref (Bearer JWT)</div>
      <pre style="background:hsl(var(--paper));color:hsl(var(--ink));border:1px solid hsl(var(--border))">GET  /api/              — API root (auth required)
GET  /api/users         — W01: lists all users + hashes
GET  /api/reports       — W02: lists own reports (IDOR on /:id)
GET  /api/reports/:id   — W02: IDOR across users
GET  /api/search?id=1   — W03: boolean-blind SQLi
GET  /api/monitor       — telemetry + internals leak
GET  /greet?name=test   — W04: reflected XSS indicator
GET  /health            — health check
POST /login             — issues JWT + cookie</pre>
    </div>
  </div>
</main>
<footer style="border-top:1px solid hsl(var(--border));margin-top:48px">
  <div class="container-editorial" style="padding:24px 0;display:flex;justify-content:space-between;gap:16px" class="meta-mono"><span>World Monitor Vulnerable Lab · AGPL-3.0 · <a href="https://github.com/koala73/worldmonitor" target="_blank">koala73/worldmonitor</a></span><span>Deliberately vulnerable · Loopback only</span></div>
</footer>
<script>
(function(){var el=document.getElementById('labDate');if(el)el.textContent=new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'long',year:'numeric'}).toUpperCase();})();
async function loginSubmit(){
  var u=document.getElementById('u').value, p=document.getElementById('p').value;
  var btn=document.getElementById('loginBtn'), out=document.getElementById('out');
  var orig=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span style="display:inline-block;width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite;margin-right:8px;vertical-align:-2px"></span> Signing in…';
  try{var res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});var data=await res.json();if(res.ok&&data.access_token){out.textContent='✓ token OK — length '+data.access_token.length+' · role: '+data.role}else{out.textContent='✗ login failed: '+(data.error||JSON.stringify(data))}}catch(e){out.textContent='error: '+e.message}finally{btn.disabled=false;btn.innerHTML=orig}
}
document.getElementById('loginForm')?.addEventListener('submit',function(e){e.preventDefault();loginSubmit();});
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