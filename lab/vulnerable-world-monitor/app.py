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
  W09  No rate limiting                all endpoints unlimited
  W10  Hardcoded demo secrets          secrets_demo.py (FAKE values)

Fix toggles (used by the retest demo):
  WM_LAB_PATCH_IDOR=1     -> ownership check enforced on /api/reports/<id>
  WM_LAB_FIX_HEADERS=1    -> strict security headers middleware enabled

Run:  python lab/vulnerable-world-monitor/app.py   (listens on 127.0.0.1:8080)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import traceback
from datetime import datetime, timezone

from flask import Flask, Response, g, jsonify, request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "lab.db")
JWT_SECRET = b"worldmonitor-lab-secret"  # W-deliberate: hardcoded weak signing secret

PATCH_IDOR = os.environ.get("WM_LAB_PATCH_IDOR") == "1"
PATCH_SQLI = os.environ.get("WM_LAB_PATCH_SQLI") == "1"
RATELIMIT = os.environ.get("WM_LAB_RATELIMIT") == "1"

FIX_HEADERS = os.environ.get("WM_LAB_FIX_HEADERS") == "1"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("WM_LAB_SESSION_KEY", "not-a-real-production-key"),
    SESSION_COOKIE_HTTPONLY=False,   # W06
    SESSION_COOKIE_SAMESITE=None,    # W06
    SESSION_COOKIE_SECURE=False,     # W06
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
_RL_HITS = {}


def db() -> sqlite3.Connection:
    conn = getattr(g, "_db", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
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
        response.config["SESSION_COOKIE_HTTPONLY"] = True
    return response


PAGE = """<!doctype html><html><head><title>World Monitor Lab</title>
<style>body{{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0}}
main{{max-width:720px;margin:8vh auto;padding:0 20px}}a{{color:#58a6ff}}
.badge{{background:#21262d;border:1px solid #30363d;padding:2px 10px;border-radius:99px;font-size:12px}}
h1{{border-bottom:1px solid #30363d;padding-bottom:12px}}</style></head>
<body><main>
<h1>World Monitor <span class="badge">VULNERABLE LAB</span></h1>
<p>This instance of <em>World Monitor</em> is <strong>intentionally insecure</strong>
and runs on loopback for the authorized assessment demo only.</p>
<ul>
<li>Demo users: alice/user123 &middot; bob/user456 &middot; admin/admin123</li>
<li>API base: <code>/api</code> (Bearer JWT or session cookie)</li>
<li>Do <strong>NOT</strong> expose this service beyond localhost.</li>
</ul>
<form onsubmit="event.preventDefault();fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})}).then(r=>r.json()).then(d=>{document.getElementById('out').textContent=d.access_token?'token OK':'login failed'})">
<h3>Login</h3><input id="u" placeholder="username"><input id="p" type="password" placeholder="password"><button>Sign in</button></form>
<pre id="out"></pre></main></body></html>"""


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.before_request
def enforce_rate_limit():
    if not RATELIMIT:
        return None
    key = request.remote_addr or '?'
    now = time.time()
    window = [t for t in _RL_HITS.get(key, []) if now - t < 60]
    if request.path.startswith('/api'):
        window.append(now)
        _RL_HITS[key] = window
        if len(window) > 60:
            return Response(json.dumps(error='rate limit exceeded'),
                            status=429, mimetype='application/json')
    return None


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
    print("=" * 70)
    print("  WORLD MONITOR POC PLAYGROUND - INTENTIONALLY VULNERABLE (localhost only)")
    print("  Demo users: alice/user123  bob/user456  admin/admin123")
    print("  Patch toggles: PATCH_IDOR | FIX_HEADERS | PATCH_SQLI | RATELIMIT")
    print("=" * 70)
    app.run(host="127.0.0.1", port=int(os.environ.get("WM_LAB_PORT", "8080")), debug=False)
