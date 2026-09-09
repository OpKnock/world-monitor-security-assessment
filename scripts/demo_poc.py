#!/usr/bin/env python3
"""Guided stage PoC: break it, scan it (BLOCKED), fix it live, scan again (APPROVED).

Runs BEFORE/AFTER assessments against the single lab :8080, flipping its
fix toggles through the loopback API in between - no restarts, no second
lab. Narrates each step in plain English for non-technical judges.

Every claim prints a verifiable artifact (assessment ID, browser URL,
timestamps, counts, toggle states). A JSON evidence bundle is written to
logs/poc-evidence-<timestamp>.json at the end.

Usage:
  python scripts/start_all.py --fresh        # lab :8080 + platform :8000
  python scripts/demo_poc.py                 # interactive, ENTER advances
  python scripts/demo_poc.py --auto 8        # auto-advance every 8 seconds
  python scripts/demo_poc.py --no-color      # plain output (dumb terminals)
  python scripts/demo_poc.py --self-test     # render check, no servers needed

Stdlib only. ASCII only (safe in every terminal font).
"""
import argparse
import datetime as _dt
import json
import os
import pathlib
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from backend.app.api.misc_routes import compute_health
from backend.app.engine.policy import DEFAULT_POLICY, evaluate_policy

API = "http://127.0.0.1:8000/api"
LAB = "http://127.0.0.1:8080"
TOGGLE_KEYS = ["PATCH_IDOR", "FIX_HEADERS", "PATCH_SQLI", "RATELIMIT"]
MODULES = ["headers", "authentication", "authorization", "api", "input_validation"]
PAGE = 70


class C:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @classmethod
    def paint(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.on else s

    @classmethod
    def red(cls, s): return cls.paint("31;1", s)
    @classmethod
    def green(cls, s): return cls.paint("32;1", s)
    @classmethod
    def yellow(cls, s): return cls.paint("33;1", s)
    @classmethod
    def cyan(cls, s): return cls.paint("36;1", s)
    @classmethod
    def bold(cls, s): return cls.paint("1", s)
    @classmethod
    def dim(cls, s): return cls.paint("2", s)


SEVC = {"CRITICAL": C.red, "HIGH": C.yellow, "MEDIUM": C.yellow,
        "LOW": C.cyan, "INFORMATIONAL": C.dim}


def line(ch="=", n=PAGE):
    print(ch * n)


def banner():
    print()
    line("=")
    print(C.bold("  WORLD MONITOR  --  LIVE SECURITY PoC"))
    print("  HackRoynx 2.0  |  R1-07 Secure Software Delivery  |  Team CodeCarto")
    print("  Claim: vulnerable code gets BLOCKED, patched code gets APPROVED.")
    print("  Everything below is live. Every number is checkable in your browser.")
    line("=")


def step(no, total, title):
    print()
    line("-")
    print(f"  STEP {no}/{total}  {C.bold(title)}")
    line("-")


def plain(msg):
    print(f"  In plain English: {msg}")


def proof(label, value):
    print(f"  [proof] {label}: {C.cyan(str(value))}")


def wait_key(auto):
    if auto:
        time.sleep(auto)
        return
    try:
        input("  Press ENTER to run it live... ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def http(method, url, body=None, token=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")
        except Exception:
            detail = ""
        return e.code, {"_http_error": detail}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return 0, {"_conn_error": str(e)}


def need_server(name, base):
    st, data = http("GET", base + "/health")
    if st != 200 or not isinstance(data, dict):
        print(f"  [!!] {name} is not answering at {base}")
        print("  Fix: python scripts/start_all.py --fresh   (then re-run this demo)")
        sys.exit(2)
    return data


def set_toggles(mapping):
    """Flip lab fixes via the loopback toggle API. Returns the live state."""
    st, data = http("POST", LAB + "/lab/toggles", mapping)
    if st != 200 or not isinstance(data, dict):
        print(f"  [!!] toggle API failed: {data}")
        print("  Fix: restart the lab from latest code (git pull), then re-run.")
        sys.exit(2)
    return data


def show_toggles(state, expect=None):
    for k in TOGGLE_KEYS:
        on = bool(state.get(k))
        want = "" if expect is None else ("  [ok]" if on == expect else "  [!! MISMATCH]")
        print(f"  {k:<13} [{'ON -fixed' if on else 'OFF-broken'}]{want}")
    return state


def login():
    email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    pwd = os.environ.get("ADMIN_PASSWORD", "ChangeMe_Use_Strong_Password_Here")
    st, data = http("POST", API + "/auth/login",
                    {"email": email, "password": pwd})
    if st != 200 or not data or not data.get("access_token"):
        print("  [!!] platform login failed. Check ADMIN_PASSWORD / .env")
        sys.exit(2)
    print(f"  Signed in as {email} (password never shown, never logged)")
    return data["access_token"]


def start_scan(token, target, label):
    st, data = http("POST", API + "/assessments",
                    {"target": target, "modules": MODULES, "authorized": True},
                    token=token, timeout=30)
    if st != 201:
        print(f"  [!!] scan rejected: {data}")
        sys.exit(2)
    aid = data["id"]
    print(f"  Assessment queued: {label}")
    proof("assessment id", aid)
    proof("watch live", f"http://127.0.0.1:8000/#/assessment/{aid}")
    return aid


def poll_scan(token, aid, timeout_s=300):
    t0 = time.time()
    spin = "-\\|/"
    i = 0
    while True:
        st, a = http("GET", API + f"/assessments/{aid}", token=token)
        if st != 200:
            print(f"  [!!] poll failed: {a}")
            sys.exit(2)
        runs = a.get("scan_runs", []) or []
        done = sum(1 for r in runs if r.get("status") in ("completed", "failed", "skipped"))
        total = len(runs) or 1
        pct = int(100 * done / total)
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        el = int(time.time() - t0)
        sys.stdout.write(f"\r  [{bar}] {pct:3d}%  {done}/{total} scanners  {a.get('status','?')}  {el}s {spin[i % 4]}")
        sys.stdout.flush()
        i += 1
        if a.get("status") in ("completed", "failed"):
            print()
            return a
        if time.time() - t0 > timeout_s:
            print("\n  [!!] scan timed out")
            sys.exit(2)
        time.sleep(2)


def findings_table(token, aid, top=8):
    st, rows = http("GET", API + f"/assessments/{aid}/findings", token=token)
    if st != 200 or not isinstance(rows, list):
        print(f"  [!!] findings fetch failed: {rows}")
        sys.exit(2)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    rows.sort(key=lambda f: (order.get(f.get("severity"), 9), -(f.get("cvss_score") or 0)))
    print(f"  Findings returned by the API: {len(rows)}")
    print("  " + "-" * 62)
    for f in rows[:top]:
        sev = f.get("severity", "?")
        paint = SEVC.get(sev, C.bold)
        cvss = f.get("cvss_score")
        print(f"  [{paint(sev):<22}] CVSS {cvss if cvss is not None else '-':<4}  {(f.get('title') or '')[:44]}")
    if len(rows) > top:
        print(f"  ... and {len(rows) - top} more (see browser link above)")
    return rows


def verdict_box(label, health_txt, gate, counts):
    print()
    print("  +" + "-" * 66 + "+")
    print(f"  |  {label:<64} |")
    print(f"  |  Security health: {health_txt:<14} Release gate: {gate:<30} |")
    print(f"  |  {counts:<64} |")
    print("  +" + "-" * 66 + "+")


def assess_verdict(assessment, counts):
    """Same math as the platform: real health + real policy gate."""
    health = int(compute_health(counts or {}))
    runs = assessment.get("scan_runs", []) or []
    has_failed = any(r.get("status") == "failed" for r in runs)
    res = evaluate_policy(counts or {}, health, has_incomplete=False,
                          has_failed=has_failed, policy=DEFAULT_POLICY)
    return health, res["status"], res.get("reasons", [])


def dashboard(token):
    st, d = http("GET", API + "/dashboard", token=token)
    if st != 200:
        print(f"  [!!] dashboard failed: {d}")
        sys.exit(2)
    return d


def main():
    global API, MODULES
    ap = argparse.ArgumentParser(description="Guided World Monitor stage PoC")
    ap.add_argument("--auto", type=int, default=0, help="auto-advance every N seconds (default: wait for ENTER)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--api", default=API, help="platform API base URL")
    ap.add_argument("--modules", default=",".join(MODULES), help="comma-separated scanner modules")
    ap.add_argument("--timeout", type=int, default=300, help="per-scan timeout seconds")
    ap.add_argument("--self-test", action="store_true", help="render check only, no servers needed")
    args = ap.parse_args()
    if args.no_color:
        C.on = False
    API = args.api.rstrip("/")
    MODULES = [m.strip() for m in args.modules.split(",") if m.strip()]

    banner()
    if args.self_test:
        verdict_box("SELF-TEST (no servers touched)", 68, "BLOCKED", "2 CRITICAL, 4 HIGH")
        print("SELF-TEST-OK")
        return 0

    # ---- Step 1: pre-flight ----
    step(1, 4, "PRE-FLIGHT - prove the stage is real")
    plain("we check both servers answer, then break the lab on purpose.")
    hv = need_server("lab      :8080", LAB)
    hp = need_server("platform :8000", API.rsplit("/api", 1)[0] + "/api")
    print(f"  platform health: {hp.get('status')} | version {hp.get('version')}")
    proof("lab time", hv.get("time"))
    token = login()
    dash0 = dashboard(token)
    print("  Breaking all fixes for a deterministic vulnerable baseline:")
    show_toggles(set_toggles({k: False for k in TOGGLE_KEYS}), expect=False)
    wait_key(args.auto)

    # ---- Step 2: scan vulnerable ----
    step(2, 4, "ACT 1 - SCAN THE BROKEN APP")
    plain("hackers' view: we attack our own deliberately-broken app, live.")
    aid_v = start_scan(token, LAB + "/", "POST /api/assessments -> :8080 (all fixes OFF)")
    a_v = poll_scan(token, aid_v, args.timeout)
    sev_v = a_v.get("severity_counts", {}) or {}
    rows_v = findings_table(token, aid_v)
    health_v, gate_v, reasons_v = assess_verdict(a_v, sev_v)
    verdict_box("VULNERABLE APP VERDICT", f"{health_v}/100", C.red(gate_v) if gate_v == "BLOCKED" else gate_v,
                f"{sev_v.get('CRITICAL',0)} CRITICAL, {sev_v.get('HIGH',0)} HIGH, {len(rows_v)} findings total")
    if reasons_v:
        print(f"  Blocked because: {'; '.join(reasons_v)}")
    if rows_v:
        top = rows_v[0]
        proof("top finding", f"{top.get('check_id')} [{top.get('scanner')}] id={str(top.get('id'))[:8]}...")
    proof("finished at", a_v.get("finished_at"))
    wait_key(args.auto)

    # ---- The patch moment: flip fixes live, no restart ----
    print()
    print("  Developers ship the patch: flipping all fixes ON, live, no restart.")
    show_toggles(set_toggles({k: True for k in TOGGLE_KEYS}), expect=True)
    proof("verify yourself", "lab homepage toggle card mirrors this state")

    # ---- Step 3: scan patched ----
    step(3, 4, "ACT 2 - SCAN THE PATCHED APP")
    plain("developers' view: same platform, same checks, fixed code. Watch the verdict flip.")
    aid_f = start_scan(token, LAB + "/", "POST /api/assessments -> :8080 (all fixes ON)")
    a_f = poll_scan(token, aid_f, args.timeout)
    sev_f = a_f.get("severity_counts", {}) or {}
    rows_f = findings_table(token, aid_f)
    health_f, gate_f, reasons_f = assess_verdict(a_f, sev_f)
    verdict_box("PATCHED APP VERDICT", f"{health_f}/100", C.green(gate_f) if gate_f == "APPROVED" else gate_f,
                f"{sev_f.get('CRITICAL',0)} CRITICAL, {sev_f.get('HIGH',0)} HIGH, {len(rows_f)} findings total")
    if reasons_f:
        print(f"  Gate notes: {'; '.join(reasons_f)}")
    proof("finished at", a_f.get("finished_at"))
    wait_key(args.auto)

    # ---- Step 4: finale ----
    step(4, 4, "FINALE - the before/after the judges keep")
    dash1 = dashboard(token)
    print(f"  Platform health now: {dash1.get('health', {}).get('score')} "
          f"(was {dash0.get('health', {}).get('score')})")
    gv = C.red(gate_v) if gate_v == "BLOCKED" else C.green(gate_v)
    gf = C.green(gate_f) if gate_f == "APPROVED" else C.red(gate_f)
    verdict_box("STAGE RESULT",
                f"{health_v} -> {health_f}",
                f"{gv} -> {gf}",
                f"delta {health_f - health_v:+d} pts across {len(rows_v)}->{len(rows_f)} findings")
    print("  Restoring the broken baseline for the next run:")
    show_toggles(set_toggles({k: False for k in TOGGLE_KEYS}), expect=False)
    evidence = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "ps": "R1-07", "team": "CodeCarto",
        "vulnerable": {"target": LAB, "toggles": {k: False for k in TOGGLE_KEYS},
                       "assessment_id": aid_v,
                       "severity_counts": sev_v, "health": health_v, "gate": gate_v,
                       "browser": f"http://127.0.0.1:8000/#/assessment/{aid_v}"},
        "patched": {"target": LAB, "toggles": {k: True for k in TOGGLE_KEYS},
                    "assessment_id": aid_f,
                    "severity_counts": sev_f, "health": health_f, "gate": gate_f,
                    "browser": f"http://127.0.0.1:8000/#/assessment/{aid_f}"},
    }
    os.makedirs("logs", exist_ok=True)
    path = f"logs/poc-evidence-{int(time.time())}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=2)
    proof("evidence bundle", path)
    print()
    print(C.bold("  That is the whole story: scan, score, gate, prove. Thank you."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
