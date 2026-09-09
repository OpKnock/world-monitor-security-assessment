
#!/usr/bin/env python3
"""
One-command dev runner ? starts lab :8080 + platform :8000 + real app :3000 (optional).

Usage (one terminal, one command):
  python scripts/start_all.py
  python scripts/start_all.py --no-real-app   # skip real-world-monitor
  python scripts/start_all.py --fix-headers --patch-idor --enable-fuzzing
  python scripts/start_all.py --poc           # PoC stage mode: + PATCHED lab :8090 (all fix toggles)
  python scripts/start_all.py --poc --fresh # kill stale servers + git pull, then start (stage-ready)

What it does:
  - Checks .venv exists, otherwise hints `pip install -r requirements.txt`
  - With --fresh: kills anything on our ports, `git pull --ff-only`, then starts
  - Checks ports 8080/8000/3000 ? if already listening, skips that service ("already existence")
  - Starts vulnerable lab (Flask) and platform (uvicorn) and, if available, real app (vite)
  - With --poc, also starts a second, fully-patched lab on :8090 for before/after demos
  - Streams prefixed logs, Ctrl+C stops all

This replaces the old "Three-Terminal Setup" with one command. For manual 3 terminals, see README Advanced.
"""
import argparse, os, socket, subprocess, sys, time, signal, shutil, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
UVICORN = [str(VENV_PY), "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]
LAB_PY = [str(VENV_PY), "lab/vulnerable-world-monitor/app.py"]
REAL_DIR = ROOT / "targets" / "real-world-monitor"

def is_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False

def which(cmd):
    return shutil.which(cmd)


def _managed_ports(args):
    ports = [8080, 8000]
    if args.poc:
        ports.append(8090)
    if not args.no_real_app:
        ports.append(3000)
    return ports


def _kill_port(port):
    """Kill listeners on a port. Returns killed PIDs (skips self + system)."""
    import re
    me = os.getpid()
    killed = []
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano"], capture_output=True,
                                 text=True, timeout=15).stdout
            pids = set()
            for line in out.splitlines():
                m = re.search(r"TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)", line)
                if m and int(m.group(1)) == port:
                    pids.add(int(m.group(2)))
            for pid in pids:
                if pid in (0, 4, me):
                    continue
                r = subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                                   capture_output=True, timeout=15)
                if r.returncode == 0:
                    killed.append(pid)
        else:
            out = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True,
                                 text=True, timeout=15).stdout
            for tok in out.split():
                try:
                    pid = int(tok)
                except ValueError:
                    continue
                if pid == me:
                    continue
                r = subprocess.run(["kill", "-9", str(pid)], capture_output=True, timeout=15)
                if r.returncode == 0:
                    killed.append(pid)
    except Exception as e:
        print(f"[fresh] port scan failed for :{port}: {e}")
    return killed


def _fresh_ports(args):
    for port in _managed_ports(args):
        if not is_port_open("127.0.0.1", port):
            continue
        killed = _kill_port(port)
        if killed:
            print(f"[fresh] killed stale PID(s) {killed} on :{port}")
        else:
            print(f"[fresh] :{port} busy but no killable listener found — will skip if still busy")
    for _ in range(10):
        if not any(is_port_open("127.0.0.1", p) for p in _managed_ports(args)):
            break
        time.sleep(0.5)


def _fresh_pull():
    try:
        r = subprocess.run(["git", "pull", "--ff-only"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=60)
        tail = (r.stdout + r.stderr).strip().splitlines()
        tail = tail[-1] if tail else "(no output)"
        if r.returncode == 0:
            print(f"[fresh] git pull: {tail}")
        else:
            print(f"[fresh] git pull failed ({tail}) — continuing with local code")
    except Exception as e:
        print(f"[fresh] git pull unavailable ({e}) — continuing with local code")

def main():
    ap = argparse.ArgumentParser(description="One-command dev runner")
    ap.add_argument("--no-real-app", action="store_true", help="skip real-world-monitor :3000")
    ap.add_argument("--fix-headers", action="store_true", help="WM_LAB_FIX_HEADERS=1")
    ap.add_argument("--patch-idor", action="store_true", help="WM_LAB_PATCH_IDOR=1")
    ap.add_argument("--patch-sqli", action="store_true", help="WM_LAB_PATCH_SQLI=1")
    ap.add_argument("--ratelimit", action="store_true", help="WM_LAB_RATELIMIT=1")
    ap.add_argument("--enable-fuzzing", action="store_true", help="WM_ENABLE_FUZZING=1")
    ap.add_argument("--poc", action="store_true",
                    help="PoC stage mode: also start a fully-patched lab on :8090 (all fix toggles)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not auto-open browser tabs; print URLs only")
    ap.add_argument("--fresh", action="store_true",
                    help="kill stale servers on our ports + git pull --ff-only, then start")
    args = ap.parse_args()

    if args.fresh:
        _fresh_ports(args)
        _fresh_pull()

    if not VENV_PY.exists():
        print("[error] .venv not found at", VENV_PY)
        print("  Fix: python -m venv .venv && .venv\\Scripts\\activate (Win) or source .venv/bin/activate (Mac/Linux)")
        print("       pip install -r requirements.txt")
        sys.exit(1)

    # env for lab/platform
    env = os.environ.copy()
    if args.fix_headers: env["WM_LAB_FIX_HEADERS"] = "1"
    if args.patch_idor: env["WM_LAB_PATCH_IDOR"] = "1"
    if args.patch_sqli: env["WM_LAB_PATCH_SQLI"] = "1"
    if args.ratelimit: env["WM_LAB_RATELIMIT"] = "1"
    if args.enable_fuzzing: env["WM_ENABLE_FUZZING"] = "1"

    # Windows pop-up mode ? 3 terminals (requested)
    if os.name == "nt":
        def popup(name, cmd_str, port=None):
            if port and is_port_open("127.0.0.1", port):
                print(f"[skip] {name} already listening on :{port} ? skipping (already existence)")
                return None
            print(f"[popup] {name} -> new PowerShell window")
            # Use Start-Process powershell -NoExit to pop up
            ps_cmd = f"Set-Location '{ROOT}'; {cmd_str}"
            subprocess.Popen(["powershell", "-NoExit", "-Command", ps_cmd], creationflags=subprocess.CREATE_NEW_CONSOLE if hasattr(subprocess, "CREATE_NEW_CONSOLE") else 0)
            return True
        # Build cmd strings with env toggles
        lab_env = ""
        if args.fix_headers: lab_env += "$env:WM_LAB_FIX_HEADERS='1'; "
        if args.patch_idor: lab_env += "$env:WM_LAB_PATCH_IDOR='1'; "
        if args.patch_sqli: lab_env += "$env:WM_LAB_PATCH_SQLI='1'; "
        if args.ratelimit: lab_env += "$env:WM_LAB_RATELIMIT='1'; "
        lab_cmd = f"{lab_env}.venv/Scripts/python.exe lab/vulnerable-world-monitor/app.py"
        poc_env = ("$env:WM_LAB_PORT='8090'; $env:WM_LAB_FIX_HEADERS='1'; "
                   "$env:WM_LAB_PATCH_IDOR='1'; $env:WM_LAB_PATCH_SQLI='1'; $env:WM_LAB_RATELIMIT='1'; ")
        poc_cmd = f"{poc_env}.venv/Scripts/python.exe lab/vulnerable-world-monitor/app.py"
        app_cmd = f".venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
        real_cmd = f"npm run dev -- --port 3000 --host 127.0.0.1"
        popup("lab", lab_cmd, port=8080)
        import time as _t; _t.sleep(1.0)
        if args.poc:
            popup("lab-fixed", poc_cmd, port=8090)
            _t.sleep(1.0)
        popup("platform", app_cmd, port=8000)
        if not args.no_real_app and REAL_DIR.exists() and (REAL_DIR / "node_modules").exists():
            popup("real-app", real_cmd, port=3000)
        elif not args.no_real_app:
            print("[real] skipped - run: cd targets/real-world-monitor && npm install")
        # auto-open browsers for first 2 terminals after a short delay
        try:
            import webbrowser
            if args.no_browser:
                print("[open] --no-browser: open tabs yourself:")
                for _name, _url, _port in (("lab", "http://127.0.0.1:8080", 8080),
                                           ("platform", "http://127.0.0.1:8000", 8000),
                                           ("lab-fixed", "http://127.0.0.1:8090", 8090) if args.poc else (None, None, None)):
                    if _name and is_port_open("127.0.0.1", _port):
                        print(f"   {_name}: {_url}")
            else:
                import time as _t2; _t2.sleep(2.0)
                if is_port_open("127.0.0.1", 8080):
                    webbrowser.open("http://127.0.0.1:8080")
                    print("[open] browser lab http://127.0.0.1:8080")
                if is_port_open("127.0.0.1", 8000):
                    webbrowser.open("http://127.0.0.1:8000")
                    print("[open] browser platform http://127.0.0.1:8000")
                if args.poc and is_port_open("127.0.0.1", 8090):
                    webbrowser.open("http://127.0.0.1:8090")
                    print("[open] browser lab-fixed http://127.0.0.1:8090")
        except Exception as _e:
            print(f"[warn] auto-open browser failed: {_e}")
        if args.poc:
            print("\n[done] PoC mode: lab :8080 (VULNERABLE) + lab-fixed :8090 (PATCHED) + platform :8000 are up.")
            print("       Run: python scripts/demo_poc.py  for the guided stage demo.")
        else:
            print("\n[done] 3 terminals popped up. Close windows to stop or Ctrl+C this window to exit.")
        return 0

    procs = []

    def start(name, cmd, cwd, port=None, extra_env=None):
        if port and is_port_open("127.0.0.1", port):
            print(f"[skip] {name} already listening on :{port} ? skipping (already existence)")
            return None
        print(f"[start] {name}: {' '.join(cmd)}  (cwd={cwd})")
        child_env = dict(extra_env) if extra_env is not None else (env if name == "lab" else os.environ.copy())
        p = subprocess.Popen(cmd, cwd=str(cwd), env=child_env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        procs.append((name, p))
        return p

    # 1. lab :8080
    lab = start("lab", LAB_PY, ROOT, port=8080)
    time.sleep(1.5)
    # 1b. patched lab :8090 for PoC before/after demos
    if args.poc:
        poc_env = dict(env)
        poc_env.update({"WM_LAB_PORT": "8090", "WM_LAB_FIX_HEADERS": "1",
                        "WM_LAB_PATCH_IDOR": "1", "WM_LAB_PATCH_SQLI": "1",
                        "WM_LAB_RATELIMIT": "1"})
        start("lab-fixed", LAB_PY, ROOT, port=8090, extra_env=poc_env)
        time.sleep(1.5)
    # 2. platform :8000
    platform = start("platform", UVICORN, ROOT, port=8000)
    time.sleep(1.5)
    # 3. real app :3000 (optional)
    real = None
    if not args.no_real_app and REAL_DIR.exists():
        # ensure generated files exist
        gen1 = REAL_DIR / "api" / "_inventory-facts.generated.js"
        if not gen1.exists():
            print("[real] _inventory-facts.generated.js missing ? running ensure script...")
            try:
                subprocess.run([str(VENV_PY), "scripts/ensure_real_app.py"], cwd=str(ROOT), timeout=40, check=False)
            except Exception as e:
                print(f"[warn] ensure failed: {e}")
        if (REAL_DIR / "package.json").exists():
            npm = "npm.cmd" if os.name == "nt" else "npm"
            if which(npm) or which("npm"):
                # npm install is heavy; only run dev if node_modules exists, else hint
                if not (REAL_DIR / "node_modules").exists():
                    print("[real] node_modules missing ? run: cd targets/real-world-monitor && npm install (takes ~1 min)")
                    print("[skip] real app :3000 ? missing node_modules (optional, platform works without it)")
                else:
                    real = start("real-app", [npm, "run", "dev", "--", "--port", "3000", "--host", "127.0.0.1"], REAL_DIR, port=3000)
            else:
                print("[skip] real app :3000 ? npm not found (optional)")
        else:
            print("[skip] real app ? no package.json")
    else:
        if args.no_real_app:
            print("[skip] real app ? --no-real-app")
        elif not REAL_DIR.exists():
            print("[skip] real app ? not cloned (git clone --recurse-submodules)")

    if not procs:
        print("[done] nothing to start ? all ports already busy. Visit http://127.0.0.1:8000")
        return 0

    print("\n" + "="*60)
    print("  Platform : http://127.0.0.1:8000  (admin@example.com / ChangeMe...)")
    print("  Lab      : http://127.0.0.1:8080  (alice/user123) localhost only")
    if args.poc:
        print("  Lab-fixed: http://127.0.0.1:8090  (PATCHED demo target)")
        print("  Next     : python scripts/demo_poc.py  (guided stage demo)")
    if real:
        print("  Real app : http://127.0.0.1:3000  (optional)")
    print("  Logs below are prefixed [lab]/[platform]/[real-app]. Ctrl+C to stop all.")
    print("="*60 + "\n")

    # stream logs
    import threading, queue
    q = queue.Queue()
    def pump(name, proc):
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            q.put(f"[{name}] {line.rstrip()}")
    threads = []
    for name, proc in procs:
        t = threading.Thread(target=pump, args=(name, proc), daemon=True)
        t.start()
        threads.append(t)

    def stop_all(signum=None, frame=None):
        print("\n[stop] shutting down...")
        for _, p in procs:
            try:
                p.terminate()
            except: pass
        time.sleep(1)
        for _, p in procs:
            try:
                p.kill()
            except: pass
        sys.exit(0)
    signal.signal(signal.SIGINT, stop_all)
    if os.name != "nt":
        signal.signal(signal.SIGTERM, stop_all)

    try:
        while True:
            try:
                line = q.get(timeout=0.5)
                print(line)
            except queue.Empty:
                # check if all procs died
                if all(p.poll() is not None for _, p in procs if p):
                    print("[exit] all processes ended")
                    break
    except KeyboardInterrupt:
        stop_all()
    return 0

if __name__ == "__main__":
    sys.exit(main())
