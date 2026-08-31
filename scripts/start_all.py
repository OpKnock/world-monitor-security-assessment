
#!/usr/bin/env python3
"""
One-command dev runner ? starts lab :8080 + platform :8000 + real app :3000 (optional).

Usage (one terminal, one command):
  python scripts/start_all.py
  python scripts/start_all.py --no-real-app   # skip real-world-monitor
  python scripts/start_all.py --fix-headers --patch-idor --enable-fuzzing

What it does:
  - Checks .venv exists, otherwise hints `pip install -r requirements.txt`
  - Checks ports 8080/8000/3000 ? if already listening, skips that service ("already existence")
  - Starts vulnerable lab (Flask) and platform (uvicorn) and, if available, real app (vite)
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

def main():
    ap = argparse.ArgumentParser(description="One-command dev runner")
    ap.add_argument("--no-real-app", action="store_true", help="skip real-world-monitor :3000")
    ap.add_argument("--fix-headers", action="store_true", help="WM_LAB_FIX_HEADERS=1")
    ap.add_argument("--patch-idor", action="store_true", help="WM_LAB_PATCH_IDOR=1")
    ap.add_argument("--patch-sqli", action="store_true", help="WM_LAB_PATCH_SQLI=1")
    ap.add_argument("--ratelimit", action="store_true", help="WM_LAB_RATELIMIT=1")
    ap.add_argument("--enable-fuzzing", action="store_true", help="WM_ENABLE_FUZZING=1")
    args = ap.parse_args()

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
        app_cmd = f".venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
        real_cmd = f"npm run dev -- --port 3000 --host 127.0.0.1"
        popup("lab", lab_cmd, port=8080)
        import time as _t; _t.sleep(1.0)
        popup("platform", app_cmd, port=8000)
        if not args.no_real_app and REAL_DIR.exists() and (REAL_DIR / "node_modules").exists():
            popup("real-app", real_cmd, port=3000)
        elif not args.no_real_app:
            print("[real] skipped ? run: cd targets/real-world-monitor && npm install")
        print("\n[done] 3 terminals popped up. Close windows to stop or Ctrl+C this window to exit.")
        return 0

    procs = []

    def start(name, cmd, cwd, port=None):
        if port and is_port_open("127.0.0.1", port):
            print(f"[skip] {name} already listening on :{port} ? skipping (already existence)")
            return None
        print(f"[start] {name}: {' '.join(cmd)}  (cwd={cwd})")
        p = subprocess.Popen(cmd, cwd=str(cwd), env=env if name=="lab" else os.environ.copy(),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        procs.append((name, p))
        return p

    # 1. lab :8080
    lab = start("lab", LAB_PY, ROOT, port=8080)
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
