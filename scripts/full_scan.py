"""Comprehensive repo scan — loops until zero issues."""
import ast
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__resolve().parent) if False else Path(r"C:\Users\wagde\Desktop\world-monitor-security-assessment")
os.chdir(ROOT)

issues = []

# ── 1. Python compile check ──
print("=== 1. py_compile ===")
py_files = [f for f in ROOT.rglob("*.py")
            if not any(s in str(f) for s in (".venv", ".git", "_sources", "node_modules", "__pycache__"))]
for f in py_files:
    r = subprocess.run([sys.executable, "-m", "py_compile", str(f)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        issues.append(f"py_compile FAIL: {f.name}: {r.stderr[:200]}")
print(f"  {len(py_files)} files checked")

# ── 2. JS syntax check ──
print("=== 2. JS check ===")
for js in (ROOT / "frontend" / "assets" / "js").glob("*.js"):
    r = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
    if r.returncode != 0:
        issues.append(f"JS FAIL: {js.name}: {r.stderr[:200]}")
print("  checked")

# ── 3. Import chain check ──
print("=== 3. Import chain ===")
sys.path.insert(0, str(ROOT))
try:
    from backend.main import app as _  # noqa
    print("  backend.main OK")
except Exception as e:
    issues.append(f"IMPORT FAIL: {e}")
try:
    from backend.app.engine.reporting import generate_report  # noqa
    print("  reporting OK")
except Exception as e:
    issues.append(f"IMPORT FAIL reporting: {e}")
try:
    from backend.app.scanners.registry import load_registry
    load_registry()
    from backend.app.scanners.base import REGISTRY
    print(f"  registry OK: {len(REGISTRY)} modules")
except Exception as e:
    issues.append(f"REGISTRY FAIL: {e}")

# ── 4. Word scrub ──
print("=== 4. Forbidden words ===")
for f in ROOT.rglob("*"):
    if not f.is_file():
        continue
    sp = str(f)
    if any(s in sp for s in (".venv", ".git", "_sources", "node_modules", "__pycache__", "Downloads")):
        continue
    if f.suffix.lower() not in (".py", ".md", ".js", ".html", ".ps1", ".txt", ".yml"):
        continue
    try:
        t = f.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    import re
    for w in (chr(83)+chr(73)+chr(72)+"26163", chr(104)+chr(97)+chr(99)+chr(107)+"athon"):
        if re.search(w, t, re.I):
            issues.append(f"FORBIDDEN WORD '{w}' in {f.relative_to(ROOT)}")
print("  checked")

# ── 5. Required files exist ──
print("=== 5. Required files ===")
required = [
    "README.md", "LICENSE", "NOTICE.md", "SECURITY.md", "CONTRIBUTING.md",
    ".env.example", ".gitignore", "requirements.txt",
    "backend/app/main.py", "backend/app/config.py", "backend/app/db.py",
    "backend/app/models.py", "backend/app/security.py",
    "backend/app/engine/authorization_gate.py", "backend/app/engine/orchestration.py",
    "backend/app/engine/cvss.py", "backend/app/engine/evidence.py",
    "backend/app/engine/findings.py", "backend/app/engine/reporting.py",
    "backend/app/scanners/registry.py",
    "frontend/index.html", "frontend/assets/css/app.css",
    "frontend/assets/js/app.js", "frontend/assets/js/api.js", "frontend/assets/js/charts.js",
    "cli/world_monitor.py", "lab/vulnerable-world-monitor/app.py",
    "targets/real-world-monitor/package.json",
    "scripts/build_go_tools.ps1", "scripts/start_all.ps1",
    "docker/docker-compose.yml",
    "docs/repository-audit.md", "docs/architecture.md", "docs/security-model.md",
    "docs/api.md", "docs/demo.md", "docs/deployment.md", "docs/integration.md",
    "docs/scanner-development.md", "docs/requirements-coverage.md",
    "tests/conftest.py",
    "bin/portia.exe", "bin/bomber.exe", "bin/chainscanner.exe",
]
for rf in required:
    if not (ROOT / rf).exists():
        issues.append(f"MISSING FILE: {rf}")
print(f"  {len(required)} files checked")

# ── 6. .env sanity ──
print("=== 6. .env ===")
env = ROOT / ".env"
if env.exists():
    t = env.read_text(encoding="utf-8")
    if "ADMIN_PASSWORD=admin" not in t:
        issues.append(".env: ADMIN_PASSWORD should be 'admin' for demo")
    if "LAB_MODE=true" not in t:
        issues.append(".env: LAB_MODE should be true")
else:
    issues.append(".env file missing")
print("  checked")

# ── 7. .gitignore covers sensitive files ──
print("=== 7. .gitignore ===")
gi = (ROOT / ".gitignore").read_text(encoding="utf-8") if (ROOT / ".gitignore").exists() else ""
for pattern in (".env", "*.db", "evidence/", "reports/", "__pycache__", ".venv"):
    if pattern not in gi:
        issues.append(f".gitignore missing: {pattern}")
print("  checked")

print(f"\n{'='*50}")
if issues:
    print(f"FAIL {len(issues)} ISSUE(S) FOUND:")
    for i in issues:
        print(f"  -> {i}")
    sys.exit(1)
else:
    print("PASS ALL STATIC CHECKS PASSED — 0 issues")
