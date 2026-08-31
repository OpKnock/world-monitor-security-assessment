
#!/usr/bin/env python3
"""Ensure real-world-monitor generated files exist (fixes vite import error)."""
from pathlib import Path
import subprocess, sys
ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "targets" / "real-world-monitor" / "api"
FILES = {
    API / "_inventory-facts.generated.js": "// AUTO-GENERATED stub - run: npm run inventory:facts\n// @ts-check\nexport const PUBLIC_INVENTORY_FACTS = {};\n",
    API / "_product-catalog.generated.js": "// AUTO-GENERATED stub - run: npm run product:facts\n// @ts-check\nexport const FALLBACK_PRICES = {};\nexport const PRODUCT_CATALOG = {};\nexport const PUBLIC_PRODUCT_FACTS = {};\nexport const PUBLIC_TIER_GROUPS = [];\nexport const TIER_CONFIG = {};\n",
}
def main():
    missing = []
    for path, stub in FILES.items():
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(stub, encoding="utf-8")
            missing.append(path)
            print(f"[fix] created stub {path.relative_to(ROOT)}")
        else:
            print(f"[ok] {path.relative_to(ROOT)} exists")
    if missing:
        print("\nStubs are minimal - for full data run in targets/real-world-monitor:")
        print("  npm install          # postinstall runs inventory:facts")
        print("  npm run inventory:facts")
        print("  npm run product:facts")
        print("\nThen restart: npm run dev -- --port 3000 --host 127.0.0.1")
        return 1
    import shutil, platform
    npm = "npm.cmd" if platform.system() == "Windows" else "npm"
    if shutil.which(npm) or shutil.which("npm"):
        print("\n[node] npm found - attempting regeneration...")
        for cmd in [[npm, "run", "inventory:facts"], [npm, "run", "product:facts"]]:
            try:
                subprocess.run(cmd, cwd=ROOT/"targets"/"real-world-monitor", timeout=30, check=False, shell=(platform.system()=="Windows"))
                print(f"[node] ran {' '.join(cmd)}")
            except Exception as e:
                print(f"[warn] {e}")
    return 0
if __name__ == "__main__":
    sys.exit(main())
