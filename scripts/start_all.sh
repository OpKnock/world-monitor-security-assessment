#!/usr/bin/env bash
# One-command dev runner (Mac/Linux) ? lab :8080 + platform :8000 + real app :3000 (optional)
# Usage: chmod +x scripts/start_all.sh && ./scripts/start_all.sh
#        ./scripts/start_all.sh --fix-headers --patch-idor
# Or: python scripts/start_all.py
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then PY="python3"; fi
ARGS=("scripts/start_all.py")
for a in "$@"; do
  case "$a" in
    --fix-headers) ARGS+=("--fix-headers") ;;
    --patch-idor) ARGS+=("--patch-idor") ;;
    --patch-sqli) ARGS+=("--patch-sqli") ;;
    --ratelimit) ARGS+=("--ratelimit") ;;
    --enable-fuzzing) ARGS+=("--enable-fuzzing") ;;
    --no-real-app) ARGS+=("--no-real-app") ;;
    *) ARGS+=("$a") ;;
  esac
done
echo "[start_all.sh] delegating to: $PY ${ARGS[*]}"
exec "$PY" "${ARGS[@]}"
