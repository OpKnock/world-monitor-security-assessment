#!/usr/bin/env bash
# Builds the Go scanner binaries (Linux/macOS counterpart to build_go_tools.ps1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
CANDIDATES_DIR="${1:-$ROOT/_sources/candidates}"
mkdir -p "$BIN" "$CANDIDATES_DIR"
echo "Using candidates dir: $CANDIDATES_DIR"

build_tool() {
  local repo="$1" cmd_path="$2" out_name="$3"
  local src="$CANDIDATES_DIR/$repo"
  if [ ! -d "$src" ]; then
    echo "Cloning $repo ..."
    git clone --depth 1 "https://github.com/OpKnock/$repo.git" "$src"
  fi
  # Patch secrets-scanner upstream nil-context bug (see docs/repository-audit.md)
  if [ "$repo" = "secrets-scanner" ]; then
    local f="$src/internal/cli/root.go"
    if grep -q "rootCmd.Context()" "$f"; then
      echo "  patching $f: fix nil-parent context panic"
      # replace rootCmd.Context() -> context.Background()
      sed -i.bak 's/rootCmd\.Context()/context.Background()/g' "$f"
      # add context import if missing
      if ! grep -q '"context"' "$f"; then
        sed -i.bak 's/^import (/import (\n\t"context"/' "$f"
      fi
      rm -f "$f.bak"
    fi
  fi
  echo "Building $repo -> bin/$out_name ..."
  (cd "$src" && go build -trimpath -o "$BIN/$out_name" "$cmd_path")
  echo "  OK: $BIN/$out_name"
}

build_tool "secrets-scanner" "./cmd/portia" "portia"
build_tool "sbom-generator-vulnerability-matcher" "./cmd/bomber" "bomber"
build_tool "supply-chain-security-analyzer" "./cmd/scanner" "chainscanner"
echo ""
echo "All Go tools built."
