#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if command -v trivy >/dev/null 2>&1; then
  echo "[security] Running Trivy filesystem scan"
  trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --no-progress .
  exit 0
fi

echo "[security] Trivy not found; running equivalent checks"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "[security] Installing cargo-audit"
  cargo install cargo-audit --locked
fi

AUDIT_DB="${CARGO_AUDIT_DB:-/tmp/sentinelpass-advisory-db}"
mkdir -p "$AUDIT_DB"

echo "[security] cargo audit (db: $AUDIT_DB)"
cargo audit --db "$AUDIT_DB"

if [[ -f browser-extension/e2e/package-lock.json ]]; then
  echo "[security] npm audit (browser-extension/e2e)"
  (
    cd browser-extension/e2e
    npm audit --audit-level=high
  )
else
  echo "[security] Skipping npm audit; no lockfile found in browser-extension/e2e"
fi
