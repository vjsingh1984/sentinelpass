#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "[web] TypeScript typecheck"
npm run web:typecheck

echo "[web] Running TypeScript unit tests with coverage"
npm run test:ts

if [[ "${RUN_EXTENSION_E2E:-0}" == "1" ]]; then
  echo "[web] Running extension e2e suite"
  npm --prefix browser-extension/e2e run test:e2e
fi
