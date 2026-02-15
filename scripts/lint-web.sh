#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

STAGED_FILES="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "$STAGED_FILES" ]]; then
  exit 0
fi

TS_CHANGED="$(printf '%s\n' "$STAGED_FILES" | rg -N '\.(ts|tsx|mts|cts)$' || true)"
JS_CHANGED="$(printf '%s\n' "$STAGED_FILES" | rg -N '\.(js|mjs|cjs|jsx)$' || true)"

if [[ -n "$TS_CHANGED" ]]; then
  echo "[web] Running TypeScript typecheck"
  if ! command -v npx >/dev/null 2>&1; then
    echo "npx is required for TypeScript linting" >&2
    exit 1
  fi

  if ! npx --no-install tsc --version >/dev/null 2>&1; then
    echo "TypeScript compiler not installed in node_modules; run npm install at repo root" >&2
    exit 1
  fi

  npm run --silent web:typecheck
fi

if [[ -n "$JS_CHANGED" ]]; then
  echo "[web] Checking JavaScript syntax for generated/runtime JS files"
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if [[ -f "$file" ]]; then
      node --check "$file"
    fi
  done <<< "$JS_CHANGED"
fi
