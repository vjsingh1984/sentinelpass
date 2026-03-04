#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MIN_LINES="${RUST_COVERAGE_MIN:-50}"

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/sentinelpass-target}"
mkdir -p "$CARGO_TARGET_DIR"

TMP_ROOT="$CARGO_TARGET_DIR/.tmp"
mkdir -p "$TMP_ROOT"
export TMPDIR="$TMP_ROOT"
export TMP="$TMP_ROOT"
export TEMP="$TMP_ROOT"
export RUSTC_TMPDIR="$CARGO_TARGET_DIR/.rustc-tmp"
mkdir -p "$RUSTC_TMPDIR"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "[rust] cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov --locked"
  exit 1
fi

mkdir -p target/llvm-cov

echo "[rust] Running LLVM coverage (line threshold: ${MIN_LINES}%)"
# Build with all features except x11 (requires X11 libraries not available in CI)
FEATURES="--all-features --no-default-features"
if [[ "$(uname)" == "Linux" ]]; then
  # On Linux, exclude x11 feature to avoid requiring X11 libraries
  FEATURES="$FEATURES --features sentinelpass-core/sync"
  FEATURES="$FEATURES --features sentinelpass-core/autofill"
  FEATURES="$FEATURES --features sentinelpass-core/ssh"
  FEATURES="$FEATURES --features sentinelpass-core/totp"
  FEATURES="$FEATURES --features sentinelpass-core/biometric"
  FEATURES="$FEATURES --features sentinelpath-core/import_export"
fi

cargo llvm-cov \
  --workspace \
  --exclude sentinelpass-ui \
  --exclude sentinelpass-relay \
  $FEATURES \
  --lcov \
  --output-path target/llvm-cov/lcov.info \
  --fail-under-lines "${MIN_LINES}" \
  --ignore-filename-regex '(sentinelpass-cli/src/main\.rs|sentinelpass-daemon/src/main\.rs|sentinelpass-host/src/main\.rs|sentinelpass-relay/|sync/(client|engine)\.rs)' \
  --summary-only

echo "[rust] Coverage report generated at target/llvm-cov/lcov.info"
