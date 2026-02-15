#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

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

echo "[rust] cargo test --workspace --exclude sentinelpass-ui"
cargo test --workspace --exclude sentinelpass-ui --verbose
