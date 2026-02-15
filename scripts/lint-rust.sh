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

echo "[rust] cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "[rust] cargo clippy --workspace --all-targets"
# Baseline allow-list for existing repository-wide lint debt.
# Remove these allows incrementally as the debt is addressed.
cargo clippy --workspace --all-targets -- \
  -D warnings \
  -A deprecated \
  -A clippy::too_many_arguments \
  -A clippy::needless_borrow \
  -A clippy::redundant_closure \
  -A clippy::collapsible_str_replace \
  -A clippy::bool_assert_comparison \
  -A clippy::unnecessary_lazy_evaluations
