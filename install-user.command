#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

bash ./install.sh --skip-build "$@"

echo
echo "SentinelPass installation completed."
read -r -p "Press Enter to close..."

