#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${VEILGRAPH_VERIFY_PYTHON:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  echo "python3 is required to run the VeilGraph verification harness" >&2
  exit 127
}

exec "$PYTHON_BIN" scripts/verify_sih_checkpoint.py "$@"
