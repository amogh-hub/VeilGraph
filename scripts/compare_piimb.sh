#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
[[ -x "$PY" ]] || { echo "VeilGraph virtual environment not found: $PY"; exit 1; }
exec "$PY" "$ROOT/scripts/compare_piimb.py" "$@"
