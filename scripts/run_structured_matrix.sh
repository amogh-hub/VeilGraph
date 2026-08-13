#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
PYTHON="./.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "VeilGraph backend virtual environment not found at backend/.venv" >&2
  exit 1
fi
PYTHONPATH=. "$PYTHON" -m pytest -q tests/test_structured_data.py
