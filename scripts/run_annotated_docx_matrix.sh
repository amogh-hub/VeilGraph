#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Backend virtual environment missing. Run ./scripts/setup_once.sh first."; exit 1; }
cd "$ROOT/backend"
PYTHONPATH=. "$PY" -m pytest -q tests/test_docx_annotated_output.py
