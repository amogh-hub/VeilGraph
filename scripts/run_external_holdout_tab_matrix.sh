#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python3"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3 || true)"
fi
if [[ -z "$PY" ]]; then
  echo "ERROR: python3 not found" >&2
  exit 1
fi
cd "$ROOT"
PYTHONPATH="$ROOT/backend" "$PY" -m pytest -q backend/tests/test_external_holdout_tab_protocol.py
"$PY" scripts/verify_broad_pii_v4_freeze.py
