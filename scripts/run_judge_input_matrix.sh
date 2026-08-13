#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
echo "VeilGraph Judge Input Readiness v7: native-text geometry + arbitrary layout + existing text/structured regressions"
source .venv/bin/activate
PYTHONPATH=. pytest -q \
  tests/test_judge_text_geometry.py \
  tests/test_native_text_formats.py \
  tests/test_structured_data.py
