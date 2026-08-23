#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; else PY=python3; fi
PYTHONPATH=. "$PY" -m pytest -q tests/test_judge_dataset_readiness.py
