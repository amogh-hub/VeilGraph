#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -x "$ROOT/backend/.venv/bin/python" ]] || { echo "Existing backend/.venv not found"; exit 1; }
[[ $# -eq 1 ]] || { echo "Usage: $0 /path/to/test_sentences.jsonl"; exit 2; }
DATASET="$1"
[[ -f "$DATASET" ]] || { echo "Dataset not found: $DATASET"; exit 2; }
cd "$ROOT/backend"
PYTHONPATH=. ./.venv/bin/python run_holdout_nemotron.py "$DATASET" --limit 100000
