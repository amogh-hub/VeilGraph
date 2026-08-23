#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -x "$ROOT/backend/.venv/bin/python" ]] || { echo "Run ./scripts/setup_once.sh first"; exit 1; }
[[ $# -ge 1 ]] || { echo "Usage: $0 /path/to/openpii.jsonl [limit]"; exit 2; }
DATASET="$1"
LIMIT="${2:-500}"
[[ -f "$DATASET" ]] || { echo "Dataset not found: $DATASET"; exit 2; }
cd "$ROOT/backend"
PYTHONPATH=. .venv/bin/python run_veilbench.py --openpii-jsonl "$DATASET" --openpii-limit "$LIMIT"
