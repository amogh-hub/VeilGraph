#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -x "$ROOT/backend/.venv/bin/python" ]] || { echo "Run ./scripts/setup_once.sh first"; exit 1; }
cd "$ROOT/backend"
PYTHONPATH=. .venv/bin/python generate_scanned_test_document.py
PYTHONPATH=. .venv/bin/python generate_identity_graph_document.py
