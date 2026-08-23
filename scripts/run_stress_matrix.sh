#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
source .venv/bin/activate
PYTHONPATH=. python run_stress_matrix.py
