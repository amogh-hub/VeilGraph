#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT/backend"
source .venv/bin/activate
PYTHONPATH=. python -m compileall -q app tests main.py export_openapi.py generate_ts_types.py generate_identity_graph_document.py run_veilbench.py run_stress_matrix.py ../scripts/verify_certificate.py ../scripts/verify_proof_package.py
PYTHONPATH=. pytest -q
PYTHONPATH=. python export_openapi.py

cd "$ROOT/frontend"
npm run generate:api
npm run typecheck
npm run build
