#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/backend/.venv/bin/python3}"
if [[ ! -x "$PY" ]]; then PY="$(command -v python3)"; fi
cd "$ROOT"

echo '[1/9] Verify Phase-1 frozen detector/model surface'
PYTHONPATH=backend "$PY" scripts/verify_broad_pii_v5_freeze.py

echo '[2/9] Phase-3 focused regression'
PYTHONPATH=backend "$PY" -m pytest -q backend/tests/test_phase3_pre_finals.py

echo '[3/9] L1-L5 gradation calibration'
PYTHONPATH=backend "$PY" scripts/run_gradation_calibration.py

echo '[4/9] Controlled model-learning evidence'
PYTHONPATH=backend "$PY" scripts/run_model_learning_evidence.py

echo '[5/9] Real TLS secure-online acceptance'
PYTHONPATH=backend "$PY" scripts/run_secure_online_acceptance.py

echo '[6/9] Quantitative COTS benchmark'
if [[ -z "${VEILGRAPH_PIIMB_JSONL:-}" ]]; then
  echo 'ERROR: VEILGRAPH_PIIMB_JSONL must point to the frozen PIIMB test_sentences.jsonl.' >&2
  echo 'Set vendor credentials as documented, then rerun. Commercial calls require VEILGRAPH_ALLOW_COMMERCIAL_COTS=1.' >&2
  exit 20
fi
COTS_ARGS=("$VEILGRAPH_PIIMB_JSONL" --limit "${VEILGRAPH_COTS_LIMIT:-100}")
if [[ "${VEILGRAPH_ALLOW_COMMERCIAL_COTS:-0}" == "1" ]]; then COTS_ARGS+=(--allow-commercial-calls); fi
COTS_PY="${VEILGRAPH_COTS_PYTHON:-$ROOT/.cots-benchmark-venv/bin/python}"
if [[ ! -x "$COTS_PY" ]]; then echo "ERROR: COTS benchmark environment missing. Run ./scripts/setup_cots_benchmark.sh first." >&2; exit 21; fi
PYTHONPATH=backend "$COTS_PY" scripts/run_cots_benchmark.py "${COTS_ARGS[@]}"
"$PY" - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('competition/phase3/COTS_QUANTITATIVE_RESULTS.json').read_text())
if not p.get('literal_ntro_cots_requirement_closed'):
    raise SystemExit('COTS benchmark ran, but no commercial COTS result executed. Configure AWS or Azure credentials and explicitly enable commercial calls.')
print('Literal NTRO COTS quantitative requirement: CLOSED')
PY

echo '[7/9] Canonical full regression + frontend production build'
set +e
./scripts/run_checks.sh 2>&1 | tee competition/phase3/PHASE3_FULL_REGRESSION.log
RC=${PIPESTATUS[0]}
set -e
PYTHONPATH=backend "$PY" scripts/record_phase3_regression.py competition/phase3/PHASE3_FULL_REGRESSION.log --exit-code "$RC"
if [[ "$RC" -ne 0 ]]; then exit "$RC"; fi

echo '[8/9] Sign pre-Grand-Finale freeze'
PYTHONPATH=backend "$PY" scripts/finalize_phase3_pre_finals.py

echo '[9/9] Verify signed pre-Grand-Finale freeze'
PYTHONPATH=backend "$PY" scripts/verify_phase3_pre_finals.py
PYTHONPATH=backend "$PY" scripts/verify_broad_pii_v5_freeze.py

echo
echo 'VEILGRAPH PRE-GRAND-FINALE — COMPLETE & FROZEN'
echo 'Only NTRO Stage-2 private dataset evaluation remains pending external data.'
