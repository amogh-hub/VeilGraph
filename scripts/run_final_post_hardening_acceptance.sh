#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/backend/.venv/bin/python3}"
if [[ ! -x "$PY" ]]; then PY="$(command -v python3)"; fi
cd "$ROOT"
export PYTHONPATH="$ROOT/backend"
mkdir -p competition/final competition/phase3 competition/phase2

echo '[1/12] Verify exact final v14.6 + v14.9 production base'
"$PY" scripts/verify_final_post_hardening_base.py

echo '[2/12] Verify frozen detector/model surface'
"$PY" scripts/verify_broad_pii_v5_freeze.py

echo '[3/12] Latest native-text / PDF / Phase-3 focused regression'
"$PY" -m pytest -q \
  backend/tests/test_native_pdf_text_hardening_v147.py \
  backend/tests/test_locality_release_hardening_v148.py \
  backend/tests/test_scanned_ocr_residual_closure_v149.py \
  backend/tests/test_phase3_pre_finals.py

echo '[4/12] Fresh real-fixture acceptance — TXT + digital PDF + scanned PDF'
"$PY" scripts/run_final_fixture_acceptance.py

echo '[5/12] Fresh Phase-2 security self-test'
"$PY" scripts/run_phase2_security_selftest.py

echo '[6/12] Fresh performance / scale benchmark'
"$PY" scripts/run_phase2_benchmarks.py

echo '[7/12] Rebuild and self-verify sanitized competition release'
"$PY" scripts/build_competition_release.py

echo '[8/12] L1-L5 calibration + controlled learning + secure-online TLS'
"$PY" scripts/run_gradation_calibration.py
"$PY" scripts/run_model_learning_evidence.py
"$PY" scripts/run_secure_online_acceptance.py

echo '[9/12] Real quantitative COTS benchmark'
PIIMB="${VEILGRAPH_PIIMB_JSONL:-}"
if [[ -z "$PIIMB" && -f "$HOME/Downloads/test_sentences.jsonl" ]]; then
  PIIMB="$HOME/Downloads/test_sentences.jsonl"
fi
if [[ -z "$PIIMB" || ! -f "$PIIMB" ]]; then
  echo 'ERROR: Set VEILGRAPH_PIIMB_JSONL to the frozen PIIMB test_sentences.jsonl path.' >&2
  exit 20
fi
if [[ "${VEILGRAPH_ALLOW_COMMERCIAL_COTS:-0}" != "1" ]]; then
  echo 'ERROR: Set VEILGRAPH_ALLOW_COMMERCIAL_COTS=1 for the explicitly authorized commercial benchmark.' >&2
  exit 21
fi
if [[ -z "${AZURE_LANGUAGE_ENDPOINT:-}" && -z "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}" ]]; then
  echo 'ERROR: Configure a commercial COTS credential set (Azure or AWS). For the accepted run, Azure was used.' >&2
  exit 22
fi
COTS_PY="${VEILGRAPH_COTS_PYTHON:-$ROOT/.cots-benchmark-venv/bin/python}"
if [[ ! -x "$COTS_PY" ]]; then
  echo 'ERROR: .cots-benchmark-venv missing. Run ./scripts/setup_cots_benchmark.sh first.' >&2
  exit 23
fi
COTS_ARGS=("$PIIMB" --limit "${VEILGRAPH_COTS_LIMIT:-100}" --allow-commercial-calls)
PYTHONPATH=backend "$COTS_PY" scripts/run_cots_benchmark.py "${COTS_ARGS[@]}"
"$PY" - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('competition/phase3/COTS_QUANTITATIVE_RESULTS.json').read_text())
if not p.get('literal_ntro_cots_requirement_closed'):
    raise SystemExit('Commercial COTS benchmark did not execute successfully; final freeze remains blocked.')
print('Literal NTRO COTS quantitative requirement: CLOSED')
PY

echo '[10/12] Complete canonical backend + OpenAPI + TypeScript + Vite regression'
set +e
./scripts/run_checks.sh 2>&1 | tee competition/final/FINAL_FULL_REGRESSION.log
RC=${PIPESTATUS[0]}
set -e
"$PY" scripts/record_final_regression.py competition/final/FINAL_FULL_REGRESSION.log --exit-code "$RC"
if [[ "$RC" -ne 0 ]]; then
  echo 'Canonical regression failed; no authoritative freeze was created.' >&2
  exit "$RC"
fi

echo '[11/12] Sign authoritative post-hardening Phase-1 / Phase-2 / Pre-GF freezes'
"$PY" scripts/finalize_post_hardening_freeze.py

echo '[12/12] Independently verify all three signed authoritative freezes'
"$PY" scripts/verify_post_hardening_freeze.py
"$PY" scripts/verify_broad_pii_v5_freeze.py

echo
echo 'VEILGRAPH — FINAL POST-HARDENING PRE-GRAND-FINALE CLOSURE COMPLETE'
echo 'Authoritative manifests are under competition/final/.'
echo 'Only NTRO Stage-2 private Grand Finale dataset evaluation remains pending external data.'
