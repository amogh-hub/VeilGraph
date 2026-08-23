#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/backend/.venv/bin/python3"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3 || true)"
fi
if [ -z "$PY" ]; then
  echo "No Python interpreter available."
  exit 2
fi
export PYTHONPATH="$ROOT/backend"

echo "== VeilGraph Phase 1 closure compatibility matrix =="

"$PY" -m pytest -q \
  backend/tests/test_semantic_ner_v1.py \
  backend/tests/test_native_text_formats.py \
  backend/tests/test_broad_pii_v5.py \
  backend/tests/test_phase1_freeze_v5.py

"$PY" scripts/verify_broad_pii_v5_freeze.py

"$PY" - <<'PY'
import json
from pathlib import Path
p = Path("competition/phase1/EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json")
if not p.is_file():
    raise SystemExit("Missing preserved ARI holdout result; do not fabricate or rerun blindly.")
x = json.loads(p.read_text(encoding="utf-8"))
assert x.get("results", {}).get("documents") == 1201
assert x.get("raw_holdout_persisted_in_repository") is False
assert x.get("detector_tuned_on_test_rows") is False
assert x.get("source", {}).get("data_artifact_identity_verified") is True
r = x["results"]
print(
    "Preserved ARI observation:",
    f"exact_F1={r.get('exact',{}).get('f1')}",
    f"relaxed_F1={r.get('relaxed_compatible_span_coverage',{}).get('f1')}",
    f"critical_recall={r.get('critical_shared_recall')}",
    f"contextual_recall={r.get('contextual_shared_recall')}",
    f"quality_gate={'PASS' if x.get('quality_gate',{}).get('pass') else 'FAIL (documented limitation)'}",
)
print("ARI result preserved; no rerun performed.")
PY

echo
echo "PHASE 1 CLOSURE COMPATIBILITY MATRIX PASS"
echo "Next: ./scripts/run_checks.sh"
