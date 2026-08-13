#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/backend/.venv/bin/python3" ]]; then
  PY="$ROOT/backend/.venv/bin/python3"
else
  PY="$(command -v python3)"
fi
export PYTHONPATH="$ROOT/backend"

echo "== VeilGraph Phase 1 final pre-holdout matrix =="
"$PY" -m pytest -q \
  backend/tests/test_broad_pii_v5.py \
  backend/tests/test_phase1_freeze_v5.py \
  backend/tests/test_external_holdout_ari_protocol.py \
  backend/tests/test_phase1_completion_v9.py \
  backend/tests/test_phase1_freeze_v4.py \
  backend/tests/test_holdout_freeze.py \
  backend/tests/test_judge_dataset_readiness.py \
  backend/tests/test_judge_text_geometry.py

"$PY" scripts/verify_broad_pii_v5_freeze.py
"$PY" scripts/run_phase1_judge_benchmark.py

"$PY" - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('competition/phase1/JUDGE_READINESS_RESULTS.json').read_text())
by={d['dataset_id']:d for d in p['datasets']}
s=by['VG-JUDGE-SHOWCASE-1.0']; c=by['VG-JUDGE-CHAOS-1.0']
checks=[
 ('showcase precision',s['detection']['precision']>=.98,s['detection']['precision']),
 ('showcase recall',s['detection']['recall']>=.98,s['detection']['recall']),
 ('showcase evidence',s['evidence']['evidence_accuracy']>=.95,s['evidence']['evidence_accuracy']),
 ('chaos precision',c['detection']['precision']>=.90,c['detection']['precision']),
 ('chaos recall',c['detection']['recall']>=.90,c['detection']['recall']),
 ('chaos F1',c['detection']['f1']>=.90,c['detection']['f1']),
 ('chaos evidence',c['evidence']['evidence_accuracy']>=.80,c['evidence']['evidence_accuracy']),
]
for name,ok,val in checks: print(('PASS' if ok else 'FAIL'),name,f'{val:.4f}')
if not all(x[1] for x in checks): raise SystemExit('Phase 1 development gate failed')
print('Phase 1 development gates: PASS')
PY

echo
if [[ -f "$ROOT/competition/phase1/EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json" ]]; then
  echo "PHASE 1 DEVELOPMENT MATRIX PASS"
  echo "External ARI holdout is already consumed and preserved. DO NOT rerun it."
  echo "Next closure checks:"
  echo "  ./scripts/run_checks.sh"
  echo "  # then perform the manual L4/L5 recommendation UI acceptance"
  echo "  PYTHONPATH=backend backend/.venv/bin/python3 scripts/verify_phase1_final_acceptance.py"
else
  echo "PRE-HOLDOUT MATRIX PASS"
  echo "No ARI result is present yet. If this detector generation has never seen ARI test rows, run the frozen holdout once."
fi
