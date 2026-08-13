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

mkdir -p "$ROOT/competition/phase2"

echo "== VeilGraph Phase 2 — production, security & scale completion =="

echo "[1/8] Preserve Phase-1 detector freeze"
"$PY" "$ROOT/scripts/verify_broad_pii_v5_freeze.py"

echo "[2/8] Focused Phase-2 + security/proof/retention matrix"
"$PY" -m pytest -q \
  backend/tests/test_phase2_production_security_scale.py \
  backend/tests/test_phase2_final_hardening.py \
  backend/tests/test_security.py \
  backend/tests/test_retention_lifecycle.py \
  backend/tests/test_slice_e.py \
  backend/tests/test_final_hardening.py

echo "[3/8] Security self-test"
"$PY" "$ROOT/scripts/run_phase2_security_selftest.py"

echo "[4/8] Performance & scale benchmark"
"$PY" "$ROOT/scripts/run_phase2_benchmarks.py"

echo "[5/8] Sanitized competition release build + self-verification"
"$PY" "$ROOT/scripts/build_competition_release.py"

echo "[6/8] Full authoritative regression + frontend build"
set +e
"$ROOT/scripts/run_checks.sh" 2>&1 | tee "$ROOT/competition/phase2/PHASE2_FULL_REGRESSION.log"
CHECK_STATUS=${PIPESTATUS[0]}
set -e
if [ "$CHECK_STATUS" -ne 0 ]; then
  echo "Full regression failed; Phase 2 remains open."
  exit "$CHECK_STATUS"
fi
echo "VEILGRAPH_RUN_CHECKS_EXIT=0" | tee -a "$ROOT/competition/phase2/PHASE2_FULL_REGRESSION.log"
"$PY" "$ROOT/scripts/record_phase2_regression.py"

echo "[7/8] Finalize signed Phase-2 evidence/freeze"
"$PY" "$ROOT/scripts/finalize_phase2.py"

echo "[8/8] Verify Phase-2 freeze"
"$PY" "$ROOT/scripts/verify_phase2_freeze.py"
"$PY" "$ROOT/scripts/verify_broad_pii_v5_freeze.py"

echo
echo "PHASE 2 — MACHINE GATES: PASS"
echo "Manual Phase-2 evidence acceptance is still required before Phase 3."
