#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
export PYTHONPATH="$PWD"
python3 -m pytest -q \
  tests/test_phase1_completion_v9.py \
  tests/test_phase1_freeze_v4.py \
  tests/test_external_holdout_spia_protocol.py \
  tests/test_broad_pii_v2.py \
  tests/test_broad_pii_v3.py \
  tests/test_broad_pii_v3_overlap_regression.py \
  tests/test_semantic_ner_v1.py \
  tests/test_detection.py \
  tests/test_structured_data.py \
  tests/test_judge_dataset_readiness.py \
  tests/test_judge_text_geometry.py \
  tests/test_verification_qr_review.py
cd "$ROOT"
./scripts/verify_broad_pii_v4_freeze.py
PYTHONPATH=backend python3 scripts/run_phase1_judge_benchmark.py
