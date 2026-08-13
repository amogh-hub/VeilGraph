#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
echo "Stage-2 Video Safety v5: 13-gate security matrix + physical-frame annotated-export completeness"
source .venv/bin/activate
PYTHONPATH=. pytest -q tests/test_video_redaction.py tests/test_video_annotated_export.py
