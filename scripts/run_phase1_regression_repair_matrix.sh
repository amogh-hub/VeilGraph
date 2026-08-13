#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -x "$ROOT/backend/.venv/bin/python3" ]]; then
  PY="$ROOT/backend/.venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
  PY="$(command -v python3)"
else
  echo "python3 not found" >&2
  exit 2
fi
cd "$ROOT"
# Keep the vision-heavy end-to-end test in its own pytest process. Some native
# OCR/OpenCV builds can hang during teardown after mixed ASGI/vision collections.
PYTHONPATH="$ROOT/backend" "$PY" -m pytest -q backend/tests/test_holdout_freeze.py
PYTHONPATH="$ROOT/backend" "$PY" -m pytest -q \
  backend/tests/test_docx_annotated_output.py::test_docx_acceptance_fixture_structural_context_preview_units_and_full_release
PYTHONPATH="$ROOT/backend" "$PY" -m pytest -q \
  backend/tests/test_video_redaction.py::test_video_level4_end_to_end_passes_13_video_gates_and_proof_package
"$PY" scripts/verify_broad_pii_v4_freeze.py
