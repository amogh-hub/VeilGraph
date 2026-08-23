#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -x "$ROOT/backend/.venv/bin/python" ]] || { echo "Run ./scripts/setup_once.sh first"; exit 1; }
[[ -d "$ROOT/frontend/node_modules" ]] || { echo "Run ./scripts/setup_once.sh first"; exit 1; }
command -v tesseract >/dev/null || { echo "Tesseract missing: OCR/verification would be inconclusive, so startup is blocked"; exit 1; }
command -v pdftotext >/dev/null || { echo "pdftotext missing: verification would be inconclusive, so startup is blocked"; exit 1; }

cleanup() {
  kill "${BACKEND_PID:-}" "${FRONTEND_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cd "$ROOT/backend"
VEILGRAPH_OFFLINE=true PYTHONPATH=. .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1 &
BACKEND_PID=$!

for _ in {1..40}; do
  if curl -fsS http://127.0.0.1:8000/api/v1/status >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -fsS http://127.0.0.1:8000/api/v1/status >/dev/null || { echo "Backend failed to start"; exit 1; }

cd "$ROOT/frontend"
npm run dev -- --host 127.0.0.1 &
FRONTEND_PID=$!

cat <<'TXT'
VeilGraph Slice E is running.
UI:  http://127.0.0.1:5173
API: http://127.0.0.1:8000/docs

Demos: backend/test_identity_graph_document.pdf, backend/test_docx_privacy_demo.docx, backend/test_video_privacy_demo.mp4, backend/test_video_transient_pii.mp4, backend/test_video_privacy_demo_with_audio.mp4 and backend/test_video_visual_qr_demo.mp4
Levels: L1 direct masking, L2 opaque pseudonymization, L3 context generalization, L4 relationship-safe pseudonymization, L5 Synthetic Twin for CSV/JSON/XLSX.
Proof gate: 12 mandatory attacks for non-video Levels 1–4, 13 for video (including full-timeline change screening and independent QR recovery attack), and 15 for Level 5; VERIFIED_SAFE outputs receive an Ed25519 certificate and tamper-evident audit proof.
Retention: user-selected 1 minute–24 hour encrypted workspace TTL; a lifecycle worker erases expired jobs and leaves only a signed destruction tombstone. Jobs surviving a process restart are erased immediately because their RAM-only keys are unrecoverable.
No installation or model download occurs in this startup script.
For the competition proof, disable Wi-Fi before starting the demo.
TXT
wait
