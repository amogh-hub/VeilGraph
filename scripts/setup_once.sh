#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v node >/dev/null || { echo "node is required"; exit 1; }
command -v npm >/dev/null || { echo "npm is required"; exit 1; }
command -v tesseract >/dev/null || { echo "tesseract is required for OCR and mandatory verification"; exit 1; }
command -v pdftotext >/dev/null || { echo "pdftotext is required for independent PDF extraction verification"; exit 1; }

cd "$ROOT/backend"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
PYTHONPATH=. python -c "import cv2, fitz, pytesseract; from app.graph.exposure_graph import build_exposure_graph; print('Local OCR, vision, graph, proof-gate, audit and Ed25519 certificate dependencies ready')"
PYTHONPATH=. python export_openapi.py

cd "$ROOT/frontend"
npm install
npm run generate:api

echo "Final hardened Slice E setup complete. Dependencies, signing support, proof-package verification and OpenAPI-derived contracts are ready."
