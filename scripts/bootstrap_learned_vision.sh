#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"
python3 scripts/provision_learned_vision.py

cd "$ROOT/browser-extension"
npm install --package-lock-only --ignore-scripts
npm ci --ignore-scripts

cd "$ROOT"
./scripts/verify_sih_checkpoint.sh
