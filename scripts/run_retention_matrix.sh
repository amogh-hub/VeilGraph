#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"
echo "Retention lifecycle v6: TTL deadline + live worker + fail-safe audit erasure + restart-key-loss cleanup + persisted signed tombstones"
source .venv/bin/activate
PYTHONPATH=. pytest -q tests/test_retention_lifecycle.py tests/test_security.py tests/test_slice_e.py::test_destroy_returns_signed_receipt_and_erases_audit_and_cert_rows
