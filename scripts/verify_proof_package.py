#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.proof.package import verify_proof_package_bytes  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/verify_proof_package.py <complete-proof-package.zip>")
        return 2
    package_path = Path(sys.argv[1])
    try:
        result = verify_proof_package_bytes(package_path.read_bytes())
    except OSError as exc:
        print(f"PACKAGE_READ_ERROR: {exc}")
        return 2
    print("VEILGRAPH_COMPLETE_PROOF_PACKAGE")
    for check in result.get("checks", []):
        state = "PASS" if check.get("valid") else "FAIL"
        print(f"[{state}] {check.get('name')}: {check.get('detail')}")
    print(f"certificate_id={result.get('certificate_id', 'unknown')}")
    print(f"bundle_sha256={result.get('bundle_sha256', 'unknown')}")
    if result.get("valid"):
        print("PACKAGE_VALID")
        return 0
    print("PACKAGE_INVALID")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
