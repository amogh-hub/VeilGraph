#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
import sys
sys.path.insert(0, str(BACKEND))

from app.security.release_package import build_release_package, verify_release_package_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "competition/releases/veilgraph-sih-phase2-sanitized.zip")
    args = parser.parse_args()
    package, manifest = build_release_package(ROOT, phase="phase2")
    verification = verify_release_package_bytes(package)
    if not verification.get("valid"):
        raise SystemExit(f"Release package self-verification failed: {verification}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(package)
    report = {
        "schema": "veilgraph.phase2-release.v1",
        "output": str(args.output.relative_to(ROOT)),
        "sha256": hashlib.sha256(package).hexdigest(),
        "size_bytes": len(package),
        "entry_count": manifest["entry_count"],
        "verification": verification,
    }
    report_path = ROOT / "competition/phase2/PHASE2_RELEASE_PACKAGE_RESULTS.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Wrote {report_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
