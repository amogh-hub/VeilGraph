#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.security.release_package import verify_release_package_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    result = verify_release_package_bytes(args.package.read_bytes())
    print(result)
    return 0 if result.get("valid") else 1

if __name__ == "__main__":
    raise SystemExit(main())
