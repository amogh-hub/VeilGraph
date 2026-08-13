#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "competition" / "final" / "FINAL_FULL_REGRESSION.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", type=Path)
    ap.add_argument("--exit-code", type=int, required=True)
    args = ap.parse_args()
    text = args.log.read_text(encoding="utf-8", errors="replace") if args.log.is_file() else ""

    matches = list(re.finditer(r"(?m)(\d+) passed(?:, (\d+) failed)?(?:, (\d+) warnings?)?", text))
    m = matches[-1] if matches else None
    passed = int(m.group(1)) if m else 0
    failed = int(m.group(2) or 0) if m else -1
    warnings = int(m.group(3) or 0) if m else 0
    openapi = "openapi.json" in text and ("Wrote " in text or "generated" in text.lower())
    ts = "typecheck" in text and ("tsc -b --pretty false" in text or "> tsc -b" in text)
    vite = "vite v" in text and "built in" in text
    all_passed = args.exit_code == 0 and m is not None and passed > 0 and failed == 0 and openapi and ts and vite

    payload = {
        "schema": "veilgraph.final-full-regression.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_checks_exit_code": args.exit_code,
        "pytest_passed": passed,
        "pytest_failed": failed,
        "warnings": warnings,
        "openapi_written": openapi,
        "typescript_typecheck": ts,
        "vite_production_build": vite,
        "all_passed": all_passed,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"Wrote {OUT}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
