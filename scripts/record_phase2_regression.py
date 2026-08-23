#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "competition/phase2/PHASE2_FULL_REGRESSION.log"
OUT = ROOT / "competition/phase2/PHASE2_FULL_REGRESSION.json"


def parse_regression_log(text: str) -> dict:
    pass_matches = list(re.finditer(r"(?m)^([0-9]+) passed(?:, ([0-9]+) warnings)?(?: in [^\n]+)?$", text))
    if not pass_matches:
        pass_matches = list(re.finditer(r"([0-9]+) passed(?:, ([0-9]+) warnings)?", text))
    if not pass_matches:
        raise ValueError("Could not parse pytest pass count from PHASE2_FULL_REGRESSION.log")

    match = pass_matches[-1]
    passed = int(match.group(1))
    warnings = int(match.group(2) or 0)
    failed_matches = list(re.finditer(r"\b([0-9]+) failed\b", text))
    failed = int(failed_matches[-1].group(1)) if failed_matches else 0

    run_checks_exit_zero = "VEILGRAPH_RUN_CHECKS_EXIT=0" in text
    openapi_written = "Wrote backend/openapi.json" in text
    typescript_typecheck = "tsc -b --pretty false" in text
    vite_production_build = bool(re.search(r"vite v[^\n]* building for production", text)) and "✓ built in" in text

    all_passed = (
        passed > 0
        and failed == 0
        and run_checks_exit_zero
        and openapi_written
        and typescript_typecheck
        and vite_production_build
    )
    return {
        "schema": "veilgraph.phase2-full-regression.v2",
        "pytest_passed": passed,
        "pytest_failed": failed,
        "warnings": warnings,
        "run_checks_exit_zero": run_checks_exit_zero,
        "openapi_written": openapi_written,
        "typescript_typecheck": typescript_typecheck,
        "vite_production_build": vite_production_build,
        "all_passed": all_passed,
    }


def main() -> int:
    text = LOG.read_text(encoding="utf-8", errors="replace")
    try:
        payload = parse_regression_log(text)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"Wrote {OUT}")
    if not payload["all_passed"]:
        print("Phase-2 regression evidence is incomplete or not green; refusing closure.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
