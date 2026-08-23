#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "competition" / "baselines" / "PIIMB_AI4PRIVACY_EN_PRE_V2_18538.json"
DEFAULT_CURRENT = ROOT / "competition" / "veilbench-results.json"
OUT_JSON = ROOT / "competition" / "PIIMB_BEFORE_AFTER.json"
OUT_MD = ROOT / "competition" / "PIIMB_BEFORE_AFTER.md"


def _pct(value: float) -> str:
    return f"{value * 100:.3f}%"


def _delta(value: float) -> str:
    return f"{value * 100:+.3f} pp"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare preserved pre-v2 PIIMB baseline with the current VeilBench PIIMB result")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--current", type=Path, default=DEFAULT_CURRENT)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    current_report = json.loads(args.current.read_text(encoding="utf-8"))
    current = current_report.get("standardized_masking_benchmark")
    if not isinstance(current, dict):
        raise SystemExit("Current VeilBench report does not contain standardized_masking_benchmark")

    base_dataset = baseline.get("dataset") or {}
    current_dataset = current.get("dataset") or {}
    base_overall = baseline["overall"]
    current_overall = current["overall"]

    comparable = (
        base_dataset.get("task_filter") == current_dataset.get("task_filter")
        and baseline.get("rows_scored") == current.get("rows_scored")
    )
    metrics = ("precision", "recall", "f1", "f2", "fpr")
    deltas = {name: round(float(current_overall[name]) - float(base_overall[name]), 6) for name in metrics}

    result = {
        "schema": "veilgraph.piimb-before-after.v1",
        "comparable_task_and_row_count": comparable,
        "baseline": {
            "generated_at": baseline.get("generated_at"),
            "detector": baseline.get("detector_baseline"),
            "dataset": base_dataset,
            "overall": base_overall,
            "performance": baseline.get("performance"),
        },
        "current": {
            "generated_at": current_report.get("generated_at"),
            "dataset": current_dataset,
            "overall": current_overall,
            "performance": current.get("performance"),
        },
        "delta": deltas,
        "claim_boundary": "Same-task before/after engineering evidence; corpus-specific metrics, not universal accuracy or anonymity guarantees.",
    }
    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# PIIMB before / after",
        "",
        f"Comparable task + row count: **{'YES' if comparable else 'NO'}**",
        "",
        "| Metric | Pre-v2 | Current | Delta |",
        "|---|---:|---:|---:|",
    ]
    for name in metrics:
        lines.append(f"| {name.upper()} | {_pct(float(base_overall[name]))} | {_pct(float(current_overall[name]))} | {_delta(deltas[name])} |")
    lines += [
        "",
        f"- Task: `{current_dataset.get('task_filter')}`",
        f"- Rows: **{current.get('rows_scored')}**",
        f"- Current dataset SHA-256: `{current_dataset.get('input_sha256', 'not recorded')}`",
        f"- Baseline dataset SHA-256: `{base_dataset.get('input_sha256', 'not recorded by pre-v2 runner')}`",
        "",
        "## Interpretation guardrail",
        "",
        "An improvement is accepted only together with the full VeilGraph regression/security gate. Recall/F2 improvement obtained by indiscriminate masking is not sufficient; precision and FPR remain visible in the same report.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")

    print("PIIMB before/after")
    print(f"Comparable task + rows: {'YES' if comparable else 'NO'}")
    for name in metrics:
        print(f"{name:9s} {float(base_overall[name]):.6f} -> {float(current_overall[name]):.6f} ({deltas[name]:+.6f})")
    print(f"Wrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
    return 0 if comparable else 2


if __name__ == "__main__":
    raise SystemExit(main())
