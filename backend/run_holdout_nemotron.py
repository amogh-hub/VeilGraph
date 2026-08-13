from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.benchmark.piimb import benchmark_piimb  # noqa: E402

MANIFEST_PATH = ROOT / "competition" / "HOLDOUT_FREEZE_MANIFEST.json"
OUT_JSON = ROOT / "competition" / "HOLDOUT_NEMOTRON_RESULTS.json"
OUT_MD = ROOT / "competition" / "HOLDOUT_NEMOTRON_REPORT.md"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def verify_frozen_source(manifest: dict) -> list[str]:
    mismatches: list[str] = []
    for item in manifest["locked_files"]:
        path = ROOT / item["path"]
        if not path.is_file():
            mismatches.append(f"MISSING {item['path']}")
            continue
        actual = sha256_file(path)
        if actual != item["sha256"]:
            mismatches.append(f"HASH {item['path']} expected={item['sha256']} actual={actual}")
    return mismatches


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def write_report(report: dict) -> None:
    OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    score = report["benchmark"]["overall"]
    perf = report["benchmark"]["performance"]
    dataset = report["benchmark"]["dataset"]
    lines = [
        "# VeilGraph Frozen-Detector Holdout — Nemotron-PII",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Evaluation integrity",
        "",
        f"- Detector frozen before evaluation: **{report['integrity']['detector_frozen_before_evaluation']}**",
        f"- Frozen detector: **{report['integrity']['frozen_detector']}**",
        f"- Locked production files verified: **{report['integrity']['locked_files_verified']}/{report['integrity']['locked_files_total']}**",
        f"- Frozen source snapshot SHA-256: `{report['integrity']['source_snapshot_sha256']}`",
        f"- Benchmark input SHA-256: `{dataset['input_sha256']}`",
        "- Holdout feedback policy: **results are evidence only; Broad PII v3 must not be tuned from this task**.",
        "",
        "## Holdout result",
        "",
        f"- Task: **{dataset['task_filter']}**",
        f"- Rows scored: **{report['benchmark']['rows_scored']}**",
        f"- Characters scored: **{report['benchmark']['characters_scored']}**",
        f"- Precision: **{pct(score['precision'])}**",
        f"- Recall: **{pct(score['recall'])}**",
        f"- F1: **{pct(score['f1'])}**",
        f"- F2: **{pct(score['f2'])}**",
        f"- Character FPR: **{pct(score['fpr'])}**",
        f"- Median latency: **{perf['median_sentence_ms']} ms/sentence**",
        f"- P95 latency: **{perf['p95_sentence_ms']} ms/sentence**",
        f"- Throughput: **{perf['sentences_per_second']} sentences/s**",
        "",
        "## Claim boundary",
        "",
        "This is post-freeze generalization evidence on the named external task. It is not a universal accuracy or anonymity guarantee. The detector was frozen before this task was evaluated, and the result must not be used to tune Broad PII v3.",
        "",
        "## Post-freeze label diagnostics",
        "",
        "The JSON result contains `diagnostic_by_gold_label`. These diagnostics are recorded only after the frozen evaluation and do not alter the official label-agnostic masking scores.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the locked Nemotron-PII holdout without changing production detection code")
    parser.add_argument("dataset", type=Path, help="PIIMB test_sentences.jsonl used by the frozen external benchmark")
    parser.add_argument("--limit", type=int, default=100000, help="Upper bound; default is intentionally above the complete Nemotron task")
    args = parser.parse_args()

    manifest = load_manifest()
    mismatches = verify_frozen_source(manifest)
    if mismatches:
        print("HOLDOUT REFUSED: frozen production source does not match manifest", file=sys.stderr)
        for item in mismatches:
            print(f" - {item}", file=sys.stderr)
        return 3

    if not args.dataset.is_file():
        print(f"HOLDOUT REFUSED: dataset not found: {args.dataset}", file=sys.stderr)
        return 2
    dataset_sha = sha256_file(args.dataset)
    if dataset_sha != manifest["piimb_input_sha256"]:
        print("HOLDOUT REFUSED: benchmark input SHA-256 does not match the locked PIIMB snapshot", file=sys.stderr)
        print(f" expected: {manifest['piimb_input_sha256']}", file=sys.stderr)
        print(f" actual:   {dataset_sha}", file=sys.stderr)
        return 4

    result = benchmark_piimb(args.dataset, task=manifest["holdout_task"], limit=args.limit)
    after = verify_frozen_source(manifest)
    if after:
        print("HOLDOUT REFUSED: production source changed during evaluation", file=sys.stderr)
        return 5

    report = {
        "schema": "veilgraph.holdout-result.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "claim_boundary": "Post-freeze external generalization evidence only; not a universal accuracy or anonymity guarantee.",
        "integrity": {
            "detector_frozen_before_evaluation": True,
            "frozen_detector": manifest["frozen_detector"],
            "source_snapshot": manifest["source_snapshot"],
            "source_snapshot_sha256": manifest["source_snapshot_sha256"],
            "locked_files_total": len(manifest["locked_files"]),
            "locked_files_verified": len(manifest["locked_files"]),
            "production_source_changed_during_run": False,
            "holdout_feedback_may_tune_detector": False,
        },
        "benchmark": result,
    }
    write_report(report)
    score = result["overall"]
    print("VeilGraph frozen-detector holdout")
    print(f"Task:      {result['dataset']['task_filter']}")
    print(f"Rows:      {result['rows_scored']}")
    print(f"Precision: {score['precision']:.6f}")
    print(f"Recall:    {score['recall']:.6f}")
    print(f"F1:        {score['f1']:.6f}")
    print(f"F2:        {score['f2']:.6f}")
    print(f"FPR:       {score['fpr']:.6f}")
    print(f"Input SHA: {result['dataset']['input_sha256']}")
    print(f"Wrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
