#!/usr/bin/env python3
from __future__ import annotations

"""Evaluate frozen Broad PII v4 on the official TAB ECHR test split.

Scientific rules:
1. Verify the Broad PII v4 freeze before acquiring or opening the holdout.
2. Acquire only the official `echr_test.json` from the Norwegian Computing
   Center (Norsk Regnesentral) Text Anonymization Benchmark repository.
3. Never train, tune, patch, or select detector rules from this holdout.
4. Score DIRECT/QUASI masking-required mentions. TAB's NO_MASK annotations are
   reported separately as an over-redaction diagnostic.
5. Re-verify the exact Broad PII v4 freeze after evaluation.
6. Persist aggregate metrics and source provenance only. Raw holdout text is
   kept in a temporary directory and removed after the run.

The primary acquisition method is a shallow clone of the public GitHub
repository. This avoids the Hugging Face transport/authentication failures seen
with the earlier SPIA attempt and gives us an immutable Git commit identifier.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

SOURCE_REPOSITORY = "NorskRegnesentral/text-anonymization-benchmark"
SOURCE_REPO_URL = f"https://github.com/{SOURCE_REPOSITORY}.git"
SOURCE_BRANCH = "master"
SOURCE_FILE = "echr_test.json"
SOURCE_LICENSE = "MIT"
SOURCE_ROLE = "TAB v1.0 ECHR test split"
MIN_SOURCE_BYTES = 1_000_000
MIN_DOCUMENTS = 25

MASK_REQUIRED_TYPES = {"DIRECT", "DIRECT_ID", "QUASI", "QUASI_ID"}
DIRECT_TYPES = {"DIRECT", "DIRECT_ID"}
QUASI_TYPES = {"QUASI", "QUASI_ID"}
NO_MASK_TYPES = {"NO_MASK"}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalize(value: object) -> str:
    text = str(value or "").casefold()
    text = text.replace("’", "'").replace("–", "-").replace("—", "-")
    text = re.sub(r"\s+", " ", text)
    return text.strip(" \t\r\n.,;:()[]{}\"'")


def verify_freeze() -> str:
    script = ROOT / "scripts" / "verify_broad_pii_v4_freeze.py"
    completed = subprocess.run(
        [sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Broad PII v4 freeze verification failed:\n"
            + completed.stdout
            + completed.stderr
        )
    return _sha256_path(
        ROOT / "competition" / "phase1" / "BROAD_PII_V4_FREEZE_MANIFEST.json"
    )


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "GitHub acquisition failed. Git command:\n"
            f"git {' '.join(args)}\n\n"
            + completed.stdout
            + completed.stderr
        )
    return completed.stdout.strip()


def acquire_official_source() -> tuple[bytes, str]:
    """Shallow-clone the official repository and return test bytes + commit."""
    if shutil.which("git") is None:
        raise RuntimeError("git is required for automatic TAB holdout acquisition")

    with tempfile.TemporaryDirectory(prefix="veilgraph-tab-holdout-") as tmp:
        checkout = Path(tmp) / "tab"
        _run_git(
            [
                "clone",
                "--depth",
                "1",
                "--branch",
                SOURCE_BRANCH,
                "--single-branch",
                SOURCE_REPO_URL,
                str(checkout),
            ]
        )
        commit = _run_git(["rev-parse", "HEAD"], cwd=checkout)
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
            raise RuntimeError(f"Unexpected TAB Git commit identifier: {commit!r}")
        path = checkout / SOURCE_FILE
        if not path.is_file():
            raise RuntimeError(f"Official TAB checkout does not contain {SOURCE_FILE}")
        data = path.read_bytes()
        return data, commit.lower()


def parse_tab_bytes(data: bytes) -> list[dict]:
    if len(data) < MIN_SOURCE_BYTES:
        raise ValueError(
            f"TAB source is unexpectedly small ({len(data)} bytes); refusing evaluation"
        )
    payload = json.loads(data.decode("utf-8-sig"))
    if isinstance(payload, dict) and isinstance(payload.get("documents"), list):
        payload = payload["documents"]
    if not isinstance(payload, list):
        raise ValueError("TAB source must be a JSON list of document objects")
    if len(payload) < MIN_DOCUMENTS:
        raise ValueError(
            f"TAB source contains only {len(payload)} documents; refusing partial holdout"
        )
    records: list[dict] = []
    for index, record in enumerate(payload):
        if not isinstance(record, dict):
            raise ValueError(f"TAB record {index} is not an object")
        if not isinstance(record.get("text"), str):
            raise ValueError(f"TAB record {index} has no text string")
        dataset_type = str(record.get("dataset_type") or "").strip().lower()
        if dataset_type and dataset_type != "test":
            raise ValueError(
                f"TAB record {index} is labelled {dataset_type!r}, not test"
            )
        if not isinstance(record.get("annotations"), dict):
            raise ValueError(f"TAB record {index} has no annotations object")
        records.append(record)
    return records


def _annotation_sets(record: dict) -> list[tuple[str, list[dict]]]:
    """Return one entity-mention list per TAB annotator.

    Official TAB evaluation micro-averages across annotators. The same system
    prediction therefore gets evaluated independently against each annotator's
    gold annotations rather than deduplicating human judgments together.
    """
    output: list[tuple[str, list[dict]]] = []
    annotations = record.get("annotations") or {}
    for annotator, payload in annotations.items():
        if not isinstance(payload, dict):
            continue
        mentions = payload.get("entity_mentions")
        if not isinstance(mentions, list):
            continue
        valid = [m for m in mentions if isinstance(m, dict)]
        output.append((str(annotator), valid))
    if not output:
        raise ValueError(
            f"TAB document {record.get('doc_id', '<unknown>')} contains no entity_mentions"
        )
    return output


def _gold_entries(text: str, mentions: list[dict]) -> tuple[list[dict], list[dict]]:
    mask_required: list[dict] = []
    no_mask: list[dict] = []
    for mention in mentions:
        identifier = str(mention.get("identifier_type") or "").strip().upper()
        if identifier not in MASK_REQUIRED_TYPES | NO_MASK_TYPES:
            continue
        try:
            start = int(mention["start_offset"])
            end = int(mention["end_offset"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (0 <= start < end <= len(text)):
            continue
        surface = str(mention.get("span_text") or text[start:end])
        normalized = _normalize(surface)
        if not normalized:
            continue
        entry = {
            "value": normalized,
            "entity_type": str(mention.get("entity_type") or "UNKNOWN").upper(),
            "identifier_type": identifier,
            "start": start,
            "end": end,
        }
        if identifier in MASK_REQUIRED_TYPES:
            mask_required.append(entry)
        else:
            no_mask.append(entry)
    return mask_required, no_mask


def _score_values(gold: list[dict], predictions: list[str]) -> tuple[int, int, int, Counter]:
    """Strict mention-value matching with multiset consumption.

    This is deliberately labelled as VeilGraph's cross-benchmark span-value
    metric, not the official TAB leaderboard metric. It avoids pretending that
    VeilGraph's richer entity taxonomy is one-to-one with TAB's eight semantic
    categories while still measuring whether each required sensitive surface
    was found.
    """
    consumed: set[int] = set()
    per_category = Counter()
    tp = 0
    fn = 0
    for item in gold:
        match = None
        for index, value in enumerate(predictions):
            if index in consumed:
                continue
            if value == item["value"]:
                match = index
                break
        category = item["entity_type"]
        if match is None:
            fn += 1
            per_category[(category, "fn")] += 1
        else:
            consumed.add(match)
            tp += 1
            per_category[(category, "tp")] += 1
    fp = len(predictions) - len(consumed)
    return tp, fp, fn, per_category


def evaluate_records(records: Iterable[dict]) -> dict:
    # Delay VeilGraph imports until actual evaluation. Parser/protocol tests can
    # run without importing the entire backend stack.
    from app.detection.pipeline import detect_all
    from app.extraction.document_processor import processed_document_from_decoded_text

    totals = Counter()
    per_category_totals = Counter()
    no_mask_total = 0
    no_mask_hits = 0
    document_count = 0
    annotator_document_pairs = 0
    direct_gold = direct_tp = 0
    quasi_gold = quasi_tp = 0
    predicted_mentions = 0

    for record in records:
        document_count += 1
        text = record["text"]
        doc = processed_document_from_decoded_text(text)
        detected = detect_all(doc)
        predictions = [_normalize(m.plaintext) for m in detected if _normalize(m.plaintext)]
        predicted_mentions += len(predictions)

        for _annotator, mentions in _annotation_sets(record):
            annotator_document_pairs += 1
            gold, no_mask = _gold_entries(text, mentions)
            tp, fp, fn, by_cat = _score_values(gold, predictions)
            totals.update({"tp": tp, "fp": fp, "fn": fn})
            per_category_totals.update(by_cat)

            # Direct/quasi recall independently. We use a fresh prediction pool
            # for each category so one TAB annotation's class cannot consume a
            # prediction needed for the other class diagnostic.
            for allowed, prefix in ((DIRECT_TYPES, "direct"), (QUASI_TYPES, "quasi")):
                subset = [g for g in gold if g["identifier_type"] in allowed]
                stp, _sfp, sfn, _ = _score_values(subset, predictions)
                if prefix == "direct":
                    direct_tp += stp
                    direct_gold += stp + sfn
                else:
                    quasi_tp += stp
                    quasi_gold += stp + sfn

            pred_counter = Counter(predictions)
            for item in no_mask:
                no_mask_total += 1
                if pred_counter[item["value"]] > 0:
                    no_mask_hits += 1

    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    beta2 = 4.0
    f2 = (
        (1.0 + beta2) * precision * recall / (beta2 * precision + recall)
        if precision + recall
        else 0.0
    )

    categories = sorted({key[0] for key in per_category_totals})
    per_category = {}
    for category in categories:
        ctp = per_category_totals[(category, "tp")]
        cfn = per_category_totals[(category, "fn")]
        per_category[category] = {
            "tp": ctp,
            "fn": cfn,
            "recall": ctp / (ctp + cfn) if ctp + cfn else None,
        }

    return {
        "documents": document_count,
        "annotator_document_pairs": annotator_document_pairs,
        "predicted_mentions_document_level": predicted_mentions,
        "mask_required_gold_mentions": tp + fn,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "strict_span_value_precision": precision,
        "strict_span_value_recall": recall,
        "strict_span_value_f1": f1,
        "strict_span_value_f2": f2,
        "direct_identifier_recall": direct_tp / direct_gold if direct_gold else None,
        "direct_identifier_gold_mentions": direct_gold,
        "quasi_identifier_recall": quasi_tp / quasi_gold if quasi_gold else None,
        "quasi_identifier_gold_mentions": quasi_gold,
        "tab_no_mask_mentions": no_mask_total,
        "tab_no_mask_hit_rate": no_mask_hits / no_mask_total if no_mask_total else None,
        "tab_no_mask_hits": no_mask_hits,
        "per_tab_entity_category": per_category,
        "metric_note": (
            "Cross-benchmark exact normalized span-value matching. This is not the "
            "official TAB leaderboard metric; TAB's target-person masking policy and "
            "VeilGraph's broader release policy are not identical."
        ),
    }


def _fmt(value: object) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}"


def write_report(result: dict, *, source_sha: str, commit: str, freeze_sha: str) -> None:
    out_dir = ROOT / "competition" / "phase1"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "EXTERNAL_HOLDOUT_TAB_RESULTS.json"
    out_md = out_dir / "EXTERNAL_HOLDOUT_TAB_REPORT.md"

    payload = {
        "schema": "veilgraph.external-holdout.tab.v1",
        "holdout_status": "UNTOUCHED_UNTIL_BROAD_PII_V4_FREEZE",
        "detector_freeze_manifest_sha256": freeze_sha,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "git_commit": commit,
            "branch_used_for_acquisition": SOURCE_BRANCH,
            "file": SOURCE_FILE,
            "role": SOURCE_ROLE,
            "license": SOURCE_LICENSE,
            "source_sha256": source_sha,
        },
        "results": result,
        "raw_holdout_persisted_in_repository": False,
        "detector_tuned_on_holdout": False,
    }
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# VeilGraph External Holdout — TAB",
        "",
        "## Scientific status",
        "",
        "- Broad PII v4 was cryptographically frozen before TAB acquisition/evaluation.",
        "- The earlier SPIA attempt failed during remote acquisition, before any holdout records were evaluated.",
        "- TAB was selected only as a transport-access replacement; no TAB score was known at selection time.",
        "- Raw TAB text is not copied into the VeilGraph repository.",
        "- Detector/model/training files must not be changed in response to this score.",
        "",
        "## Source provenance",
        "",
        f"- Repository: `{SOURCE_REPOSITORY}`",
        f"- Commit: `{commit}`",
        f"- File: `{SOURCE_FILE}`",
        f"- Source SHA-256: `{source_sha}`",
        f"- Documents: {result['documents']}",
        "",
        "## VeilGraph cross-benchmark metrics",
        "",
        f"- Strict span-value precision: **{_fmt(result['strict_span_value_precision'])}**",
        f"- Strict span-value recall: **{_fmt(result['strict_span_value_recall'])}**",
        f"- Strict span-value F1: **{_fmt(result['strict_span_value_f1'])}**",
        f"- Strict span-value F2: **{_fmt(result['strict_span_value_f2'])}**",
        f"- Direct-identifier recall: **{_fmt(result['direct_identifier_recall'])}**",
        f"- Quasi-identifier recall: **{_fmt(result['quasi_identifier_recall'])}**",
        f"- TAB NO_MASK hit rate: **{_fmt(result['tab_no_mask_hit_rate'])}**",
        "",
        "> These are VeilGraph cross-benchmark exact normalized span-value metrics, not the official TAB leaderboard metrics. TAB's target-person masking policy and VeilGraph's broader release policy differ, so the NO_MASK hit rate is reported separately rather than mislabeled as a conventional FPR.",
        "",
        "## Per TAB semantic category recall",
        "",
        "| TAB category | TP | FN | Recall |",
        "|---|---:|---:|---:|",
    ]
    for category, values in result["per_tab_entity_category"].items():
        lines.append(
            f"| {category} | {values['tp']} | {values['fn']} | {_fmt(values['recall'])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation rule",
            "",
            "This is a one-shot external generalization measurement for frozen Broad PII v4. If the score exposes weaknesses, keep the result and address them only in a future detector version developed on separate data, followed by a new untouched holdout.",
            "",
        ]
    )
    out_md.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-file",
        type=Path,
        help=(
            "Optional local copy of the official TAB echr_test.json. Automatic "
            "GitHub shallow-clone acquisition is preferred."
        ),
    )
    parser.add_argument(
        "--source-commit",
        default="LOCAL_COPY_COMMIT_NOT_PROVIDED",
        help="Commit provenance for --source-file, if known.",
    )
    args = parser.parse_args(argv)

    freeze_sha = verify_freeze()
    print("Broad PII v4 freeze verified BEFORE external holdout acquisition.")

    if args.source_file:
        source = args.source_file.expanduser().resolve()
        if not source.is_file():
            raise SystemExit(f"TAB source file not found: {source}")
        print(f"Opening local official TAB test copy: {source.name}")
        data = source.read_bytes()
        commit = args.source_commit
    else:
        print(
            "Acquiring official TAB test split from "
            f"{SOURCE_REPOSITORY} using a temporary shallow Git clone ..."
        )
        data, commit = acquire_official_source()
        print(f"Pinned TAB repository commit: {commit}")

    source_sha = _sha256_bytes(data)
    records = parse_tab_bytes(data)
    print(
        f"TAB source validated: {len(records)} test documents | "
        f"SHA-256 {source_sha}"
    )

    result = evaluate_records(records)

    freeze_after = verify_freeze()
    if freeze_after != freeze_sha:
        raise RuntimeError("Broad PII v4 freeze manifest changed during evaluation")
    print("Broad PII v4 freeze verified AFTER external holdout evaluation.")

    write_report(result, source_sha=source_sha, commit=commit, freeze_sha=freeze_sha)
    print()
    print("TAB EXTERNAL HOLDOUT RESULT")
    print(f"  documents: {result['documents']}")
    print(
        "  P={p} R={r} F1={f1} F2={f2}".format(
            p=_fmt(result["strict_span_value_precision"]),
            r=_fmt(result["strict_span_value_recall"]),
            f1=_fmt(result["strict_span_value_f1"]),
            f2=_fmt(result["strict_span_value_f2"]),
        )
    )
    print(f"  direct recall: {_fmt(result['direct_identifier_recall'])}")
    print(f"  quasi recall:  {_fmt(result['quasi_identifier_recall'])}")
    print(f"  TAB NO_MASK hit rate: {_fmt(result['tab_no_mask_hit_rate'])}")
    print()
    print("Wrote competition/phase1/EXTERNAL_HOLDOUT_TAB_RESULTS.json")
    print("Wrote competition/phase1/EXTERNAL_HOLDOUT_TAB_REPORT.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
