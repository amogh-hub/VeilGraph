#!/usr/bin/env python3
from __future__ import annotations

"""Evaluate frozen Broad PII v4 on a fresh external SPIA PANORAMA test holdout.

Scientific rules:
1. Verify the Broad PII v4 freeze before opening/downloading the holdout.
2. Never train or tune from this holdout.
3. Score only the taxonomy-overlap, surface-visible subset because SPIA also
   annotates information that can be inferred but is not literally present.
4. Re-verify the freeze after evaluation.
5. Persist aggregate metrics/provenance only; raw holdout text is not copied
   into the VeilGraph repository.
"""

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.detection.pipeline import detect_all  # noqa: E402
from app.extraction.document_processor import processed_document_from_decoded_text  # noqa: E402

SOURCE_REPO = "spia-bench/SPIA-benchmark"
SOURCE_FILE = "02_spia_panorama_151.jsonl"
SOURCE_URL = f"https://huggingface.co/datasets/{SOURCE_REPO}/resolve/main/{SOURCE_FILE}"
SOURCE_LICENSE = "MIT (PANORAMA source data noted by SPIA as CC BY 4.0)"
SOURCE_ROLE = "PANORAMA synthetic test subset"
EXPECTED_DOCUMENTS = 151

# Shared taxonomy only.  SPIA labels such as SEX/NATIONALITY/EDUCATION and
# RELATIONSHIP are meaningful privacy signals but are not one-to-one with the
# current VeilGraph detector taxonomy, so they are reported as excluded rather
# than silently scored as misses.
TAG_TO_VEILGRAPH: dict[str, tuple[str, ...]] = {
    "NAME": ("PERSON_NAME",),
    "AGE": ("AGE",),
    "LOCATION": ("LOCALITY", "STREET_ADDRESS", "POSTCODE"),
    "AFFILIATION": ("EMPLOYER",),
    "OCCUPATION": ("JOB_TITLE",),
    "POSITION": ("JOB_TITLE", "PERSON_TITLE"),
    "EMAIL_ADDRESS": ("EMAIL",),
    "PHONE_NUMBER": ("PHONE",),
    "IDENTIFICATION_NUMBER": ("NATIONAL_ID", "SOCIAL_IDENTIFIER", "TAX_IDENTIFIER"),
    "DRIVER_LICENSE_NUMBER": ("DRIVER_LICENSE_NUMBER",),
    "PASSPORT_NUMBER": ("PASSPORT_NUMBER",),
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalize(value: object) -> str:
    text = str(value or "").casefold()
    text = text.replace("’", "'").replace("–", "-").replace("—", "-")
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n.,;:()[]{}\"'")
    return text


def verify_freeze() -> str:
    script = ROOT / "scripts" / "verify_broad_pii_v4_freeze.py"
    completed = subprocess.run([sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError("Broad PII v4 freeze verification failed before/after holdout evaluation:\n" + completed.stdout + completed.stderr)
    return _sha256_path(ROOT / "competition" / "phase1" / "BROAD_PII_V4_FREEZE_MANIFEST.json")


def _download_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "VeilGraph-SIH-2026-Holdout-Evaluator/1.0"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def parse_jsonl_bytes(data: bytes) -> list[dict]:
    rows: list[dict] = []
    for index, raw in enumerate(data.decode("utf-8-sig").splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        item = json.loads(raw)
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise ValueError(f"Invalid SPIA record at line {index}")
        rows.append(item)
    return rows


def _record_gold(record: dict) -> tuple[list[tuple[str, str]], Counter, Counter]:
    text = record.get("text", "")
    text_cf = text.casefold()
    gold: list[tuple[str, str]] = []
    excluded = Counter()
    inference_only = Counter()
    seen: set[tuple[str, str]] = set()
    for subject in record.get("subjects") or []:
        for pii in (subject or {}).get("PIIs") or []:
            tag = str((pii or {}).get("tag") or "").upper().strip()
            keyword = str((pii or {}).get("keyword") or "").strip()
            if not tag or not keyword:
                continue
            if tag not in TAG_TO_VEILGRAPH:
                excluded[tag] += 1
                continue
            # SPIA is inference-aware.  A privacy detector cannot be expected to
            # locate a literal span which does not occur in the document.  Such
            # annotations are measured separately, not counted as false negatives.
            if keyword.casefold() not in text_cf:
                inference_only[tag] += 1
                continue
            key = (tag, _normalize(keyword))
            if key[1] and key not in seen:
                seen.add(key)
                gold.append(key)
    return gold, excluded, inference_only


def evaluate_records(records: Iterable[dict]) -> dict:
    totals = Counter()
    excluded_total = Counter()
    inference_total = Counter()
    per_tag: dict[str, Counter] = defaultdict(Counter)
    negative_slots = 0
    false_positive_slots = 0
    documents = 0

    accepted_veils = {item for values in TAG_TO_VEILGRAPH.values() for item in values}

    for record in records:
        documents += 1
        text = record.get("text", "")
        gold, excluded, inference_only = _record_gold(record)
        excluded_total.update(excluded)
        inference_total.update(inference_only)

        doc = processed_document_from_decoded_text(text)
        mentions = detect_all(doc)
        predictions = [(m.entity_type.value, _normalize(m.plaintext)) for m in mentions if m.entity_type.value in accepted_veils and _normalize(m.plaintext)]

        consumed: set[int] = set()
        gold_by_tag: dict[str, list[str]] = defaultdict(list)
        for tag, value in gold:
            gold_by_tag[tag].append(value)
            match_index = None
            allowed = set(TAG_TO_VEILGRAPH[tag])
            for i, (ptype, pvalue) in enumerate(predictions):
                if i in consumed or ptype not in allowed:
                    continue
                if pvalue == value:
                    match_index = i
                    break
            if match_index is None:
                totals["fn"] += 1
                per_tag[tag]["fn"] += 1
            else:
                consumed.add(match_index)
                totals["tp"] += 1
                per_tag[tag]["tp"] += 1

        # Overlap-taxonomy precision: every unused prediction in a mapped class
        # is a false discovery for this benchmark record.
        for i, (ptype, _pvalue) in enumerate(predictions):
            if i in consumed:
                continue
            totals["fp"] += 1
            # Attribute to all external tags which accept this class only if unique.
            owners = [tag for tag, vals in TAG_TO_VEILGRAPH.items() if ptype in vals]
            if len(owners) == 1:
                per_tag[owners[0]]["fp"] += 1

        # Entity-type/document false-positive rate.  Each mapped external tag is
        # a negative slot when that record contains no surface-visible gold of
        # that tag.  A prediction from the corresponding VeilGraph class turns
        # that slot into a false positive.
        for tag, allowed in TAG_TO_VEILGRAPH.items():
            if gold_by_tag.get(tag):
                continue
            negative_slots += 1
            if any(ptype in allowed for ptype, _ in predictions):
                false_positive_slots += 1

    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    beta2 = 4.0
    f2 = (1 + beta2) * precision * recall / (beta2 * precision + recall) if precision + recall else 0.0
    fpr = false_positive_slots / negative_slots if negative_slots else 0.0
    fdr = fp / (tp + fp) if tp + fp else 0.0

    per_entity = {}
    for tag in sorted(TAG_TO_VEILGRAPH):
        c = per_tag[tag]
        p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
        r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        ef1 = (2*p*r/(p+r)) if p is not None and r is not None and p+r else None
        per_entity[tag] = {"tp":c["tp"],"fp":c["fp"],"fn":c["fn"],"precision":p,"recall":r,"f1":ef1}

    return {
        "documents": documents,
        "surface_visible_gold": tp + fn,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "f2": f2,
        "false_discovery_rate": fdr,
        "entity_type_document_fpr": fpr,
        "negative_type_document_slots": negative_slots,
        "false_positive_type_document_slots": false_positive_slots,
        "inference_only_supported_annotations_excluded": dict(sorted(inference_total.items())),
        "unsupported_external_annotations_excluded": dict(sorted(excluded_total.items())),
        "per_entity": per_entity,
    }


def _fmt(x: object) -> str:
    if x is None: return "n/a"
    return f"{float(x):.4f}"


def write_report(result: dict, source_sha: str, freeze_sha: str) -> None:
    out_json = ROOT / "competition" / "phase1" / "EXTERNAL_HOLDOUT_SPIA_RESULTS.json"
    out_md = ROOT / "competition" / "phase1" / "EXTERNAL_HOLDOUT_SPIA_REPORT.md"
    payload = {
        "schema": "veilgraph.external-holdout.spia.v1",
        "holdout_status": "UNTOUCHED_UNTIL_BROAD_PII_V4_FREEZE",
        "detector_freeze_manifest_sha256": freeze_sha,
        "source": {
            "repository": SOURCE_REPO,
            "file": SOURCE_FILE,
            "role": SOURCE_ROLE,
            "license": SOURCE_LICENSE,
            "source_sha256": source_sha,
            "expected_documents": EXPECTED_DOCUMENTS,
        },
        "evaluation_scope": {
            "kind": "taxonomy-overlap surface-visible subset",
            "mapped_external_tags": TAG_TO_VEILGRAPH,
            "important_limitation": "SPIA includes inference-only PII. An annotation is scored only when its keyword is literally present in the document and maps to the current VeilGraph taxonomy.",
            "fpr_definition": "Entity-type/document FPR over mapped tags: a tag/document slot is negative when no surface-visible gold of that tag exists; any corresponding prediction makes the slot false-positive.",
        },
        "metrics": result,
        "scientific_integrity": {
            "training_or_tuning_on_holdout": False,
            "post_holdout_detector_changes_allowed_without_new_holdout": False,
            "raw_holdout_copied_into_repository": False,
        },
    }
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# VeilGraph Broad PII v4 — Fresh External Holdout",
        "",
        f"- Source: `{SOURCE_REPO}` / `{SOURCE_FILE}`",
        f"- Source SHA-256: `{source_sha}`",
        f"- Broad PII v4 freeze manifest SHA-256: `{freeze_sha}`",
        f"- Documents: **{result['documents']}**",
        f"- Surface-visible, taxonomy-overlap gold entities: **{result['surface_visible_gold']}**",
        "",
        "## Aggregate metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Precision | {_fmt(result['precision'])} |",
        f"| Recall | {_fmt(result['recall'])} |",
        f"| F1 | {_fmt(result['f1'])} |",
        f"| F2 | {_fmt(result['f2'])} |",
        f"| False discovery rate | {_fmt(result['false_discovery_rate'])} |",
        f"| Entity-type/document FPR | {_fmt(result['entity_type_document_fpr'])} |",
        "",
        "## Per-entity metrics",
        "",
        "| External tag | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for tag, m in result["per_entity"].items():
        lines.append(f"| {tag} | {m['tp']} | {m['fp']} | {m['fn']} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} |")
    lines += [
        "",
        "## Interpretation boundary",
        "",
        "SPIA is subject-level and inference-aware. This report therefore does **not** pretend that inferred-but-absent information is a missed text span. Only supported labels whose annotated keyword is literally present are scored. Unsupported taxonomy and inference-only annotations are reported separately in the JSON result.",
        "",
        "This holdout was opened only after the Broad PII v4 production/model hash freeze. If a frozen detector/model file changes after this evaluation, this result is no longer valid evidence for that new detector and a new untouched holdout is required.",
    ]
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_json}")
    print(f"Wrote {out_md}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", type=Path, help="Use an already downloaded SPIA JSONL file instead of network download")
    parser.add_argument("--replace", action="store_true", help="Allow replacing an existing aggregate holdout result")
    args = parser.parse_args()

    output = ROOT / "competition" / "phase1" / "EXTERNAL_HOLDOUT_SPIA_RESULTS.json"
    if output.exists() and not args.replace:
        print(f"Refusing to overwrite existing holdout evidence: {output}")
        print("Use --replace only to reproduce the same frozen detector against the same source; never tune between runs.")
        return 2

    freeze_sha_before = verify_freeze()
    print("Broad PII v4 freeze verified BEFORE opening external holdout.")

    if args.source_file:
        data = args.source_file.read_bytes()
    else:
        print(f"Downloading fresh external holdout from {SOURCE_REPO} / {SOURCE_FILE} ...")
        data = _download_bytes(SOURCE_URL)
    source_sha = _sha256_bytes(data)
    records = parse_jsonl_bytes(data)
    if len(records) != EXPECTED_DOCUMENTS:
        raise RuntimeError(f"Unexpected SPIA test document count: {len(records)} (expected {EXPECTED_DOCUMENTS})")

    result = evaluate_records(records)
    freeze_sha_after = verify_freeze()
    if freeze_sha_before != freeze_sha_after:
        raise RuntimeError("Detector freeze manifest changed during holdout evaluation")

    write_report(result, source_sha, freeze_sha_after)
    print(
        "External holdout: "
        f"P={result['precision']:.4f} R={result['recall']:.4f} "
        f"F1={result['f1']:.4f} F2={result['f2']:.4f} "
        f"type/doc FPR={result['entity_type_document_fpr']:.4f}"
    )
    print("Freeze verified AFTER evaluation. Do not tune Broad PII v4 from this holdout result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
