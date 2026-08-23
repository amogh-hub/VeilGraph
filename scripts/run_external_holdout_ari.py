#!/usr/bin/env python3
from __future__ import annotations

"""Evaluate frozen Broad PII v5 on a new external held-out challenge split.

Holdout identity
----------------
Dataset: Ari-S-123/pii-detection-english-consolidated
Revision: 61e7c4fcd6c569d4cc89db9cba79deab833df085
Split: test
Filter: data_source == "synthetic"
Expected records: 1,201

The dataset card states that the synthetic examples target six NER failure-mode
families and that 1,201 synthetic examples are reserved in the test split.
VeilGraph does not train on or persist those test records. The evaluator uses
Hugging Face's public Dataset Viewer /filter endpoint so no Parquet dependency
is required in the competition environment.

Scientific rules
----------------
1. Broad PII v5 must verify byte-for-byte BEFORE any holdout row is requested.
2. The frozen test Parquet artifact must remain byte-identical to the predeclared SHA-256; repository metadata may advance.
3. Only the 1,201 synthetic TEST records are evaluated. The ai4privacy portion
   is excluded because that source family was used earlier in VeilGraph work.
4. Unknown/non-shared PII labels are reported but excluded from the primary
   cross-taxonomy score rather than being silently remapped.
5. No detector/model/training file may be changed after seeing this result if
   this run is to remain valid external evidence.
6. Broad PII v5 is re-verified AFTER evaluation.
7. Raw holdout rows are never written into the VeilGraph repository; only
   aggregate metrics and provenance hashes are persisted.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

DATASET = "Ari-S-123/pii-detection-english-consolidated"
EXPECTED_REVISION = "61e7c4fcd6c569d4cc89db9cba79deab833df085"
EXPECTED_TEST_PARQUET_LFS_SHA256 = "768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471"
TEST_PARQUET_PATH = "data/test-00000-of-00001.parquet"
EXPECTED_TEST_ROWS = 31_361
EXPECTED_SYNTHETIC_TEST_ROWS = 1_201
CONFIG = "default"
SPLIT = "test"
FILTER_WHERE = '"data_source"=\'synthetic\''
API_BASE = "https://datasets-server.huggingface.co/filter"
REPO_GIT_URL = f"https://huggingface.co/datasets/{DATASET}"
LICENSE = "MIT"
PAGE_SIZE = 100

# These thresholds were declared before opening the final v5 holdout. They are
# intentionally unchanged from the v5 freeze plan even though the originally
# considered CEE source became unavailable before any record was opened.
THRESHOLDS = {
    "exact_f1_min": 0.50,
    "relaxed_f1_min": 0.65,
    "critical_recall_min": 0.75,
    "contextual_relaxed_recall_min": 0.55,
    "no_entity_fp_doc_rate_max": 0.20,
}

# Cross-taxonomy compatibility. A gold label can map to more than one
# VeilGraph class where the external dataset collapses national/social IDs or
# where date granularity differs. Unknown labels are explicitly excluded and
# counted in the report.
GOLD_TO_VEILGRAPH: dict[str, set[str]] = {
    "FIRSTNAME": {"PERSON_NAME"},
    "LASTNAME": {"PERSON_NAME"},
    "EMAIL": {"EMAIL"},
    "PHONENUMBER": {"PHONE"},
    "PHONE": {"PHONE"},
    "DRIVERLICENSENUM": {"DRIVER_LICENSE_NUMBER"},
    "DRIVER_LICENSE": {"DRIVER_LICENSE_NUMBER"},
    "PASSPORTNUM": {"PASSPORT_NUMBER"},
    "PASSPORT_NUMBER": {"PASSPORT_NUMBER"},
    "TAXNUM": {"TAX_IDENTIFIER", "PAN_LIKE"},
    "TAX_ID_TFN": {"TAX_IDENTIFIER"},
    "SSN": {"SOCIAL_IDENTIFIER", "NATIONAL_ID", "AADHAAR_LIKE"},
    "IDCARDNUM": {"NATIONAL_ID", "SOCIAL_IDENTIFIER", "AADHAAR_LIKE", "PAN_LIKE"},
    "NATIONAL_ID": {"NATIONAL_ID", "SOCIAL_IDENTIFIER", "AADHAAR_LIKE", "PAN_LIKE"},
    "CREDITCARDNUMBER": {"PAYMENT_CARD_NUMBER"},
    "DATE": {"GENERIC_DATE", "DATE_OF_BIRTH"},
    "DOB": {"DATE_OF_BIRTH", "GENERIC_DATE"},
    "AGE": {"AGE"},
    "TITLE": {"PERSON_TITLE"},
    "STREET": {"STREET_ADDRESS"},
    "CITY": {"LOCALITY"},
    "ZIPCODE": {"POSTCODE"},
    "BUILDINGNUMBER": {"BUILDING_NUMBER"},
    "SEX": {"DEMOGRAPHIC_ATTRIBUTE"},
}

CRITICAL_GOLD_LABELS = {
    "FIRSTNAME", "LASTNAME", "EMAIL", "PHONENUMBER", "PHONE",
    "DRIVERLICENSENUM", "DRIVER_LICENSE", "PASSPORTNUM", "PASSPORT_NUMBER",
    "TAXNUM", "TAX_ID_TFN", "SSN", "IDCARDNUM", "NATIONAL_ID",
    "CREDITCARDNUMBER",
}
CONTEXTUAL_GOLD_LABELS = {
    "DATE", "DOB", "AGE", "TITLE", "STREET", "CITY", "ZIPCODE",
    "BUILDINGNUMBER", "SEX",
}
SHARED_VEILGRAPH_TYPES = set().union(*GOLD_TO_VEILGRAPH.values())


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
    script = ROOT / "scripts" / "verify_broad_pii_v5_freeze.py"
    completed = subprocess.run(
        [sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Broad PII v5 freeze verification failed:\n"
            + completed.stdout
            + completed.stderr
        )
    return _sha256_path(ROOT / "competition" / "phase1" / "BROAD_PII_V5_FREEZE_MANIFEST.json")


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "ls-remote", REPO_GIT_URL, "refs/heads/main"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Could not verify the external dataset revision using git ls-remote.\n"
            + completed.stdout + completed.stderr
        )
    first = completed.stdout.strip().split()
    if not first or not re.fullmatch(r"[0-9a-fA-F]{40}", first[0]):
        raise RuntimeError(f"Unexpected Hugging Face revision response: {completed.stdout!r}")
    return first[0].lower()


def _remote_artifact_url(revision: str) -> str:
    quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in TEST_PARQUET_PATH.split("/"))
    return f"https://huggingface.co/datasets/{DATASET}/resolve/{revision}/{quoted_path}?download=true"


def _hash_remote_test_artifact(revision: str, *, attempts: int = 4) -> str:
    """Hash the exact test Parquet bytes at a Git revision without persisting them."""
    headers = {
        "Accept": "application/octet-stream",
        "User-Agent": "VeilGraph-SIH-2026/Phase1-Holdout-Provenance",
    }
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last: Exception | None = None
    url = _remote_artifact_url(revision)
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            digest = hashlib.sha256()
            with urllib.request.urlopen(req, timeout=90) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status} while hashing pinned test artifact")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(1.5 * (attempt + 1))
                continue
            break
    raise RuntimeError(
        "Could not verify the immutable external test artifact bytes. "
        "Do not modify Broad PII v5; check internet access and rerun the same command. "
        f"Last error: {last}"
    )


def verify_pinned_data_artifact() -> dict:
    """Allow repository metadata drift only when the frozen test artifact is byte-identical."""
    observed_head = _git_head()
    artifact_sha = _hash_remote_test_artifact(observed_head)
    if artifact_sha != EXPECTED_TEST_PARQUET_LFS_SHA256:
        raise RuntimeError(
            "External dataset test artifact changed: "
            f"expected SHA-256 {EXPECTED_TEST_PARQUET_LFS_SHA256}, got {artifact_sha} "
            f"at repository HEAD {observed_head}. Refusing a different holdout."
        )
    return {
        "pinned_data_revision": EXPECTED_REVISION,
        "observed_repository_head": observed_head,
        "test_parquet_sha256": artifact_sha,
        "data_artifact_identity_verified": True,
    }


def _request_json(url: str, *, attempts: int = 4) -> dict:
    headers = {
        "Accept": "application/json",
        "User-Agent": "VeilGraph-SIH-2026/Phase1-Holdout",
    }
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=90) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status} from holdout endpoint")
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            if attempt + 1 < attempts:
                time.sleep(1.5 * (attempt + 1))
                continue
            break
    raise RuntimeError(
        "Could not acquire the public held-out rows from Hugging Face Dataset Viewer. "
        "Do not modify Broad PII v5. Check internet access and rerun the same command. "
        f"Last error: {last}"
    )


def _page_url(offset: int, length: int) -> str:
    params = {
        "dataset": DATASET,
        "config": CONFIG,
        "split": SPLIT,
        "where": FILTER_WHERE,
        "offset": str(offset),
        "length": str(length),
    }
    return API_BASE + "?" + urllib.parse.urlencode(params)


def acquire_filtered_rows() -> tuple[list[dict], str, int | None]:
    """Acquire only synthetic test rows and return canonical stream hash."""
    rows: list[dict] = []
    stream = hashlib.sha256()
    offset = 0
    reported_total: int | None = None
    while True:
        payload = _request_json(_page_url(offset, PAGE_SIZE))
        page_rows = payload.get("rows")
        if not isinstance(page_rows, list):
            raise RuntimeError("Dataset Viewer response has no rows list")
        if reported_total is None and isinstance(payload.get("num_rows_total"), int):
            reported_total = int(payload["num_rows_total"])
        if not page_rows:
            break
        for entry in page_rows:
            if not isinstance(entry, dict) or not isinstance(entry.get("row"), dict):
                raise RuntimeError("Malformed Dataset Viewer row")
            if entry.get("truncated_cells"):
                raise RuntimeError(
                    f"Holdout row {entry.get('row_idx')} contains truncated cells; refusing partial evaluation"
                )
            row = entry["row"]
            if str(row.get("data_source") or "").casefold() != "synthetic":
                raise RuntimeError("Filter integrity failure: non-synthetic row returned")
            source_text = row.get("source_text")
            privacy_mask = row.get("privacy_mask")
            if not isinstance(source_text, str) or not isinstance(privacy_mask, list):
                raise RuntimeError("Holdout row missing source_text/privacy_mask")
            canonical = json.dumps(
                {"row_idx": entry.get("row_idx"), "row": row},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            stream.update(len(canonical).to_bytes(8, "big"))
            stream.update(canonical)
            rows.append(row)
        offset += len(page_rows)
        if len(page_rows) < PAGE_SIZE:
            break
        if offset > EXPECTED_SYNTHETIC_TEST_ROWS + PAGE_SIZE:
            raise RuntimeError("Holdout endpoint returned more rows than the frozen protocol permits")
    if len(rows) != EXPECTED_SYNTHETIC_TEST_ROWS:
        raise RuntimeError(
            f"Expected {EXPECTED_SYNTHETIC_TEST_ROWS} synthetic test rows, got {len(rows)}; refusing partial/changed holdout"
        )
    if reported_total is not None and reported_total != EXPECTED_SYNTHETIC_TEST_ROWS:
        raise RuntimeError(
            f"Dataset Viewer reports {reported_total} filtered rows, expected {EXPECTED_SYNTHETIC_TEST_ROWS}"
        )
    return rows, stream.hexdigest(), reported_total


@dataclass(frozen=True)
class Gold:
    label: str
    start: int
    end: int
    value: str
    compatible_types: frozenset[str]


@dataclass(frozen=True)
class Pred:
    entity_type: str
    start: int
    end: int
    value: str


def _gold_for_row(row: dict) -> tuple[list[Gold], Counter]:
    text = row["source_text"]
    supported: list[Gold] = []
    excluded = Counter()
    for raw in row.get("privacy_mask") or []:
        if not isinstance(raw, dict):
            continue
        label = str(raw.get("label") or "").strip().upper()
        compatible = GOLD_TO_VEILGRAPH.get(label)
        if not compatible:
            excluded[label or "<MISSING>"] += 1
            continue
        try:
            start = int(raw["start"])
            end = int(raw["end"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (0 <= start < end <= len(text)):
            continue
        value = str(raw.get("value") or text[start:end])
        supported.append(Gold(label, start, end, value, frozenset(compatible)))
    return supported, excluded


def _predictions(text: str) -> list[Pred]:
    from app.detection.pipeline import detect_all
    from app.extraction.document_processor import processed_document_from_decoded_text

    doc = processed_document_from_decoded_text(text)
    result: list[Pred] = []
    for mention in detect_all(doc):
        et = mention.entity_type.value
        if et not in SHARED_VEILGRAPH_TYPES:
            continue
        result.append(Pred(et, int(mention.page_char_start), int(mention.page_char_end), mention.plaintext))
    return result


def _compatible(gold: Gold, pred: Pred) -> bool:
    return pred.entity_type in gold.compatible_types


def _exact_match(gold: Gold, pred: Pred) -> bool:
    return _compatible(gold, pred) and gold.start == pred.start and gold.end == pred.end


def _relaxed_match(gold: Gold, pred: Pred) -> bool:
    if not _compatible(gold, pred):
        return False
    intersection = max(0, min(gold.end, pred.end) - max(gold.start, pred.start))
    if intersection <= 0:
        return False
    gold_len = max(1, gold.end - gold.start)
    pred_len = max(1, pred.end - pred.start)
    if intersection / gold_len >= 0.50 or intersection / pred_len >= 0.50:
        return True
    gv, pv = _normalize(gold.value), _normalize(pred.value)
    return bool(gv and pv and (gv in pv or pv in gv))


def _one_to_one(gold: list[Gold], pred: list[Pred], matcher) -> tuple[int, int, int]:
    used: set[int] = set()
    tp = 0
    for g in gold:
        options = [
            (abs((p.end - p.start) - (g.end - g.start)), index)
            for index, p in enumerate(pred)
            if index not in used and matcher(g, p)
        ]
        if not options:
            continue
        _distance, index = min(options)
        used.add(index)
        tp += 1
    return tp, len(pred) - len(used), len(gold) - tp


def _coverage(gold: list[Gold], pred: list[Pred], matcher) -> tuple[int, int, int]:
    gold_hit = sum(1 for g in gold if any(matcher(g, p) for p in pred))
    pred_hit = sum(1 for p in pred if any(matcher(g, p) for g in gold))
    return gold_hit, pred_hit, len(gold), len(pred)


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    b2 = 4.0
    f2 = (1 + b2) * p * r / (b2 * p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f1, "f2": f2}


def evaluate_rows(rows: Iterable[dict]) -> dict:
    exact = Counter()
    relaxed_gold_hit = relaxed_pred_hit = relaxed_gold = relaxed_pred = 0
    critical_hit = critical_total = 0
    contextual_hit = contextual_total = 0
    per_label = defaultdict(lambda: Counter())
    per_dimension = defaultdict(lambda: Counter())
    excluded_labels = Counter()
    negative_docs = negative_fp_docs = 0
    documents = 0
    total_predictions = 0

    for row in rows:
        documents += 1
        text = row["source_text"]
        gold, excluded = _gold_for_row(row)
        excluded_labels.update(excluded)
        pred = _predictions(text)
        total_predictions += len(pred)

        etp, efp, efn = _one_to_one(gold, pred, _exact_match)
        exact.update({"tp": etp, "fp": efp, "fn": efn})

        gh, ph, gt, pt = _coverage(gold, pred, _relaxed_match)
        relaxed_gold_hit += gh
        relaxed_pred_hit += ph
        relaxed_gold += gt
        relaxed_pred += pt

        if gt == 0:
            negative_docs += 1
            if pt > 0:
                negative_fp_docs += 1

        dimension = str(row.get("feature_dimension") or "unknown")
        for g in gold:
            hit = any(_relaxed_match(g, p) for p in pred)
            per_label[g.label]["gold"] += 1
            per_label[g.label]["hit"] += int(hit)
            per_dimension[dimension]["gold"] += 1
            per_dimension[dimension]["hit"] += int(hit)
            if g.label in CRITICAL_GOLD_LABELS:
                critical_total += 1
                critical_hit += int(hit)
            if g.label in CONTEXTUAL_GOLD_LABELS:
                contextual_total += 1
                contextual_hit += int(hit)

    exact_metrics = _prf(exact["tp"], exact["fp"], exact["fn"])
    relaxed_precision = relaxed_pred_hit / relaxed_pred if relaxed_pred else 0.0
    relaxed_recall = relaxed_gold_hit / relaxed_gold if relaxed_gold else 0.0
    relaxed_f1 = (
        2 * relaxed_precision * relaxed_recall / (relaxed_precision + relaxed_recall)
        if relaxed_precision + relaxed_recall else 0.0
    )
    relaxed_f2 = (
        5 * relaxed_precision * relaxed_recall / (4 * relaxed_precision + relaxed_recall)
        if relaxed_precision + relaxed_recall else 0.0
    )
    no_entity_fp_doc_rate = (
        negative_fp_docs / negative_docs if negative_docs else None
    )
    per_label_result = {
        label: {
            "gold": values["gold"],
            "covered": values["hit"],
            "relaxed_recall": values["hit"] / values["gold"] if values["gold"] else None,
        }
        for label, values in sorted(per_label.items())
    }
    per_dimension_result = {
        dim: {
            "gold": values["gold"],
            "covered": values["hit"],
            "relaxed_recall": values["hit"] / values["gold"] if values["gold"] else None,
        }
        for dim, values in sorted(per_dimension.items())
    }
    return {
        "documents": documents,
        "shared_taxonomy_gold_mentions": relaxed_gold,
        "shared_taxonomy_predictions": relaxed_pred,
        "excluded_gold_label_counts": dict(sorted(excluded_labels.items())),
        "exact": {**dict(exact), **exact_metrics},
        "relaxed_compatible_span_coverage": {
            "gold_covered": relaxed_gold_hit,
            "prediction_supported": relaxed_pred_hit,
            "gold_total": relaxed_gold,
            "prediction_total": relaxed_pred,
            "precision": relaxed_precision,
            "recall": relaxed_recall,
            "f1": relaxed_f1,
            "f2": relaxed_f2,
        },
        "critical_shared_recall": critical_hit / critical_total if critical_total else None,
        "critical_shared_gold": critical_total,
        "contextual_shared_recall": contextual_hit / contextual_total if contextual_total else None,
        "contextual_shared_gold": contextual_total,
        "negative_documents_with_no_shared_gold": negative_docs,
        "negative_documents_with_prediction": negative_fp_docs,
        "no_entity_fp_document_rate": no_entity_fp_doc_rate,
        "per_gold_label": per_label_result,
        "per_feature_dimension": per_dimension_result,
        "metric_note": (
            "Primary relaxed metrics score only the predeclared shared taxonomy and require compatible entity families plus span overlap. "
            "Unsupported external labels are counted and excluded, never silently remapped. Exact metrics require compatible family and exact offsets."
        ),
    }


def quality_gate(result: dict) -> dict:
    exact_f1 = float(result["exact"]["f1"])
    relaxed = result["relaxed_compatible_span_coverage"]
    critical = result["critical_shared_recall"]
    contextual = result["contextual_shared_recall"]
    fp_rate = result["no_entity_fp_document_rate"]
    checks = {
        "exact_f1": {
            "value": exact_f1,
            "threshold": THRESHOLDS["exact_f1_min"],
            "pass": exact_f1 >= THRESHOLDS["exact_f1_min"],
        },
        "relaxed_f1": {
            "value": float(relaxed["f1"]),
            "threshold": THRESHOLDS["relaxed_f1_min"],
            "pass": float(relaxed["f1"]) >= THRESHOLDS["relaxed_f1_min"],
        },
        "critical_recall": {
            "value": critical,
            "threshold": THRESHOLDS["critical_recall_min"],
            "pass": critical is not None and float(critical) >= THRESHOLDS["critical_recall_min"],
        },
        "contextual_relaxed_recall": {
            "value": contextual,
            "threshold": THRESHOLDS["contextual_relaxed_recall_min"],
            "pass": contextual is not None and float(contextual) >= THRESHOLDS["contextual_relaxed_recall_min"],
        },
        "no_entity_fp_doc_rate": {
            "value": fp_rate,
            "threshold": THRESHOLDS["no_entity_fp_doc_rate_max"],
            "pass": fp_rate is None or float(fp_rate) <= THRESHOLDS["no_entity_fp_doc_rate_max"],
            "not_applicable_when_no_negative_docs": True,
        },
    }
    return {"pass": all(item["pass"] for item in checks.values()), "checks": checks}


def _fmt(value: object) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}"


def write_report(*, result: dict, gate: dict, provenance: dict, stream_sha: str, freeze_sha: str) -> None:
    out_dir = ROOT / "competition" / "phase1"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / "EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json"
    out_md = out_dir / "EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_REPORT.md"
    payload = {
        "schema": "veilgraph.external-holdout.ari-synthetic-test.v1",
        "holdout_status": "UNTOUCHED_TEST_ROWS_UNTIL_BROAD_PII_V5_FREEZE",
        "detector_generation": "Broad PII v5",
        "detector_freeze_manifest_sha256": freeze_sha,
        "source": {
            "dataset": DATASET,
            "revision": provenance["pinned_data_revision"],
            "observed_repository_head": provenance["observed_repository_head"],
            "observed_repository_head_after": provenance.get("observed_repository_head_after", provenance["observed_repository_head"]),
            "data_artifact_identity_verified": provenance["data_artifact_identity_verified"],
            "verified_test_parquet_sha256": provenance["test_parquet_sha256"],
            "split": SPLIT,
            "filter": "data_source == synthetic",
            "expected_full_test_rows": EXPECTED_TEST_ROWS,
            "expected_synthetic_test_rows": EXPECTED_SYNTHETIC_TEST_ROWS,
            "test_parquet_lfs_sha256": EXPECTED_TEST_PARQUET_LFS_SHA256,
            "dataset_viewer_stream_sha256": stream_sha,
            "license": LICENSE,
        },
        "thresholds_predeclared_before_holdout": THRESHOLDS,
        "results": result,
        "quality_gate": gate,
        "raw_holdout_persisted_in_repository": False,
        "detector_tuned_on_test_rows": False,
        "source_family_note": (
            "The evaluated 1,201 rows are the dataset's held-out synthetic challenge split. "
            "The ai4privacy rows in the same dataset are excluded."
        ),
    }
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    exact = result["exact"]
    relaxed = result["relaxed_compatible_span_coverage"]
    lines = [
        "# VeilGraph External Holdout — Ari Synthetic Test",
        "",
        "## Scientific status",
        "",
        "- Broad PII v5 was byte-for-byte frozen before requesting any synthetic test row.",
        "- Only `data_source == synthetic` rows from the test split are evaluated.",
        "- The ai4privacy portion is excluded from this final v5 holdout.",
        "- Raw test rows are not persisted in the VeilGraph repository.",
        "- Thresholds and taxonomy mapping were declared before acquisition.",
        "",
        "## Provenance",
        "",
        f"- Dataset: `{DATASET}`",
        f"- Pinned data revision: `{provenance['pinned_data_revision']}`",
        f"- Observed repository HEAD: `{provenance['observed_repository_head']}`",
        f"- Test artifact byte identity verified: **{provenance['data_artifact_identity_verified']}**",
        f"- Synthetic test records: **{result['documents']}**",
        f"- Dataset-viewer canonical stream SHA-256: `{stream_sha}`",
        f"- Test Parquet LFS SHA-256 declared by repository: `{EXPECTED_TEST_PARQUET_LFS_SHA256}`",
        "",
        "## Cross-taxonomy metrics",
        "",
        f"- Exact precision: **{_fmt(exact['precision'])}**",
        f"- Exact recall: **{_fmt(exact['recall'])}**",
        f"- Exact F1: **{_fmt(exact['f1'])}**",
        f"- Exact F2: **{_fmt(exact['f2'])}**",
        f"- Relaxed compatible-span precision: **{_fmt(relaxed['precision'])}**",
        f"- Relaxed compatible-span recall: **{_fmt(relaxed['recall'])}**",
        f"- Relaxed compatible-span F1: **{_fmt(relaxed['f1'])}**",
        f"- Relaxed compatible-span F2: **{_fmt(relaxed['f2'])}**",
        f"- Critical shared recall: **{_fmt(result['critical_shared_recall'])}**",
        f"- Contextual shared recall: **{_fmt(result['contextual_shared_recall'])}**",
        f"- No-entity FP document rate: **{_fmt(result['no_entity_fp_document_rate'])}**",
        "",
        f"## Predeclared quality gate: **{'PASS' if gate['pass'] else 'FAIL'}**",
        "",
        "| Check | Value | Required | Status |",
        "|---|---:|---:|---|",
    ]
    for name, item in gate["checks"].items():
        comparator = "≤" if name == "no_entity_fp_doc_rate" else "≥"
        lines.append(
            f"| {name} | {_fmt(item['value'])} | {comparator} {_fmt(item['threshold'])} | {'PASS' if item['pass'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "## Per-label relaxed recall",
        "",
        "| External label | Gold | Covered | Recall |",
        "|---|---:|---:|---:|",
    ])
    for label, values in result["per_gold_label"].items():
        lines.append(f"| {label} | {values['gold']} | {values['covered']} | {_fmt(values['relaxed_recall'])} |")
    lines.extend([
        "",
        "## Challenge-dimension relaxed recall",
        "",
        "| Dimension | Gold | Covered | Recall |",
        "|---|---:|---:|---:|",
    ])
    for dim, values in result["per_feature_dimension"].items():
        lines.append(f"| {dim} | {values['gold']} | {values['covered']} | {_fmt(values['relaxed_recall'])} |")
    if result["excluded_gold_label_counts"]:
        lines.extend([
            "",
            "## Non-shared external labels",
            "",
            "These labels are disclosed and excluded from the primary VeilGraph cross-taxonomy metric because no equivalent VeilGraph entity class was predeclared:",
            "",
        ])
        for label, count in result["excluded_gold_label_counts"].items():
            lines.append(f"- `{label}`: {count}")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_json.relative_to(ROOT)}")
    print(f"Wrote {out_md.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-revision-check", action="store_true", help="Protocol-test escape hatch only; skips immutable artifact verification. Do not use for competition evidence.")
    args = parser.parse_args()

    print("Broad PII v5 freeze verified BEFORE external holdout acquisition.")
    freeze_sha = verify_freeze()

    if args.skip_revision_check:
        provenance = {
            "pinned_data_revision": EXPECTED_REVISION,
            "observed_repository_head": EXPECTED_REVISION,
            "test_parquet_sha256": EXPECTED_TEST_PARQUET_LFS_SHA256,
            "data_artifact_identity_verified": True,
        }
    else:
        print("Verifying immutable pinned external test artifact ...")
        provenance = verify_pinned_data_artifact()
        if provenance["observed_repository_head"] != EXPECTED_REVISION:
            print(
                "Repository HEAD differs from the original pinned commit, but the exact test Parquet "
                "artifact is byte-identical to the predeclared SHA-256. Proceeding with the same holdout."
            )
    print(f"Pinned data revision: {provenance['pinned_data_revision']}")
    print(f"Observed repository HEAD: {provenance['observed_repository_head']}")
    print(f"Verified test Parquet SHA-256: {provenance['test_parquet_sha256']}")
    print(f"Acquiring {EXPECTED_SYNTHETIC_TEST_ROWS} held-out synthetic TEST rows via Dataset Viewer API ...")
    rows, stream_sha, _reported_total = acquire_filtered_rows()
    print(f"Holdout validated: {len(rows)} synthetic test records | stream SHA-256 {stream_sha}")

    # Re-check repository drift after acquisition. Metadata-only drift is acceptable only
    # while the exact frozen test artifact remains byte-identical.
    if not args.skip_revision_check:
        head_after = _git_head()
        provenance["observed_repository_head_after"] = head_after
        if head_after != provenance["observed_repository_head"]:
            after_sha = _hash_remote_test_artifact(head_after)
            if after_sha != EXPECTED_TEST_PARQUET_LFS_SHA256:
                raise RuntimeError(
                    "External dataset changed during acquisition and the test artifact no longer "
                    "matches the frozen SHA-256. Refusing this run."
                )

    result = evaluate_rows(rows)
    gate = quality_gate(result)

    # Drop raw rows before final verification/report persistence.
    del rows
    freeze_after = verify_freeze()
    if freeze_after != freeze_sha:
        raise RuntimeError("Broad PII v5 freeze manifest changed during external evaluation")
    print("Broad PII v5 freeze verified AFTER external holdout evaluation.")

    write_report(result=result, gate=gate, provenance=provenance, stream_sha=stream_sha, freeze_sha=freeze_sha)
    exact = result["exact"]
    relaxed = result["relaxed_compatible_span_coverage"]
    print("\nARI SYNTHETIC TEST EXTERNAL HOLDOUT RESULT")
    print(f"  documents: {result['documents']}")
    print(f"  exact   P={exact['precision']:.4f} R={exact['recall']:.4f} F1={exact['f1']:.4f} F2={exact['f2']:.4f}")
    print(f"  relaxed P={relaxed['precision']:.4f} R={relaxed['recall']:.4f} F1={relaxed['f1']:.4f} F2={relaxed['f2']:.4f}")
    print(f"  critical recall:   {_fmt(result['critical_shared_recall'])}")
    print(f"  contextual recall: {_fmt(result['contextual_shared_recall'])}")
    print(f"  quality gate: {'PASS' if gate['pass'] else 'FAIL'}")
    return 0 if gate["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
