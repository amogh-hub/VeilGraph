from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from app.detection.pipeline import detect_all
from app.extraction.document_processor import processed_document_from_decoded_text



def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _merge_spans(spans: Iterable[tuple[int, int]], text_length: int) -> list[tuple[int, int]]:
    cleaned = sorted((max(0, int(start)), min(text_length, int(end))) for start, end in spans if int(end) > int(start))
    merged: list[list[int]] = []
    for start, end in cleaned:
        if start >= end:
            continue
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def _span_length(spans: Sequence[tuple[int, int]]) -> int:
    return sum(end - start for start, end in spans)


def _intersection_length(first: Sequence[tuple[int, int]], second: Sequence[tuple[int, int]]) -> int:
    i = j = 0
    total = 0
    while i < len(first) and j < len(second):
        a0, a1 = first[i]
        b0, b1 = second[j]
        total += max(0, min(a1, b1) - max(a0, b0))
        if a1 <= b1:
            i += 1
        else:
            j += 1
    return total


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _scores(tp: int, fp: int, fn: int, non_pii_chars: int) -> dict[str, float | int]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    beta2 = 4.0
    f2 = _safe_div((1 + beta2) * precision * recall, beta2 * precision + recall)
    return {
        "tp_characters": tp,
        "fp_characters": fp,
        "fn_characters": fn,
        "non_pii_characters": non_pii_chars,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "f2": round(f2, 6),
        "fpr": round(_safe_div(fp, non_pii_chars), 6),
    }


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    fraction = position - low
    return ordered[low] * (1 - fraction) + ordered[high] * fraction


def load_piimb_jsonl(path: Path, *, task: str | None = "ai4privacy-en", limit: int = 5000) -> tuple[list[dict[str, Any]], Counter[str]]:
    if limit <= 0:
        raise ValueError("PIIMB limit must be positive")
    rows: list[dict[str, Any]] = []
    counters: Counter[str] = Counter()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if len(rows) >= limit:
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                counters["invalid_json"] += 1
                continue
            if not isinstance(row, dict) or not isinstance(row.get("text"), str):
                counters["invalid_row"] += 1
                continue
            row_task = str(row.get("task_name") or "")
            if task and row_task != task:
                counters["task_filtered"] += 1
                continue
            entities = row.get("entities")
            if not isinstance(entities, list):
                counters["invalid_entities"] += 1
                continue
            rows.append(row)
            counters[f"task:{row_task or 'unknown'}"] += 1
            counters[f"language:{row.get('language') or 'unknown'}"] += 1
    return rows, counters


def benchmark_piimb(path: Path, *, task: str | None = "ai4privacy-en", limit: int = 5000) -> dict:
    rows, counters = load_piimb_jsonl(path, task=task, limit=limit)
    if not rows:
        raise ValueError("No PIIMB benchmark rows matched the requested task")

    totals: Counter[str] = Counter()
    by_task: dict[str, Counter[str]] = defaultdict(Counter)
    latencies: list[float] = []
    exact_mask_matches = 0
    by_gold_label: dict[str, Counter[str]] = defaultdict(Counter)
    started_wall = time.perf_counter()
    started_cpu = time.process_time()

    for index, row in enumerate(rows):
        text = row["text"]
        gold_spans = _merge_spans(
            (
                (int(entity.get("start", -1)), int(entity.get("end", -1)))
                for entity in row["entities"]
                if isinstance(entity, dict)
            ),
            len(text),
        )
        case_started = time.perf_counter()
        document = processed_document_from_decoded_text(text)
        detections = detect_all(document)
        predicted_spans = _merge_spans(
            ((item.page_char_start, item.page_char_end) for item in detections),
            len(text),
        )
        latencies.append((time.perf_counter() - case_started) * 1000.0)

        # Diagnostic only: official PIIMB scoring below remains character-level
        # and label-agnostic. This breakdown tells us which published gold
        # categories are driving misses without changing the benchmark metric.
        for entity in row["entities"]:
            if not isinstance(entity, dict):
                continue
            try:
                start = max(0, int(entity.get("start", -1)))
                end = min(len(text), int(entity.get("end", -1)))
            except (TypeError, ValueError):
                continue
            if end <= start:
                continue
            label = str(entity.get("label") or "UNKNOWN").upper()
            covered = _intersection_length([(start, end)], predicted_spans)
            bucket = by_gold_label[label]
            bucket["span_count"] += 1
            bucket["gold_characters"] += end - start
            bucket["covered_characters"] += covered
            if covered >= end - start:
                bucket["fully_covered_spans"] += 1

        gold_chars = _span_length(gold_spans)
        pred_chars = _span_length(predicted_spans)
        tp = _intersection_length(gold_spans, predicted_spans)
        fp = max(0, pred_chars - tp)
        fn = max(0, gold_chars - tp)
        non_pii = max(0, len(text) - gold_chars)
        if gold_spans == predicted_spans:
            exact_mask_matches += 1

        task_name = str(row.get("task_name") or "unknown")
        for target in (totals, by_task[task_name]):
            target["tp"] += tp
            target["fp"] += fp
            target["fn"] += fn
            target["non_pii"] += non_pii
            target["characters"] += len(text)
            target["gold_spans"] += len(gold_spans)
            target["predicted_spans"] += len(predicted_spans)

    wall_ms = (time.perf_counter() - started_wall) * 1000.0
    cpu_ms = (time.process_time() - started_cpu) * 1000.0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_rss_mb = rss / (1024 * 1024) if os.uname().sysname == "Darwin" else rss / 1024

    return {
        "dataset": {
            "name": "PIIMB: PII Masking Benchmark",
            "input_file": path.name,
            "input_sha256": _sha256_file(path),
            "task_filter": task,
            "row_limit": limit,
            "rows_scored": len(rows),
            "license": "CC-BY-NC-4.0",
            "label_agnostic": True,
            "label_accounting": dict(sorted(counters.items())),
        },
        "overall": _scores(totals["tp"], totals["fp"], totals["fn"], totals["non_pii"]),
        "by_task": {
            task_name: _scores(counts["tp"], counts["fp"], counts["fn"], counts["non_pii"])
            for task_name, counts in sorted(by_task.items())
        },
        "rows_scored": len(rows),
        "characters_scored": totals["characters"],
        "gold_mask_spans": totals["gold_spans"],
        "predicted_mask_spans": totals["predicted_spans"],
        "exact_mask_matches": exact_mask_matches,
        "diagnostic_by_gold_label": {
            label: {
                "span_count": counts["span_count"],
                "gold_characters": counts["gold_characters"],
                "covered_characters": counts["covered_characters"],
                "recall": round(_safe_div(counts["covered_characters"], counts["gold_characters"]), 6),
                "fully_covered_spans": counts["fully_covered_spans"],
                "full_span_rate": round(_safe_div(counts["fully_covered_spans"], counts["span_count"]), 6),
            }
            for label, counts in sorted(by_gold_label.items())
        },
        "performance": {
            "wall_ms": round(wall_ms, 3),
            "cpu_ms": round(cpu_ms, 3),
            "mean_sentence_ms": round(statistics.mean(latencies), 3),
            "median_sentence_ms": round(statistics.median(latencies), 3),
            "p95_sentence_ms": round(_percentile(latencies, 0.95), 3),
            "sentences_per_second": round(_safe_div(len(rows), wall_ms / 1000.0), 3),
            "peak_process_rss_mb": round(peak_rss_mb, 3),
        },
        "metric_definition": {
            "level": "character-level, label-agnostic masking",
            "precision": "predicted PII characters overlapping true PII / all predicted PII characters",
            "recall": "true PII characters covered / all true PII characters",
            "f1": "harmonic mean of precision and recall",
            "f2": "harmonic mean weighting recall twice as strongly as precision",
            "fpr": "predicted PII characters outside gold PII / all non-PII characters",
            "span_preprocessing": "overlapping or consecutive regions are merged before scoring",
            "diagnostic_by_gold_label": "Non-ranking diagnostic only; per-label gold-character coverage does not alter official label-agnostic PIIMB scoring.",
        },
    }
