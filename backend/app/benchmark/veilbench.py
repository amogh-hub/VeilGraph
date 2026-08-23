from __future__ import annotations

import json
import math
import os
import resource
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import normalize_value
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document


@dataclass(frozen=True)
class GoldSpan:
    entity_type: EntityType
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    domain: str
    text: str
    gold: tuple[GoldSpan, ...]
    source: str = "veilbench-curated"


def _find_occurrence(text: str, value: str, occurrence: int = 0) -> tuple[int, int]:
    start = -1
    cursor = 0
    for _ in range(occurrence + 1):
        start = text.find(value, cursor)
        if start < 0:
            raise ValueError(f"Gold value not found in benchmark text: {value!r}")
        cursor = start + len(value)
    return start, start + len(value)


def load_curated_corpus(path: Path) -> list[BenchmarkCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != "veilgraph.benchmark-corpus.v1":
        raise ValueError("Unsupported VeilBench corpus schema")
    cases: list[BenchmarkCase] = []
    for item in raw.get("cases", []):
        text = str(item["text"])
        seen: Counter[tuple[str, str]] = Counter()
        gold: list[GoldSpan] = []
        for entity in item.get("entities", []):
            if len(entity) not in {2, 3}:
                raise ValueError(f"Invalid gold entity in {item.get('id')}: {entity!r}")
            type_name, value = str(entity[0]), str(entity[1])
            occurrence = int(entity[2]) if len(entity) == 3 else seen[(type_name, value)]
            seen[(type_name, value)] += 1
            start, end = _find_occurrence(text, value, occurrence)
            gold.append(GoldSpan(EntityType(type_name), value, start, end))
        cases.append(
            BenchmarkCase(
                case_id=str(item["id"]),
                domain=str(item.get("domain", "unknown")),
                text=text,
                gold=tuple(gold),
            )
        )
    return cases


def _overlap(first_start: int, first_end: int, second_start: int, second_end: int) -> float:
    intersection = max(0, min(first_end, second_end) - max(first_start, second_start))
    if intersection <= 0:
        return 0.0
    union = max(first_end, second_end) - min(first_start, second_start)
    return intersection / union if union else 0.0


def _match_case(case: BenchmarkCase, prediction_scope: set[EntityType] | None = None) -> dict:
    document = process_document(case.text.encode("utf-8"), FileType.TEXT, f"{case.case_id}.txt")
    predictions = detect_all(document)
    if prediction_scope is not None:
        predictions = [item for item in predictions if item.entity_type in prediction_scope]
    unmatched_gold = set(range(len(case.gold)))
    tp: list[tuple[int, int]] = []
    fp: list[int] = []

    for p_index, prediction in enumerate(predictions):
        best: tuple[float, int] | None = None
        for g_index in unmatched_gold:
            gold = case.gold[g_index]
            if gold.entity_type != prediction.entity_type:
                continue
            overlap = _overlap(gold.start, gold.end, prediction.page_char_start, prediction.page_char_end)
            same_value = normalize_value(gold.entity_type, gold.value) == normalize_value(
                prediction.entity_type, prediction.plaintext
            )
            score = max(overlap, 1.0 if same_value and overlap > 0 else 0.0)
            if score >= 0.50 and (best is None or score > best[0]):
                best = (score, g_index)
        if best is None:
            fp.append(p_index)
        else:
            unmatched_gold.remove(best[1])
            tp.append((p_index, best[1]))

    false_negatives = sorted(unmatched_gold)
    return {
        "case": case,
        "predictions": predictions,
        "tp_pairs": tp,
        "fp_indices": fp,
        "fn_indices": false_negatives,
    }


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _metrics(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        # Entity extraction does not have a meaningful true-negative span count.
        # These two rates are therefore defined over predictions and gold spans,
        # respectively, and are explicitly named to avoid pretending they are
        # classical TN-based classification FPR/FNR.
        "prediction_false_positive_rate": round(_safe_div(fp, tp + fp), 6),
        "gold_false_negative_rate": round(_safe_div(fn, tp + fn), 6),
    }


def benchmark_cases(cases: Sequence[BenchmarkCase], prediction_scope: set[EntityType] | None = None) -> dict:
    if not cases:
        raise ValueError("VeilBench requires at least one benchmark case")

    started_wall = time.perf_counter()
    started_cpu = time.process_time()
    case_latencies: list[float] = []
    results: list[dict] = []
    by_type_counts: dict[EntityType, Counter[str]] = defaultdict(Counter)
    domain_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for case in cases:
        case_started = time.perf_counter()
        matched = _match_case(case, prediction_scope=prediction_scope)
        elapsed_ms = (time.perf_counter() - case_started) * 1000.0
        case_latencies.append(elapsed_ms)

        for _p_index, g_index in matched["tp_pairs"]:
            entity_type = case.gold[g_index].entity_type
            by_type_counts[entity_type]["tp"] += 1
            domain_counts[case.domain]["tp"] += 1
        for p_index in matched["fp_indices"]:
            entity_type = matched["predictions"][p_index].entity_type
            by_type_counts[entity_type]["fp"] += 1
            domain_counts[case.domain]["fp"] += 1
        for g_index in matched["fn_indices"]:
            entity_type = case.gold[g_index].entity_type
            by_type_counts[entity_type]["fn"] += 1
            domain_counts[case.domain]["fn"] += 1

        results.append(
            {
                "id": case.case_id,
                "domain": case.domain,
                "source": case.source,
                "gold": len(case.gold),
                "predicted": len(matched["predictions"]),
                "tp": len(matched["tp_pairs"]),
                "fp": len(matched["fp_indices"]),
                "fn": len(matched["fn_indices"]),
                "exact_case_pass": not matched["fp_indices"] and not matched["fn_indices"],
                "latency_ms": round(elapsed_ms, 3),
                "false_positive_types": [matched["predictions"][i].entity_type.value for i in matched["fp_indices"]],
                "false_negative_types": [case.gold[i].entity_type.value for i in matched["fn_indices"]],
            }
        )

    total_counts = Counter()
    for counts in by_type_counts.values():
        total_counts.update(counts)
    overall = _metrics(total_counts["tp"], total_counts["fp"], total_counts["fn"])

    per_entity = {}
    for entity_type in sorted(by_type_counts, key=lambda value: value.value):
        counts = by_type_counts[entity_type]
        per_entity[entity_type.value] = _metrics(counts["tp"], counts["fp"], counts["fn"])

    per_domain = {}
    for domain in sorted(domain_counts):
        counts = domain_counts[domain]
        per_domain[domain] = _metrics(counts["tp"], counts["fp"], counts["fn"])

    f1_values = [float(value["f1"]) for value in per_entity.values() if (value["tp"] + value["fn"]) > 0]
    wall_ms = (time.perf_counter() - started_wall) * 1000.0
    cpu_ms = (time.process_time() - started_cpu) * 1000.0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS returns bytes, Linux returns KiB.
    peak_rss_mb = rss / (1024 * 1024) if os.uname().sysname == "Darwin" else rss / 1024

    return {
        "case_count": len(cases),
        "gold_span_count": sum(len(case.gold) for case in cases),
        "exact_case_passes": sum(1 for result in results if result["exact_case_pass"]),
        "overall": overall,
        "macro_f1": round(statistics.mean(f1_values), 6) if f1_values else 0.0,
        "per_entity": per_entity,
        "per_domain": per_domain,
        "performance": {
            "wall_ms": round(wall_ms, 3),
            "cpu_ms": round(cpu_ms, 3),
            "mean_case_ms": round(statistics.mean(case_latencies), 3),
            "median_case_ms": round(statistics.median(case_latencies), 3),
            "p95_case_ms": round(_percentile(case_latencies, 0.95), 3),
            "cases_per_second": round(_safe_div(len(cases), wall_ms / 1000.0), 3),
            "peak_process_rss_mb": round(peak_rss_mb, 3),
            "peak_rss_note": "Process-wide maximum RSS; includes imported libraries and native dependencies.",
        },
        "cases": results,
        "metric_definition": {
            "matching": "Entity type must match and character-span overlap must be >= 0.50; normalized value equality only strengthens an overlapping match.",
            "precision": "TP / (TP + FP)",
            "recall": "TP / (TP + FN)",
            "f1": "harmonic mean of precision and recall",
            "prediction_false_positive_rate": "FP / (TP + FP); not a TN-based classification FPR",
            "gold_false_negative_rate": "FN / (TP + FN)",
        },
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
    weight = position - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def benchmark_curated(corpus_path: Path) -> dict:
    cases = load_curated_corpus(corpus_path)
    # v1 was annotated before the broad-coverage v2 taxonomy existed. Score only
    # entity types that are actually annotated in this frozen corpus; otherwise
    # valid new-class detections (for example a generic date) would be counted as
    # false positives despite having no corresponding v1 gold annotation.
    prediction_scope = {gold.entity_type for case in cases for gold in case.gold}
    result = benchmark_cases(cases, prediction_scope=prediction_scope)
    result["dataset"] = {
        "name": "VeilBench Curated Identity Exposure Corpus v1",
        "source": "VeilGraph project",
        "license": "CC0-1.0",
        "contains_real_pii": False,
        "purpose": "Internal reproducible accuracy regression; this is not the required external open-source benchmark.",
        "evaluation_scope": "Predictions are scored only for entity classes annotated in the frozen v1 corpus; broad-coverage v2-only classes are evaluated on external PIIMB and dedicated v2 tests.",
    }
    return result
