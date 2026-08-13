#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.benchmark.piimb import load_piimb_jsonl, _merge_spans, _intersection_length, _span_length, _scores
from app.detection.pipeline import detect_all
from app.extraction.document_processor import processed_document_from_decoded_text

OUT = ROOT / "competition" / "phase3" / "COTS_QUANTITATIVE_RESULTS.json"
OUT_MD = ROOT / "competition" / "phase3" / "COTS_QUANTITATIVE_REPORT.md"


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    pos = (len(values) - 1) * q
    low, high = math.floor(pos), math.ceil(pos)
    if low == high:
        return values[low]
    return values[low] * (high - pos) + values[high] * (pos - low)


def evaluate(rows: list[dict], adapter: Callable[[str], list[tuple[int, int]]], name: str, metadata: dict) -> dict:
    tp = fp = fn = non_pii = 0
    latencies: list[float] = []
    errors = 0
    started = time.perf_counter()
    for row in rows:
        text = row["text"]
        gold = _merge_spans(((int(e.get("start", -1)), int(e.get("end", -1))) for e in row["entities"] if isinstance(e, dict)), len(text))
        t0 = time.perf_counter()
        try:
            pred = _merge_spans(adapter(text), len(text))
        except Exception:
            errors += 1
            pred = []
        latencies.append((time.perf_counter() - t0) * 1000.0)
        gold_chars = _span_length(gold); pred_chars = _span_length(pred)
        overlap = _intersection_length(gold, pred)
        tp += overlap; fp += max(0, pred_chars - overlap); fn += max(0, gold_chars - overlap); non_pii += max(0, len(text) - gold_chars)
    wall = time.perf_counter() - started
    return {
        "system": name,
        "status": "EXECUTED" if errors == 0 else "EXECUTED_WITH_ERRORS",
        "metadata": metadata,
        "rows": len(rows),
        "errors": errors,
        "metrics": _scores(tp, fp, fn, non_pii),
        "performance": {
            "wall_seconds": round(wall, 6),
            "mean_row_ms": round(statistics.mean(latencies), 6) if latencies else 0.0,
            "median_row_ms": round(statistics.median(latencies), 6) if latencies else 0.0,
            "p95_row_ms": round(percentile(latencies, 0.95), 6),
            "rows_per_second": round(len(rows) / wall, 6) if wall else 0.0,
        },
    }


def veilgraph_adapter(text: str) -> list[tuple[int, int]]:
    doc = processed_document_from_decoded_text(text)
    return [(int(d.page_char_start), int(d.page_char_end)) for d in detect_all(doc)]


def presidio_adapter():
    try:
        import platform
        import presidio_analyzer
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        version = getattr(presidio_analyzer, "__version__", "installed")
    except Exception as exc:
        return None, {"status": "NOT_EXECUTED", "reason": f"Presidio unavailable: {type(exc).__name__}: {exc}"}
    def run(text: str) -> list[tuple[int, int]]:
        return [(int(r.start), int(r.end)) for r in analyzer.analyze(text=text, language="en")]
    py_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    return run, {
        "package": "presidio-analyzer",
        "version": version,
        "deployment": "local",
        "nlp_engine": "spaCy",
        "spacy_version": spacy.__version__,
        "spacy_model": "en_core_web_sm-3.8.0",
        "python": platform.python_version(),
        "presidio_published_python_range_note": (
            "within published 3.10-3.13 range" if py_minor in {"3.10", "3.11", "3.12", "3.13"}
            else "outside Presidio published 3.10-3.13 support range; benchmark executed only if smoke/runtime succeeds"
        ),
    }


def aws_adapter(allow: bool):
    if not allow:
        return None, {"status": "NOT_EXECUTED", "reason": "Commercial calls disabled; rerun with --allow-commercial-calls and AWS credentials."}
    try:
        import boto3
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise RuntimeError("AWS_REGION/AWS_DEFAULT_REGION is required")
        client = boto3.client("comprehend", region_name=region)
    except Exception as exc:
        return None, {"status": "NOT_EXECUTED", "reason": f"AWS adapter unavailable: {type(exc).__name__}: {exc}"}
    def run(text: str) -> list[tuple[int, int]]:
        response = client.detect_pii_entities(Text=text, LanguageCode="en")
        return [(int(e["BeginOffset"]), int(e["EndOffset"])) for e in response.get("Entities", [])]
    return run, {"service": "AWS Comprehend DetectPiiEntities", "region": region, "deployment": "commercial cloud"}


def azure_adapter(allow: bool):
    if not allow:
        return None, {"status": "NOT_EXECUTED", "reason": "Commercial calls disabled; rerun with --allow-commercial-calls and Azure credentials."}
    try:
        from azure.ai.textanalytics import TextAnalyticsClient
        from azure.core.credentials import AzureKeyCredential
        endpoint = os.environ["AZURE_LANGUAGE_ENDPOINT"]
        key = os.environ["AZURE_LANGUAGE_KEY"]
        client = TextAnalyticsClient(endpoint=endpoint, credential=AzureKeyCredential(key))
    except Exception as exc:
        return None, {"status": "NOT_EXECUTED", "reason": f"Azure adapter unavailable: {type(exc).__name__}: {exc}"}
    def run(text: str) -> list[tuple[int, int]]:
        result = client.recognize_pii_entities([text], language="en")[0]
        if getattr(result, "is_error", False):
            raise RuntimeError(str(result))
        return [(int(e.offset), int(e.offset + e.length)) for e in result.entities]
    return run, {"service": "Azure AI Language PII", "endpoint_host": endpoint.split('/')[2] if '//' in endpoint else "configured", "deployment": "commercial cloud"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("piimb_jsonl", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--allow-commercial-calls", action="store_true")
    args = parser.parse_args()
    if args.limit <= 0 or args.limit > 1000:
        raise SystemExit("--limit must be 1..1000 for bounded COTS evaluation")
    rows, accounting = load_piimb_jsonl(args.piimb_jsonl, task="ai4privacy-en", limit=args.limit)
    if len(rows) != args.limit:
        raise SystemExit(f"Requested {args.limit} rows but only loaded {len(rows)}")
    systems = []
    systems.append(evaluate(rows, veilgraph_adapter, "VeilGraph", {"detector": "Broad PII v5 + Semantic NER v3", "runtime_external_model_api": False}))
    for name, factory in [("Microsoft Presidio", lambda: presidio_adapter()), ("AWS Comprehend PII", lambda: aws_adapter(args.allow_commercial_calls)), ("Azure AI Language PII", lambda: azure_adapter(args.allow_commercial_calls))]:
        adapter, meta = factory()
        if adapter is None:
            systems.append({"system": name, **meta})
        else:
            systems.append(evaluate(rows, adapter, name, meta))
    commercial_executed = any(item.get("status") == "EXECUTED" and item.get("errors", 0) == 0 and item["system"] in {"AWS Comprehend PII", "Azure AI Language PII"} for item in systems)
    external_executed = any(item.get("status") == "EXECUTED" and item.get("errors", 0) == 0 and item["system"] != "VeilGraph" for item in systems)
    report = {
        "schema": "veilgraph.cots-quantitative.v1",
        "generated_at_unix": int(time.time()),
        "dataset": {"name": "PIIMB: PII Masking Benchmark", "path_name": args.piimb_jsonl.name, "sha256": file_sha(args.piimb_jsonl), "rows": len(rows), "task": "ai4privacy-en", "label_accounting": dict(accounting)},
        "metric": "character-level label-agnostic PII coverage, identical rows for every executed system",
        "systems": systems,
        "acceptance": {
            "veilgraph_executed": True,
            "external_off_the_shelf_executed": external_executed,
            "commercial_cots_executed": commercial_executed,
        },
        "literal_ntro_cots_requirement_closed": commercial_executed,
        "claim_boundary": "NOT_EXECUTED systems have no substituted marketing numbers. Commercial execution may incur vendor charges and requires explicit credentials/flag.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# VeilGraph COTS Quantitative Benchmark", "", f"Dataset SHA-256: `{report['dataset']['sha256']}` · rows: {len(rows)}", "", "| System | Status | Precision | Recall | F1 | p95 ms/row |", "|---|---|---:|---:|---:|---:|"]
    for item in systems:
        if item.get("status", "").startswith("EXECUTED"):
            m=item["metrics"]; p=item["performance"]
            lines.append(f"| {item['system']} | {item['status']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {p['p95_row_ms']:.2f} |")
        else:
            lines.append(f"| {item['system']} | NOT EXECUTED | — | — | — | — |")
    lines += ["", f"Commercial COTS requirement closed: **{'YES' if commercial_executed else 'NO'}**", "", report["claim_boundary"], ""]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(report["acceptance"], indent=2, sort_keys=True))
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
