#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import math
import platform
import resource
import statistics
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

import fitz
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import db
from app.core.enums import FileType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.ingestion.validator import validate_upload


@dataclass
class Sample:
    elapsed_ms: float
    process_cpu_ms: float
    result_count: int
    signature: str
    process_high_water_rss_mib: float


@dataclass
class BenchmarkCase:
    name: str
    stage: str
    format: str
    input_bytes: int
    repeats: int
    p50_ms: float
    p95_ms: float
    max_ms: float
    p50_process_cpu_ms: float
    p95_process_cpu_ms: float
    cpu_core_equivalent_pct_p50: float
    throughput_kib_s_p50: float
    python_peak_alloc_mib: float
    process_high_water_rss_mib: float
    result_count: int
    deterministic: bool
    passed: bool


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    idx = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[idx]


def _rss_mib() -> float:
    """Return process lifetime high-water RSS, not a per-case resident-memory reading."""
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value / (1024 * 1024) if platform.system() == "Darwin" else value / 1024


def _hash_jsonable(value) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _measure(fn: Callable[[], tuple[int, str]]) -> Sample:
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    count, signature = fn()
    process_cpu_ms = (time.process_time() - cpu_started) * 1000.0
    elapsed_ms = (time.perf_counter() - wall_started) * 1000.0
    return Sample(elapsed_ms, process_cpu_ms, count, signature, _rss_mib())


def _python_peak_alloc_mib(fn: Callable[[], tuple[int, str]]) -> float:
    """Measure Python-tracked allocation peak separately so latency samples are not tracer-instrumented."""
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        fn()
        _, peak = tracemalloc.get_traced_memory()
        return peak / (1024 * 1024)
    finally:
        tracemalloc.stop()


def _text_payload(target_bytes: int) -> bytes:
    line = (
        "FICTIONAL BENCH RECORD | Name: Aarav Testperson | Email: aarav.test@example.org | "
        "Phone: +91 98765 43210 | City: Bengaluru | Case: VG-BENCH-2026-0001\n"
    ).encode("utf-8")
    repeats = max(1, math.ceil(target_bytes / len(line)))
    return (line * repeats)[:target_bytes]


def _csv_payload(rows: int) -> bytes:
    out = ["full_name,email,phone,age,city,pincode"]
    for i in range(rows):
        out.append(
            f"Fictional Person {i},bench{i}@example.org,+91 90000 {i % 100000:05d},{20 + (i % 45)},Bengaluru,{560000 + (i % 99):06d}"
        )
    return ("\n".join(out) + "\n").encode("utf-8")


def _pdf_payload(pages: int) -> bytes:
    doc = fitz.open()
    try:
        for i in range(pages):
            page = doc.new_page(width=595, height=842)
            y = 72
            for j in range(8):
                page.insert_text((60, y), f"FICTIONAL BENCH PAGE {i+1} ROW {j+1}", fontsize=10)
                y += 18
                page.insert_text(
                    (60, y),
                    f"Name: Aarav Testperson Email: bench{i}-{j}@example.org Phone: +91 98765 43210",
                    fontsize=9,
                )
                y += 24
        return doc.tobytes(garbage=4, deflate=True)
    finally:
        doc.close()


def _full_detection(data: bytes, file_type: FileType, filename: str) -> tuple[int, str]:
    doc = process_document(data, file_type, filename)
    detections = detect_all(doc)
    signature = _hash_jsonable([
        (d.entity_type.value, d.page_index, d.page_char_start, d.page_char_end, d.plaintext)
        for d in detections
    ])
    return len(detections), signature


def _extraction_only(data: bytes, file_type: FileType, filename: str) -> tuple[int, str]:
    doc = process_document(data, file_type, filename)
    signature = _hash_jsonable([
        (p.page_index, [(line.text, len(line.tokens)) for line in p.lines])
        for p in doc.pages
    ])
    return doc.page_count, signature


def _validation_only(data: bytes, filename: str) -> tuple[int, str]:
    file_type, safe_filename, sha256 = validate_upload(data, filename)
    return len(data), _hash_jsonable((file_type.value, safe_filename, sha256, len(data)))


def run_case(
    name: str,
    stage: str,
    file_type: FileType,
    filename: str,
    data: bytes,
    repeats: int,
    fn: Callable[[], tuple[int, str]],
) -> BenchmarkCase:
    _measure(fn)  # warm-up
    samples = [_measure(fn) for _ in range(repeats)]
    python_peak = _python_peak_alloc_mib(fn)
    latencies = [s.elapsed_ms for s in samples]
    cpu_times = [s.process_cpu_ms for s in samples]
    p50 = statistics.median(latencies)
    p95 = _percentile(latencies, 0.95)
    cpu_p50 = statistics.median(cpu_times)
    cpu_p95 = _percentile(cpu_times, 0.95)
    signatures = {s.signature for s in samples}
    counts = {s.result_count for s in samples}
    rss = max(s.process_high_water_rss_mib for s in samples)
    throughput = (len(data) / 1024) / max(p50 / 1000.0, 0.001)
    cpu_pct = (cpu_p50 / max(p50, 0.001)) * 100.0
    passed = (
        len(signatures) == 1
        and len(counts) == 1
        and p95 < 120_000
        and rss < 4096
        and math.isfinite(cpu_p95)
        and math.isfinite(python_peak)
    )
    return BenchmarkCase(
        name=name,
        stage=stage,
        format=file_type.value,
        input_bytes=len(data),
        repeats=repeats,
        p50_ms=round(p50, 3),
        p95_ms=round(p95, 3),
        max_ms=round(max(latencies), 3),
        p50_process_cpu_ms=round(cpu_p50, 3),
        p95_process_cpu_ms=round(cpu_p95, 3),
        cpu_core_equivalent_pct_p50=round(cpu_pct, 2),
        throughput_kib_s_p50=round(throughput, 2),
        python_peak_alloc_mib=round(python_peak, 2),
        process_high_water_rss_mib=round(rss, 2),
        result_count=samples[0].result_count,
        deterministic=len(signatures) == 1 and len(counts) == 1,
        passed=passed,
    )


def _detector_concurrency_probe() -> dict:
    data = _text_payload(4 * 1024)
    _, expected = _full_detection(data, FileType.TEXT, "concurrency.txt")
    started = time.perf_counter()
    cpu_started = time.process_time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_full_detection, data, FileType.TEXT, f"concurrency-{i}.txt") for i in range(4)]
        results = [future.result(timeout=120) for future in futures]
    elapsed = (time.perf_counter() - started) * 1000.0
    cpu_ms = (time.process_time() - cpu_started) * 1000.0
    signatures = [signature for _, signature in results]
    counts = [count for count, _ in results]
    return {
        "workers": 4,
        "completed": len(results),
        "elapsed_ms": round(elapsed, 3),
        "process_cpu_ms": round(cpu_ms, 3),
        "signatures_identical": all(value == expected for value in signatures),
        "mentions_each": counts,
        "passed": len(results) == 4 and all(value == expected for value in signatures),
    }


def _api_job_concurrency_probe() -> dict:
    """Exercise real API -> DB -> encrypted workspace -> analysis job isolation concurrently.

    The probe switches the global DB/workspace to a temporary sandbox and restores them
    afterward. It never touches the user's normal VeilGraph jobs or encrypted workspaces.
    """
    from main import app

    previous_db_path = db.path
    previous_workspace_root = settings.workspace_root
    started = time.perf_counter()
    cpu_started = time.process_time()
    details: list[dict] = []
    error: str | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="veilgraph-phase2-concurrent-jobs-") as tmp:
            temp_root = Path(tmp)
            db.path = temp_root / "phase2-concurrency.db"
            settings.workspace_root = temp_root / "jobs"
            settings.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            db.init_schema()

            def worker(index: int) -> dict:
                client = TestClient(app)
                try:
                    created = client.post(
                        "/api/v1/jobs",
                        json={
                            "purpose": f"Phase2 concurrency probe {index}",
                            "recipient": "NTRO benchmark fixture",
                            "audience_profile": "PUBLIC_RELEASE",
                            "privacy_level": 3,
                            "retention_seconds": 3600,
                        },
                    )
                    if created.status_code != 201:
                        return {"index": index, "passed": False, "stage": "create", "status": created.status_code}
                    job_id = created.json()["id"]
                    unique_email = f"phase2.worker{index}@example.org"
                    data = (
                        f"Fictional concurrent record {index}\n"
                        f"Name: Worker Testperson {index}\n"
                        f"Email: {unique_email}\n"
                        f"Phone: +91 90000 {10000 + index}\n"
                        f"City: Bengaluru\n"
                    ).encode("utf-8")
                    uploaded = client.post(
                        f"/api/v1/jobs/{job_id}/files",
                        files={"file": (f"worker-{index}.txt", data, "text/plain")},
                    )
                    if uploaded.status_code != 201:
                        return {"index": index, "job_id": job_id, "passed": False, "stage": "upload", "status": uploaded.status_code}
                    file_id = uploaded.json()["id"]
                    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
                    if analysed.status_code != 200:
                        return {"index": index, "job_id": job_id, "file_id": file_id, "passed": False, "stage": "analyse", "status": analysed.status_code}
                    body = analysed.json()
                    file_row = db.fetchone("SELECT job_id, original_filename FROM files WHERE id=?", (file_id,))
                    entity_rows = db.fetchall("SELECT DISTINCT job_id, file_id FROM canonical_entities WHERE file_id=?", (file_id,))
                    isolated = (
                        file_row is not None
                        and file_row.get("job_id") == job_id
                        and file_row.get("original_filename") == f"worker-{index}.txt"
                        and all(row.get("job_id") == job_id and row.get("file_id") == file_id for row in entity_rows)
                    )
                    return {
                        "index": index,
                        "job_id": job_id,
                        "file_id": file_id,
                        "mentions": int(body.get("mentions", 0)),
                        "canonical_entities": int(body.get("canonical_entities", 0)),
                        "isolated": isolated,
                        "passed": isolated and int(body.get("mentions", 0)) > 0,
                    }
                finally:
                    client.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(worker, index) for index in range(4)]
                details = [future.result(timeout=180) for future in futures]
    except Exception as exc:  # fail-closed evidence rather than crashing without a report
        error = f"{type(exc).__name__}: {exc}"
    finally:
        db.path = previous_db_path
        settings.workspace_root = previous_workspace_root

    elapsed = (time.perf_counter() - started) * 1000.0
    cpu_ms = (time.process_time() - cpu_started) * 1000.0
    job_ids = [item.get("job_id") for item in details if item.get("job_id")]
    file_ids = [item.get("file_id") for item in details if item.get("file_id")]
    passed = (
        error is None
        and len(details) == 4
        and len(job_ids) == len(set(job_ids)) == 4
        and len(file_ids) == len(set(file_ids)) == 4
        and all(item.get("passed") is True for item in details)
    )
    return {
        "workers": 4,
        "completed": len(details),
        "elapsed_ms": round(elapsed, 3),
        "process_cpu_ms": round(cpu_ms, 3),
        "unique_jobs": len(set(job_ids)),
        "unique_files": len(set(file_ids)),
        "job_isolation_valid": all(item.get("isolated") is True for item in details) if details else False,
        "details": details,
        "error": error,
        "passed": passed,
    }


def main() -> int:
    text_1k = _text_payload(1024)
    text_8k = _text_payload(8 * 1024)
    text_24k = _text_payload(24 * 1024)
    text_64k = _text_payload(64 * 1024)
    text_8m = _text_payload(8 * 1024 * 1024)
    csv_1000 = _csv_payload(1000)
    csv_5000 = _csv_payload(5000)
    pdf_5 = _pdf_payload(5)

    cases = [
        run_case("full_detection_text_1k", "full_detection", FileType.TEXT, "bench.txt", text_1k, 4,
                 lambda: _full_detection(text_1k, FileType.TEXT, "bench.txt")),
        run_case("full_detection_text_8k", "full_detection", FileType.TEXT, "bench.txt", text_8k, 3,
                 lambda: _full_detection(text_8k, FileType.TEXT, "bench.txt")),
        run_case("full_detection_text_24k", "full_detection", FileType.TEXT, "bench.txt", text_24k, 2,
                 lambda: _full_detection(text_24k, FileType.TEXT, "bench.txt")),
        run_case("full_detection_text_64k", "full_detection", FileType.TEXT, "bench.txt", text_64k, 2,
                 lambda: _full_detection(text_64k, FileType.TEXT, "bench.txt")),
        run_case("validation_text_8mb", "ingestion_validation", FileType.TEXT, "bench.txt", text_8m, 2,
                 lambda: _validation_only(text_8m, "bench.txt")),
        run_case("structured_extraction_1000_rows", "extraction", FileType.DATASET, "bench.csv", csv_1000, 3,
                 lambda: _extraction_only(csv_1000, FileType.DATASET, "bench.csv")),
        run_case("structured_extraction_5000_rows", "extraction", FileType.DATASET, "bench.csv", csv_5000, 2,
                 lambda: _extraction_only(csv_5000, FileType.DATASET, "bench.csv")),
        run_case("pdf_extraction_5_pages", "extraction", FileType.PDF, "bench.pdf", pdf_5, 2,
                 lambda: _extraction_only(pdf_5, FileType.PDF, "bench.pdf")),
    ]
    detector_concurrency = _detector_concurrency_probe()
    api_job_concurrency = _api_job_concurrency_probe()
    payload = {
        "schema": "veilgraph.phase2-benchmark.v2",
        "product_version": settings.version,
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "method": {
            "warmup": True,
            "latency": "steady-state wall-clock milliseconds; Python allocation tracing is measured separately",
            "cpu": "process CPU milliseconds from time.process_time; core-equivalent percentage may exceed 100% under parallel native work",
            "python_memory": "per-case Python-tracked peak allocations from tracemalloc; excludes native-library allocations",
            "process_memory": "process lifetime high-water RSS from getrusage; explicitly not claimed as per-case resident memory",
            "external_model_calls": False,
            "large_input_note": "8 MiB ingestion, 5,000-row structured extraction, 5-page PDF extraction and 64 KiB full detector scaling are measured within SIH-bounded execution; configured hard limits remain separately regression-tested.",
            "concurrency_note": "Both pure detector concurrency and isolated concurrent API jobs through DB/encrypted-workspace/analysis paths are exercised.",
            "completion_gate_note": "p50/p95/CPU/memory are evidence, not endless optimization targets; hangs, nondeterminism, isolation failure or resource blow-up fail the functional gate.",
        },
        "cases": [asdict(case) for case in cases],
        "detector_concurrency": detector_concurrency,
        "api_job_concurrency": api_job_concurrency,
        "process_high_water_rss_mib": round(_rss_mib(), 2),
        "all_cases_passed": all(case.passed for case in cases),
        "all_passed": (
            all(case.passed for case in cases)
            and bool(detector_concurrency["passed"])
            and bool(api_job_concurrency["passed"])
        ),
    }
    out = ROOT / "competition/phase2/PHASE2_BENCHMARK_RESULTS.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = ROOT / "competition/phase2/PHASE2_BENCHMARK_REPORT.md"
    rows = [
        "# VeilGraph Phase 2 Performance & Scale Benchmark",
        "",
        f"Status: **{'PASS' if payload['all_passed'] else 'FAIL'}**",
        "",
        "| Case | Stage | Input bytes | p50 ms | p95 ms | CPU p50 ms | CPU core-equiv % | KiB/s p50 | Python peak MiB | Process high-water RSS MiB | Deterministic |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for c in cases:
        rows.append(
            f"| {c.name} | {c.stage} | {c.input_bytes} | {c.p50_ms} | {c.p95_ms} | {c.p50_process_cpu_ms} | "
            f"{c.cpu_core_equivalent_pct_p50} | {c.throughput_kib_s_p50} | {c.python_peak_alloc_mib} | "
            f"{c.process_high_water_rss_mib} | {c.deterministic} |"
        )
    rows += [
        "",
        f"Detector concurrency: {detector_concurrency['completed']}/{detector_concurrency['workers']} completed; deterministic={detector_concurrency['signatures_identical']}; elapsed={detector_concurrency['elapsed_ms']} ms.",
        f"Integrated API-job concurrency: {api_job_concurrency['completed']}/{api_job_concurrency['workers']} completed; unique jobs={api_job_concurrency['unique_jobs']}; isolation={api_job_concurrency['job_isolation_valid']}; elapsed={api_job_concurrency['elapsed_ms']} ms.",
        "",
        f"Process lifetime high-water RSS after benchmark: {payload['process_high_water_rss_mib']} MiB.",
        "",
        "Memory claim boundary: `python_peak_alloc_mib` is per-case Python allocator evidence; `process_high_water_rss_mib` is a process-lifetime high-water mark and is not described as per-case resident memory.",
        "",
        "These figures are measurements from the executing machine, not universal performance guarantees.",
    ]
    report.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"Wrote {out}")
    print(f"Wrote {report}")
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
