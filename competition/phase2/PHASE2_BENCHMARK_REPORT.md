# VeilGraph Phase 2 Performance & Scale Benchmark

Status: **PASS**

| Case | Stage | Input bytes | p50 ms | p95 ms | CPU p50 ms | CPU core-equiv % | KiB/s p50 | Python peak MiB | Process high-water RSS MiB | Deterministic |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| full_detection_text_1k | full_detection | 1024 | 44.932 | 45.345 | 44.928 | 99.99 | 22.26 | 0.08 | 144.94 | True |
| full_detection_text_8k | full_detection | 8192 | 430.883 | 431.679 | 430.879 | 100.0 | 18.57 | 0.61 | 145.95 | True |
| full_detection_text_24k | full_detection | 24576 | 1338.624 | 1339.915 | 1338.62 | 100.0 | 17.93 | 1.99 | 166.09 | True |
| full_detection_text_64k | full_detection | 65536 | 3726.502 | 3746.544 | 3726.496 | 100.0 | 17.17 | 5.74 | 216.72 | True |
| validation_text_8mb | ingestion_validation | 8388608 | 274.534 | 276.819 | 274.533 | 100.0 | 29839.61 | 8.0 | 221.98 | True |
| structured_extraction_1000_rows | extraction | 77819 | 42.596 | 42.683 | 42.595 | 100.0 | 1784.07 | 6.75 | 224.12 | True |
| structured_extraction_5000_rows | extraction | 397819 | 266.278 | 268.944 | 266.274 | 100.0 | 1458.98 | 35.13 | 256.16 | True |
| pdf_extraction_5_pages | extraction | 18635 | 382.797 | 385.193 | 382.789 | 100.0 | 47.54 | 0.43 | 327.03 | True |

Detector concurrency: 4/4 completed; deterministic=True; elapsed=824.106 ms.
Integrated API-job concurrency: 4/4 completed; unique jobs=4; isolation=True; elapsed=108.725 ms.

Process lifetime high-water RSS after benchmark: 349.28 MiB.

Memory claim boundary: `python_peak_alloc_mib` is per-case Python allocator evidence; `process_high_water_rss_mib` is a process-lifetime high-water mark and is not described as per-case resident memory.

These figures are measurements from the executing machine, not universal performance guarantees.
