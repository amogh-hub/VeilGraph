# VeilGraph Evaluation

This document summarizes the evidence present in the frozen SIH260381 repository. Measurements are tied to named datasets, fixtures and machines; they are not universal accuracy/performance guarantees.

## Final canonical regression

`competition/final/FINAL_FULL_REGRESSION.json`

- backend pytest: **268 passed, 0 failed**;
- warnings: 5 non-blocking SWIG/PyMuPDF-related deprecation warnings on the target environment;
- OpenAPI generated successfully;
- TypeScript typecheck passed;
- Vite production build passed.

## Final defect-closure fixtures

`competition/final/FINAL_REAL_FIXTURE_ACCEPTANCE.json`

| Fixture | Format | Mandatory gates | Proof score | Critical blockers | Decision |
|---|---|---:|---:|---:|---|
| `01_case_brief.txt` | TXT | 12/12 | 100/100 | 0 | `VERIFIED_SAFE` / `ALLOW_RELEASE` |
| `04_case_packet.pdf` | digital PDF | 12/12 | 100/100 | 0 | `VERIFIED_SAFE` / `ALLOW_RELEASE` |
| `05_scanned_application.pdf` | scanned PDF | 12/12 | 100/100 | 0 | `VERIFIED_SAFE` / `ALLOW_RELEASE` |

These are specifically the three fixtures that exposed late native-text/digital-PDF/scanned-PDF defects and were re-run after hardening.

## L1–L5 gradation calibration

`competition/phase3/GRADATION_CALIBRATION_REPORT.md`

| Level | Intervention coverage | Context coverage | Exposure | Utility | Red Team |
|---:|---:|---:|---:|---:|---:|
| L1 | 44% | 0% | 95 → 86 | 45% | 12/12 |
| L2 | 67% | 40% | 95 → 85 | 45% | 12/12 |
| L3 | 100% | 100% | 95 → 86 | 45% | 12/12 |
| L4 | 100% | 100% | 95 → 78 | 45% | 12/12 |
| L5 | 100% | 100% | 95 → 1 | 88% | 15/15 |

Acceptance: every level executed, every release gate passed, intervention/context coverage was non-decreasing, and L5 passed the source-independence criteria.

Residual Exposure is a calibrated product indicator and is not forced to be mathematically monotonic between adjacent policies.

## Commercial/off-the-shelf comparison

`competition/phase3/COTS_QUANTITATIVE_RESULTS.json`

Protocol: **100 identical PIIMB rows**, character-level label-agnostic PII coverage.

| System | Precision | Recall | F1 | F2 | FPR | p95 ms/row |
|---|---:|---:|---:|---:|---:|---:|
| **VeilGraph** | 0.9189 | 0.7672 | **0.8362** | 0.7934 | 0.0149 | 8.87 |
| Microsoft Presidio | 0.6626 | 0.6879 | 0.6750 | 0.6827 | 0.0771 | 13.24 |
| Azure AI Language PII | 0.7639 | 0.7215 | 0.7421 | 0.7296 | 0.0490 | 144.23 |
| AWS Comprehend PII | not executed | — | — | — | — | — |

AWS was not substituted with marketing numbers. The repository records it as `NOT_EXECUTED` because the benchmark environment lacked the required AWS region configuration. The literal NTRO commercial-COTS requirement was closed by the actually executed Azure comparison.

The Azure adapter is benchmark-only. VeilGraph operational privacy processing has no mandatory Azure dependency.

## Frozen external Nemotron holdout

`competition/HOLDOUT_NEMOTRON_REPORT.md`

- rows: **77,907**;
- characters: **4,737,260**;
- Precision: **85.52%**;
- Recall: **32.81%**;
- F1: **47.43%**;
- F2: **37.42%**;
- character FPR: **0.84%**;
- median latency: **0.662 ms/sentence**;
- p95 latency: **1.605 ms/sentence**;
- throughput: **1205.041 sentences/s**.

This result is deliberately not hidden despite weak recall. The detector was frozen before this task was evaluated, and the result is evidence only: **it must not be used to tune the frozen detector**.

## Phase-2 performance / scale

`competition/phase2/PHASE2_BENCHMARK_REPORT.md`

Final target-machine evidence included:

- deterministic full detection from 1 KiB through 64 KiB text;
- 8 MiB ingestion validation;
- structured extraction at 1,000 and 5,000 rows;
- 5-page PDF extraction;
- 4-worker detector concurrency with identical signatures;
- 4 concurrent API jobs with unique jobs/files and verified isolation.

Representative target-machine measurements:

| Case | p50 | p95 |
|---|---:|---:|
| 1 KiB full text detection | 44.932 ms | 45.345 ms |
| 8 KiB full text detection | 430.883 ms | 431.679 ms |
| 64 KiB full text detection | 3726.502 ms | 3746.544 ms |
| 8 MiB ingestion validation | 274.534 ms | 276.819 ms |
| 5,000-row structured extraction | 266.278 ms | 268.944 ms |
| 5-page PDF extraction | 382.797 ms | 385.193 ms |

These numbers are measurements from one executing machine, not universal latency promises.

## Security acceptance

`competition/phase2/PHASE2_SECURITY_RESULTS.json`

**9/9 passed**, covering secure-online bearer authentication, HTTPS/trusted-proxy behavior, offline egress guard, SQLite integrity, workspace permissions, proof ZIP path traversal rejection, secret exclusion and exact release-member enforcement.

## Scientific claim boundary

No benchmark here establishes universal anonymity. Accuracy depends on language/domain/format and the implemented detector classes. The release protocol reduces risk through multiple independent channels, human review and fail-closed verification; it does not eliminate the possibility of every unknown future linkage attack.
