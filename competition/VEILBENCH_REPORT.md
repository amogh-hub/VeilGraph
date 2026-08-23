# VeilBench v1.0 — Accuracy, Performance & Release Evidence

Generated: 2026-08-09T08:19:39.791769+00:00

VeilBench separates **detection accuracy** from **release-safety verification**. A 12/12 Red Team result is not presented as Precision/Recall/F1, and a high F1 score is not presented as an anonymity guarantee.

## A. Bundled curated accuracy corpus

- Cases: **32**
- Gold spans: **85**
- Precision: **100.00%**
- Recall: **100.00%**
- F1: **100.00%**
- Macro F1: **100.00%**
- Exact case passes: **32/32**
- Median detector latency: **1.389 ms/case**
- P95 detector latency: **2.036 ms/case**
- Throughput: **646.526 cases/s**
- Peak process RSS: **136.156 MB**

| Entity | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| AADHAAR_LIKE | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| AGE | 5 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| CASE_REFERENCE | 7 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| DATE_OF_BIRTH | 5 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| EMAIL | 9 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| EMPLOYER | 6 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| JOB_TITLE | 4 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| LOCALITY | 6 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| PAN_LIKE | 3 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| PERSON_NAME | 18 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| PHONE | 10 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| POSTCODE | 5 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| STREET_ADDRESS | 5 | 0 | 0 | 100.00% | 100.00% | 100.00% |

## B. Standardized open-source masking benchmark (PIIMB)

- Rows scored: **18538**
- Characters scored: **1774805**
- Precision: **93.40%**
- Recall: **64.45%**
- F1: **76.27%**
- F2: **68.71%**
- Character FPR: **1.30%**
- Median latency: **0.978 ms/sentence**

## D. End-to-end release-safety evidence

Overall: **PASS** · 2/2 cases passed
Mandatory attack pass rate: **100.0%**

### Digital identity reconstruction dossier · Level 4

- Result: **PASS**
- Duration: 4218.5 ms
- Entities / mentions: 15 / 17
- Graph: 16 nodes / 34 edges
- Exposure: 100 → 37
- Utility retained: 66
- Privacy Red Team: 12/12 PASS · Proof 100/100
- Certificate signature valid: True

### Scanned multimodal dossier · Level 1

- Result: **PASS**
- Duration: 7800.9 ms
- Entities / mentions: 10 / 11
- Graph: 10 nodes / 17 edges
- Exposure: 50 → 13
- Utility retained: 69
- Privacy Red Team: 12/12 PASS · Proof 100/100
- Certificate signature valid: True

## Claim boundaries

- Precision/Recall/F1 apply only to the explicitly named and sampled benchmark corpus.
- Unmapped third-party entity classes are disclosed rather than silently scored as negatives.
- Release-safety tests demonstrate the implemented attacks and fixtures; they do not constitute a legal or mathematical guarantee of anonymity.
- Process RSS is a process-wide maximum and includes imported/native dependencies.
