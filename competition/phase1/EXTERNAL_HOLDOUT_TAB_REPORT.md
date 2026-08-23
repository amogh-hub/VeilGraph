# VeilGraph External Holdout — TAB

## Scientific status

- Broad PII v4 was cryptographically frozen before TAB acquisition/evaluation.
- The earlier SPIA attempt failed during remote acquisition, before any holdout records were evaluated.
- TAB was selected only as a transport-access replacement; no TAB score was known at selection time.
- Raw TAB text is not copied into the VeilGraph repository.
- Detector/model/training files must not be changed in response to this score.

## Source provenance

- Repository: `NorskRegnesentral/text-anonymization-benchmark`
- Commit: `558e09e26d6b36f5f78440074e6a233946d98bd9`
- File: `echr_test.json`
- Source SHA-256: `cd0f0f15f84a8739654c7cf30c6be8ce27b051ef73974d39d792a0cb8c846379`
- Documents: 127

## VeilGraph cross-benchmark metrics

- Strict span-value precision: **0.2843**
- Strict span-value recall: **0.3874**
- Strict span-value F1: **0.3279**
- Strict span-value F2: **0.3612**
- Direct-identifier recall: **0.0360**
- Quasi-identifier recall: **0.4169**
- TAB NO_MASK hit rate: **0.1084**

> These are VeilGraph cross-benchmark exact normalized span-value metrics, not the official TAB leaderboard metrics. TAB's target-person masking policy and VeilGraph's broader release policy differ, so the NO_MASK hit rate is reported separately rather than mislabeled as a conventional FPR.

## Per TAB semantic category recall

| TAB category | TP | FN | Recall |
|---|---:|---:|---:|
| CODE | 0 | 1612 | 0.0000 |
| DATETIME | 6872 | 2664 | 0.7206 |
| DEM | 28 | 889 | 0.0305 |
| LOC | 837 | 622 | 0.5737 |
| MISC | 7 | 530 | 0.0130 |
| ORG | 127 | 1819 | 0.0653 |
| PERSON | 189 | 3949 | 0.0457 |
| QUANTITY | 1 | 663 | 0.0015 |

## Interpretation rule

This is a one-shot external generalization measurement for frozen Broad PII v4. If the score exposes weaknesses, keep the result and address them only in a future detector version developed on separate data, followed by a new untouched holdout.
