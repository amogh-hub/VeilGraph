# RE-DACT Requirement Progress — VeilBench v1.0

## Requirement

The NTRO RE-DACT problem statement explicitly requests **Precision, Recall and F1 Score on an open-source testing dataset** and evaluates speed and optimized computing usage.

## Implemented in this patch

- Real TP / FP / FN accounting on a bundled labelled fictional corpus.
- Per-entity Precision / Recall / F1.
- Micro and macro F1.
- Explicit false-positive and false-negative rates for entity extraction.
- Detector latency, throughput, CPU time and process peak RSS.
- Standardized PIIMB character-level masking evaluator:
  - Precision
  - Recall
  - F1
  - F2
  - FPR over non-PII characters
- Negative examples are scored rather than discarded.
- External dataset provenance is kept separate from internal curated data.
- Optional Ai4Privacy OpenPII JSONL adapter with unmapped-label disclosure.
- Accuracy evidence remains separate from the existing 12-attack release-safety proof.

## Important status boundary

**The open-source testing-dataset requirement is not marked complete merely by installing this code.**
It becomes complete only after an external benchmark dataset is run and measured results are written into `competition/veilbench-results.json` and `competition/VEILBENCH_REPORT.md`.

This prevents VeilGraph from claiming benchmark results that were never actually measured.
