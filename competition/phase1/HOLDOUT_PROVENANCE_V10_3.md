# VeilGraph Phase 1 Holdout Provenance v10.3

## Purpose

The v10.1 holdout runner froze the correct external **data artifact** but also required the dataset repository's `main` branch HEAD to remain equal to the original data commit. That is unnecessarily strict: repository metadata can advance without changing the test data.

v10.3 changes the provenance gate to the scientifically relevant invariant:

- Broad PII v5 must be frozen before acquisition.
- The test Parquet artifact is pinned by SHA-256:
  `768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471`.
- The current repository HEAD may differ from the original data commit only if the exact test Parquet bytes still hash to that frozen value.
- The evaluator still requires exactly 1,201 `data_source == synthetic` TEST rows.
- The canonical Dataset Viewer row stream is hashed and persisted as provenance.
- Raw rows are not persisted in the VeilGraph repository.
- Broad PII v5 is re-verified after evaluation.
- If the test Parquet bytes differ, evaluation fails closed.

This patch does not change Broad PII v5, Semantic NER v3, models, training data, thresholds, taxonomy mapping, or the acceptance criteria.
