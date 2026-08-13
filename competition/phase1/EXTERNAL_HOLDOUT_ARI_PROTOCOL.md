# Broad PII v5 Final External Holdout Protocol

## Dataset identity

- Repository: `Ari-S-123/pii-detection-english-consolidated`
- Frozen repository revision: `61e7c4fcd6c569d4cc89db9cba79deab833df085`
- Split: `test`
- Filter: `data_source == synthetic`
- Expected full test rows: 31,361
- Expected synthetic test rows: 1,201
- Test Parquet Git-LFS SHA-256: `768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471`
- License: MIT

The dataset card states that the corpus combines an ai4privacy component with separately generated challenging synthetic examples and reserves 1,201 of the synthetic examples for test. VeilGraph excludes the ai4privacy portion from this final v5 holdout because ai4privacy-family data was used in earlier detector work.

## Why this is a holdout

Before the first synthetic test row is requested:

1. Broad PII v5 code/model/training files are hash-frozen.
2. The label mapping below is fixed.
3. Acceptance thresholds below are fixed.
4. The test split is not used for training, tuning or rule selection.

The public dataset card/schema and repository metadata may be used to define the protocol; test records themselves may not be inspected before the freeze.

## Shared taxonomy

Primary scoring only covers labels with a predeclared VeilGraph equivalent. Examples include FIRSTNAME/LASTNAME, EMAIL, PHONENUMBER, driver licence, passport, tax/social/national ID, payment card, DOB/date, age, title, street, city, postcode and building number.

Any external label without a predeclared VeilGraph class is counted and disclosed under `excluded_gold_label_counts`; it is not silently forced into an unrelated class.

## Metrics

Two cross-taxonomy views are reported:

- **Exact**: compatible entity family and exact source offsets.
- **Relaxed compatible-span coverage**: compatible entity family plus meaningful source-span overlap. This handles granularity differences such as an external FIRSTNAME/LASTNAME pair versus one VeilGraph PERSON_NAME span.

Also reported:

- critical shared recall,
- contextual shared recall,
- per-label recall,
- per-challenge-dimension recall,
- no-shared-PII document false-positive rate when applicable,
- excluded/non-shared label counts.

## Predeclared acceptance thresholds

These are inherited unchanged from the v5 freeze plan that existed before the final holdout source was acquired:

- exact F1 >= 0.50
- relaxed compatible-span F1 >= 0.65
- critical shared recall >= 0.75
- contextual shared recall >= 0.55
- no-shared-PII document FP rate <= 0.20 when negative documents exist

A failed threshold is a failed holdout gate. The result must not be hidden or tuned against and rerun as if untouched.

## Acquisition

`scripts/run_external_holdout_ari.py`:

1. verifies Broad PII v5 freeze,
2. verifies repository HEAD equals the pinned revision,
3. queries only synthetic TEST rows via the Hugging Face Dataset Viewer `/filter` endpoint,
4. requires exactly 1,201 records,
5. hashes the canonical row stream,
6. evaluates frozen v5,
7. deletes raw row objects before report persistence,
8. verifies the v5 freeze again,
9. writes aggregate JSON/Markdown evidence only.

If acquisition fails, the detector remains frozen and the same command is retried. Network failure is not an evaluation result.
