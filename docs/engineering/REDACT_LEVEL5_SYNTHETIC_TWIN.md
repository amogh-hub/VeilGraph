# VeilGraph Level 5 — Synthetic Twin v1

## Scope

Level 5 is a real fifth privacy gradation for structured **CSV, JSON and XLSX** data. It does not pretend that replacing a few names in a PDF is synthetic-data generation. Non-dataset Level 5 requests fail closed with an explicit 422 response until document-level synthesis is implemented.

The Level 5 pipeline is fully local. It learns the schema and utility-bearing statistical structure of the current dataset in memory, generates a new synthetic population, verifies the result and releases it only after the Level 5 Privacy Red Team passes.

## What it preserves

- table / JSON structural schema and record count;
- low-cardinality category distribution shape;
- numeric means and dispersion;
- numeric cross-column correlation structure;
- parseable date ordering and time sequence;
- logical scalar types and output format;
- analytical usefulness measured by a transparent product utility score.

## What it deliberately breaks

- source person/contact/credential values;
- exact source records;
- source identity-to-record linkage;
- source identity-to-generated-identity stability across releases;
- unique source combinations that would make a record traceable.

Population attributes such as age, locality or gender may legitimately recur because a useful synthetic population must preserve distributions. The exact-source absence gate therefore targets identity and unique-marker classes rather than incorrectly treating every recurring population value as a leak.

## Generator design

1. Parse the input with VeilGraph's hardened structured-data layer.
2. Bind approved sensitive mentions to exact structured scalar locations.
3. Learn in-memory column profiles: type, cardinality, numeric spread, correlations and date structure.
4. Create a job-randomized synthetic release seed. Only its commitment is reported; identical source data does not deterministically produce the same production release.
5. Regenerate identity-bearing values using local synthetic vocabularies and explicit non-live credential formats.
6. Use shared deranged donor ordering plus bounded perturbation for numerical variables to preserve cross-column structure without copying records.
7. Preserve low-cardinality marginal distributions while privacy-safe categories may be renamed.
8. Shift date-like columns coherently so order and intervals remain useful without retaining exact source dates.
9. Re-export through the existing clean CSV / JSON / XLSX serializers.
10. Compute utility/privacy evidence and run the Level 5 release gates.

The pure engine supports deterministic test execution when no release salt is supplied. Production API transformations always provide a cryptographically random release salt to prevent cross-release linkability.

## Measured evidence emitted per release

The manifest and API expose `synthetic_twin` evidence including:

- `schema_preserved`;
- original and synthetic record counts;
- exact source row copies / copy rate;
- exact source identity reuse / reuse rate;
- numeric mean fidelity;
- numeric standard-deviation fidelity;
- numeric correlation fidelity;
- categorical distribution fidelity;
- time-order fidelity;
- utility score;
- privacy score;
- source hash, output hash and seed commitment;
- release-randomization flag.

These are reproducible product indicators for the generated output. They are **not** a differential-privacy guarantee, a legal anonymity guarantee, or a claim that every future external linkage attack is impossible.

## Level 5 fail-closed verification

Structured Level 5 outputs use 15 mandatory gates:

1. source-identity absence;
2. independent structured extraction;
3. secondary structured parser rescan;
4. hidden structured-channel scan;
5. structured scalar replacement integrity;
6. metadata / embedded-content inspection;
7. policy coverage;
8. Level 5 relationship-linkability rule;
9. raw object/byte scan;
10. direct-identifier fragment attack;
11. manifest replacement presence;
12. schema preservation;
13. source-record copy attack;
14. synthetic utility/privacy evidence gate;
15. output commitment verification.

Any FAIL or INCONCLUSIVE result keeps the artifact `RELEASE_BLOCKED`.

## Bundled fictional demo

Upload:

```text
backend/test_synthetic_twin_dataset.csv
```

Select **Level 5 · Synthetic Twin**. The bundled source is fictional and contains names, emails, phones, age, locality, cohort, numeric analytical variables, visit dates and treatment groups.

On the build-time Linux validation run, this fixture produced zero exact source-row copies, zero exact source identity reuse, full date-order preservation and passed all 15 Level 5 gates. Exact utility/correlation values are release-specific because production releases are randomized; use the UI's measured values rather than quoting a hard-coded score.

## Validation matrix

Run:

```bash
./scripts/run_level5_synthetic_matrix.sh
```

The matrix covers:

- real Level 5 policy semantics;
- deterministic test-mode synthesis;
- release-salt anti-linkability;
- CSV end-to-end generation + 15-gate proof + signed certificate;
- explicit rejection of non-dataset fake synthesis;
- nested JSON Level 5 generation;
- XLSX Level 5 generation and sheet/schema preservation.

## Holdout integrity

The earlier `nemotron-pii` frozen-detector result remains historical post-freeze evidence. Level 5 does not edit any `backend/app/detection/*` file or the frozen semantic model. The original broad full-source holdout runner intentionally remains locked to the historical pre-Level-5 snapshot; it should not be re-run and presented as another untouched holdout after product evolution.
