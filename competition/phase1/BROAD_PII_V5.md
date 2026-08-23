# Broad PII v5 — Generalization Hardening

## Purpose

Broad PII v5 is the Phase-1 detector generation created after the frozen Broad PII v4 external TAB evaluation exposed a large development-to-external generalization gap. v4 and its TAB result remain immutable historical evidence; v5 is a new generation rather than a rewrite of that evidence.

## Architecture

Broad PII v5 is a local hybrid detector:

1. deterministic direct identifiers and validators,
2. Broad PII international/context rules,
3. v4 field/schema context,
4. v5 generalization rules for labelled and long-form prose,
5. Semantic NER v3, a bundled local logistic contextual-span classifier,
6. candidate fusion using canonical source offsets plus evidence geometry,
7. existing human review, Identity Exposure Graph, transformation, Privacy Red Team and fail-closed release controls.

ML proposes semantic spans. It does not authorize release. Encryption, signatures, Red Team gate aggregation and `ALLOW_RELEASE` remain deterministic.

## v5 changes

- Stronger person recognition in honorific, legal/appositive, role, self-introduction, sign-off and labelled-field contexts.
- Better employer, locality, job-title and address context coverage.
- International context-anchored passport, driving-licence, tax, social/national ID, policy/account/reference and postal-code coverage.
- Ordinal and month-first birth-date support.
- Source-offset-aware fusion prevents visually colliding long-line boxes from suppressing unrelated sensitive spans.
- Postal-code structural logic no longer treats unrelated dates/numbers elsewhere on a labelled line as postcodes.
- Frozen DOCX, VIDEO and structured-dataset adapters remain authoritative; v5 free-text semantic inference does not run over those adapter domains.

## Semantic NER v3

- Version: `3.0.0`
- Model family: local logistic-regression contextual span classifier
- Training examples: 2,330
- Training corpus: fully synthetic; `contains_real_pii=false`
- Runtime network required: `false`
- Model and corpus are bundled and hash-bound in the v5 freeze manifest.

## Development evidence

The Judge Showcase and Judge Chaos datasets are development/regression datasets, not external holdouts. Current container results before the final external holdout:

- Showcase: P 0.9974 / R 1.0000 / F1 0.9987 / F2 0.9995 / FPR 0.0000 / evidence 0.9731
- Chaos: P 0.9612 / R 0.9340 / F1 0.9474 / F2 0.9393 / FPR 0.0000 / evidence 0.8611

The user's Mac run remains authoritative for competition evidence.

## External-evaluation integrity

Consumed prior holdouts are never reused as untouched v5 evidence:

- Nemotron: consumed by v3.
- TAB ECHR test: consumed by v4 and preserved with the historical v4 snapshot.

The final v5 holdout is a new held-out test split declared in `EXTERNAL_HOLDOUT_ARI_PROTOCOL.md`. Thresholds and taxonomy mapping are fixed before any final test row is requested.
