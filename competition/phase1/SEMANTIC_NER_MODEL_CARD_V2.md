# VeilGraph Semantic NER v2 — Model Card

## Purpose

Semantic NER v2 is the learned component of Broad PII v4. It complements deterministic validators for emails, phones, credentials and schema-labelled identifiers by scoring locally generated contextual span candidates for **PERSON_NAME, EMPLOYER, LOCALITY, STREET_ADDRESS and JOB_TITLE**.

It is not a release authority. Privacy Red Team verification, download gating, cryptographic proof and workspace destruction remain deterministic.

## Model

- Schema: `veilgraph.semantic-ner.linear.v2`
- Version: `2.0.0`
- Family: local logistic-regression span classifier
- Inference runtime: pure Python sigmoid over committed coefficients
- Network required at runtime: **no**
- External model/API calls: **none**
- Classes: PERSON_NAME, EMPLOYER, LOCALITY, STREET_ADDRESS, JOB_TITLE
- Candidate generation: local linguistic/context patterns followed by learned accept/reject scoring

## Training data

The committed corpus is `backend/training_data/semantic_ner_train_v2.json` and contains **97 fictional candidate examples**. It is separate from the untouched external holdout used after v4 freeze. The corpus declares that it contains no real personal data.

The model JSON embeds the SHA-256 of the exact training corpus. The regeneration script is `scripts/train_semantic_ner_v2.py`. scikit-learn and NumPy are development-only trainer dependencies and are deliberately not production runtime requirements.

## Hybrid design

Broad PII v4 does not replace strong deterministic checks with ML. It fuses:

1. deterministic direct-identifier validators;
2. schema/context-aware v4 detection;
3. local Semantic NER v2;
4. existing quasi-identifier and visual detection;
5. human review for uncertain/high-impact candidates.

This keeps exact formats such as email, phone and credential patterns deterministic while using learned scoring where context matters.

## Evaluation boundaries

Judge Showcase and Judge Chaos are development/regression datasets and may be used for error analysis. They are **not** external holdouts. After model/detector freeze, a new external source must be evaluated without modifying the frozen files.

A score from VeilGraph datasets is a product-development result, not evidence of universal PII generalization. External-holdout results must be reported separately.

## Known limitations

- OCR errors can corrupt the evidence before semantic detection, especially on skewed/low-quality images.
- The linear classifier is intentionally compact for local reproducibility and is not a large language model.
- Entity classes outside the five learned classes remain deterministic/contextual or visual.
- Human review is retained for uncertain person names and other high-impact cases.
