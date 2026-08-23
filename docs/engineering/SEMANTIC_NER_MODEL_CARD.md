# VeilGraph Semantic NER v1 — Model Card

## Purpose
A small, auditable, local NLP/ML layer for contextual sensitive-entity spans that deterministic labels and structured identifier patterns may miss.

## Model family
Per-entity logistic-regression span classifiers operating on conservative context-generated candidates. Runtime uses Python standard-library math only; no network or external model API is required.

## Supported semantic classes in v1
- PERSON_NAME
- STREET_ADDRESS
- EMPLOYER
- JOB_TITLE

Structured identifiers such as phone, email, PAN-like and Aadhaar-like values remain under deterministic validators because those are more appropriate for high-structure identifiers.

## Training data
A small independent fictional CC0 synthetic context corpus bundled at `backend/training_data/semantic_ner_train_v1.json`. The model records the SHA-256 of that corpus. It is intentionally separate from the evaluation corpus.

## Evaluation boundary
The existing VeilBench curated corpus is SHA-256 frozen and must not be modified during this phase. Internal VeilBench results are regression evidence only, not universal accuracy claims. External open-source benchmark measurement remains mandatory before the NTRO metric requirement is marked complete.

## Human review
Semantic person-name detections are routed to fail-closed human review. Other high-confidence semantic categories use the existing policy and proof pipeline.

## Security
The model has no tool permissions, no network access, no prompt execution surface and no user-data training behavior.
