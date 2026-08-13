# Semantic NER v3 — Model Card

## Summary

Semantic NER v3 is VeilGraph's local semantic component for Broad PII v5. It is intentionally lightweight and offline: a contextual candidate generator produces possible PERSON_NAME, EMPLOYER, LOCALITY, STREET_ADDRESS and JOB_TITLE spans and a bundled logistic model scores them using deterministic lexical/context features.

It is not a generative model and does not make release decisions.

## Identity

- Version: `3.0.0`
- Schema: `veilgraph.semantic-ner.linear.v3`
- Model family: local logistic-regression contextual span classifier
- Runtime external network/API calls: none
- Training examples: 2,330
- Training data: synthetic only
- Real PII in training corpus: no

## Inputs and outputs

Input: locally extracted text plus canonical source offsets/geometry.

Output: candidate semantic mentions with entity class, confidence, source offsets and review status. The candidates are fused with deterministic detection channels before human review and graph analysis.

## Supported semantic classes

- PERSON_NAME
- EMPLOYER
- LOCALITY
- STREET_ADDRESS
- JOB_TITLE

High-structure credentials such as emails, phones, passports and tax/national identifiers are primarily handled by deterministic/context-anchored detectors rather than asking ML to rediscover reliable syntax.

## Training and reproducibility

`backend/training_data/semantic_ner_train_v3.json` is generated reproducibly by `scripts/build_semantic_ner_v3_corpus.py`. `scripts/train_semantic_ner_v3.py` reproduces `backend/models/semantic_ner_v3.json`. The freeze manifest binds both files by SHA-256.

## Safety boundary

Semantic NER v3 can nominate a sensitive span. It cannot:

- issue `VERIFIED_SAFE`,
- authorize `ALLOW_RELEASE`,
- sign a certificate,
- bypass mandatory Privacy Red Team gates,
- change retention/destruction policy.

Those operations remain deterministic and fail closed.

## Limitations

The model is deliberately compact and is not equivalent to a large transformer NER system. Ambiguous prose, new languages/scripts, rare identifiers and highly obfuscated context can still require human review or deterministic fallback. External-holdout results must therefore be reported alongside development metrics.
