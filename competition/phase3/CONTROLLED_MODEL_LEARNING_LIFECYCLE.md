# VeilGraph Controlled Model Learning Lifecycle

VeilGraph **does not silently learn from operational uploads**. Sensitive user documents remain operational data and are never automatically promoted into training material.

The model-improvement lifecycle is controlled:

1. reviewer feedback is exported only through an approved, privacy-reviewed workflow;
2. training data is curated into a versioned corpus separate from operational workspaces;
3. training runs offline using the repository's explicit training scripts;
4. the result is a candidate model with a new version and hashes;
5. candidate performance is evaluated on development data and then on untouched holdout data that was not used for tuning;
6. production/model files are frozen by SHA-256 only after acceptance;
7. the frozen model is promoted as a signed/reproducible release; and
8. runtime inference remains local and requires no third-party model API.

This is the intended meaning of “over time, model will learn” for a high-security NTRO setting: **controlled model evolution without covert training on confidential inputs**.

## Current demonstrated evolution

- Semantic NER v1 → v2 → v3 are retained as distinct model generations.
- Semantic NER v3 is version `3.0.0` and is bound to the Phase-1 frozen detector surface.
- The v3 training corpus contains 2,330 examples.
- Broad PII v5 / Semantic NER v3 are frozen and must not be modified during Phase 3.

## Promotion rule

No future model may replace the frozen production model in place. A future v4 must be built as a new candidate, evaluated on new evidence, and receive a new freeze manifest. Consumed holdouts remain consumed and cannot be turned into tuning data.
