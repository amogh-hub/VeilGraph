# Broad PII v4 — Local Hybrid Detection

Broad PII v4 is VeilGraph's Phase-1 generalization upgrade. It is a hybrid detector, not a cloud LLM wrapper.

## Pipeline

```text
supported input
→ Universal Privacy IR / positioned evidence
→ deterministic identifiers
→ schema/context detector v4
→ local Semantic NER v2
→ quasi + visual detectors
→ conflict-aware candidate fusion
→ canonical entities + human review
→ Identity Exposure Graph
```

## What v4 adds

- common field/header semantics across native text, PDF, DOCX and structured-data renderings;
- adjacent label/value layouts;
- dense `key=value|...` records;
- nested JSON path semantics;
- Unicode/mixed-script-aware labelled names;
- prose case/person/employer/locality contexts;
- a reproducible local learned span classifier for contextual entities;
- conflict-aware fusion so authoritative schema semantics are not overwritten by weaker generic candidates;
- valid absolute OPC relationship targets in arbitrary XLSX packages;
- signature-region search that is robust when OCR merges a handwritten mark into the same line as its label.

## Scientific split discipline

`Judge Showcase v1` and `Judge Chaos v1` are development data. The previous frozen Nemotron result belongs to Broad PII v3 and is not used to tune v4. Broad PII v4 must be hash-frozen before any new external holdout is opened/evaluated.

## Security boundary

ML can propose sensitive spans. It cannot sign a certificate, declare `VERIFIED_SAFE`, bypass mandatory human review, or authorize a download. Those decisions remain governed by deterministic transformation, Privacy Red Team and proof logic.
