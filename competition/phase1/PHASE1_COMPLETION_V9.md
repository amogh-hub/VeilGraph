# VeilGraph Phase 1 Completion v9

## Scope

Phase 1 is **Accuracy & Judge-Data Readiness**. This release adds the final Phase-1 production/evidence work on top of the accepted v8 baseline without changing the frozen privacy transformation, proof, Red Team, DOCX, video or retention semantics.

### Broad PII v4

- hybrid deterministic + local semantic ML detector;
- `semantic_ner_v2` is a bundled logistic-regression span classifier with a pure-Python runtime and no inference-time network dependency;
- explicit context/schema detector for field, inline, adjacent, nested structured and prose semantics;
- deterministic validators remain authoritative for identifiers they already handle well;
- Broad PII v3 remains byte-identical and is retained as an independent detector channel;
- security/release decisions remain deterministic and are never delegated to ML.

### Judge readiness evidence

Development datasets remain strictly separated:

- `VG-JUDGE-SHOWCASE-1.0`: polished judge/demo + development data;
- `VG-JUDGE-CHAOS-1.0`: adversarial development/regression data;
- neither dataset is an untouched holdout.

`run_phase1_judge_benchmark.py` reports detection quality (P/R/F1/F2/FPR/FDR, per-entity/per-format) and evidence quality (source-unit/geometry/annotation integrity) using the production pipeline.

Current development evidence in this build:

- Showcase: P 0.9949 / R 1.0000 / F1 0.9974 / F2 0.9990 / explicit-negative FPR 0.0000 / evidence 0.9731
- Chaos: P 0.9612 / R 0.9340 / F1 0.9474 / F2 0.9393 / explicit-negative FPR 0.0000 / evidence 0.8611

The Chaos result intentionally remains lower: the rotated/low-quality OCR fixtures are development stress evidence rather than data selected to produce a perfect score.

### Explainable L1-L5 recommendation

The backend now recommends a privacy level from audience, purpose, input type, detected risk and entity sensitivity. It returns:

- recommended level;
- minimum organisational-policy floor;
- reasons;
- privacy/utility preview for L1-L5;
- format limitations (including no fake L5 for non-structured inputs);
- explicit disclaimer that exposure/utility numbers are product indicators, not legal anonymity guarantees.

The frontend displays the recommendation, explanation, all level previews and a one-click recommended-level action. Policy-floor enforcement is available by configuration and remains disabled by default in competition mode to preserve current user-control behavior.

### Fresh external holdout protocol

The exact Broad PII v4 detection/inference surface is frozen in `BROAD_PII_V4_FREEZE_MANIFEST.json` **before** the new external holdout is opened. The final Phase-1 scientific gate is `spia-bench/SPIA-benchmark` / `02_spia_panorama_151.jsonl`, a 151-document PANORAMA synthetic test subset.

Because SPIA is inference-aware, VeilGraph scores only the taxonomy-overlap, surface-visible subset and separately reports inference-only/unsupported annotations. The raw external holdout is not bundled into the repository. The evaluator checks the detector freeze before and after the run and writes aggregate evidence only.

Once that holdout has been evaluated, no frozen detector/model file may be tuned from the result. Any subsequent detector change requires a different untouched external holdout.

## Acceptance gates

1. `./scripts/run_phase1_completion_matrix.sh` passes.
2. `./scripts/run_external_holdout_spia.py` completes against the frozen detector and writes aggregate results.
3. `./scripts/run_checks.sh` passes all **207** backend tests plus TypeScript and Vite production build on the target Mac.
4. Browser acceptance shows the L1-L5 recommendation + preview for at least one non-structured file and L5 recommendation for a structured Synthetic Twin use case.

Only after these gates are recorded should Phase 1 be marked COMPLETE/FROZEN and Phase 2 begin.
