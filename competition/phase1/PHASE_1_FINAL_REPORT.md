# VeilGraph — Phase 1 Final Report

## Status
**PHASE 1 — ACCURACY & JUDGE-DATA READINESS: COMPLETE & FROZEN**

VeilGraph Phase 1 is closed on Broad PII v5 + Semantic NER v3.  
No Broad PII v6/v7 iteration is required merely to keep Phase 1 open.

## Frozen detector
- Broad PII: v5
- Semantic NER: v3.0.0
- Training examples: 2,330
- Runtime external model calls: none
- Frozen production/model surface: 22 files, independently verified byte-identical before/after external evaluation
- Privacy Red Team: unchanged and fail-closed

## Development evidence

### VG-JUDGE-SHOWCASE-1.0
- Precision: 0.9974
- Recall: 1.0000
- F1: 0.9987
- F2: 0.9995
- FPR: 0.0000
- Evidence geometry score: 0.9731

### VG-JUDGE-CHAOS-1.0
- Precision: 0.9519
- Recall: 0.9340
- F1: 0.9429
- F2: 0.9375
- FPR: 0.0000
- Evidence geometry score: 0.8611

## Untouched external evidence

### TAB — Broad PII v4 historical holdout
- Documents: 127
- Precision: 0.2843
- Recall: 0.3874
- F1: 0.3279
- F2: 0.3612
- Direct recall: 0.0360
- Quasi recall: 0.4169

This result is preserved as historical v4 generalization evidence.

### ARI synthetic TEST — Broad PII v5 holdout
- Documents: 1,201
- Exact precision: 0.3472
- Exact recall: 0.5021
- Exact F1: 0.4105
- Exact F2: 0.4610
- Relaxed precision: 0.4029
- Relaxed recall: 0.5807
- Relaxed F1: 0.4757
- Relaxed F2: 0.5336
- Critical shared recall: 0.5280
- Contextual shared recall: 0.6886
- Predeclared external quality gate: FAIL

The failed quality gate is retained as a documented generalization limitation. It does not trigger an endless detector-version loop or invalidate completion of the engineering/evaluation scope of Phase 1.

## Regression acceptance
Authoritative Mac acceptance run:
- Backend tests: **237 passed, 0 failed**
- Warnings: 5 non-fatal SWIG deprecation warnings
- TypeScript typecheck: PASS
- Vite production build: PASS
- Broad PII v5 freeze: VALID
- Semantic NER v3 runtime network requirement: False

## Browser recommendation acceptance
Manual UI acceptance completed:
- External/public DOCX → **L4 Relationship-safe pseudonymization**: PASS
- L5 unavailable for unsupported unstructured DOCX output: PASS
- Structured XLSX synthetic/shareable research intent → **L5 Synthetic Twin** automatically recommended: PASS
- L5 policy UI showed synthetic generation and preserved fail-closed human review: PASS

## Phase-1 exit rule
Phase completion means the agreed accuracy and judge-data engineering scope has been implemented, evaluated, regression-tested and frozen. It does **not** mean the detector has perfect performance on every possible unseen distribution.

Future accuracy improvements may still be made if later judge testing or production evidence justifies them, but they are normal controlled iterations and do not reopen Phase 1 automatically.
