# VeilGraph Judge Dataset Readiness v8

This milestone begins Phase 1 — Accuracy & Judge-Data Readiness.

## Locked dataset separation

| Dataset | Purpose | May tune on it? | Show judges? |
|---|---|---:|---:|
| Judge Showcase v1 | polished demonstration + labelled examples | yes | yes |
| Judge Chaos v1 | adversarial robustness development | yes | representative cases + aggregate results |
| New external holdout | final generalization evidence after Broad PII v4 freeze | **no** | yes, final metrics |

## What v8 does

- Adds 23 fully fictional multi-format files.
- Adds 517 entity-level ground-truth occurrences.
- Covers all current VeilGraph format families.
- Adds machine-verifiable SHA-256 dataset manifests.
- Adds explicit L5 scope checks: L5 is only recommended on CSV/JSON/XLSX.
- Adds regression tests preventing accidental holdout contamination or dataset drift.

## What v8 deliberately does not do

- It does not modify Broad PII v3.
- It does not claim improved detection accuracy.
- It does not modify the Identity Exposure Graph, transformation engine, Red Team, proof, video, DOCX or retention logic.
- It does not convert the Chaos dataset into a holdout.

## Next milestone

Use Showcase + Chaos as development/evaluation inputs for **Broad PII v4**, the local hybrid ML + deterministic detector. After v4 is frozen, evaluate on a new untouched external holdout exactly once for final generalization evidence.
