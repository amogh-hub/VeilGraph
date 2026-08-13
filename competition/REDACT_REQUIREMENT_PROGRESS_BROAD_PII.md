# RE-DACT requirement progress · Broad-Coverage PII Engine v2

## Requirement addressed

The NTRO statement requires NLP/ML redaction that removes identifiers and other clues that can reveal identity, and explicitly requires Precision/Recall/F1 measurement on an open-source test set.

## Evidence before v2

The verified 104-test build completed the full PIIMB `ai4privacy-en` benchmark (18,538 sentences) with:

| Metric | Pre-v2 baseline |
|---|---:|
| Precision | 98.266% |
| Recall | 24.380% |
| F1 | 39.067% |
| F2 | 28.695% |
| FPR | 0.123% |

This showed excellent selectivity but inadequate breadth.

## v2 implementation

Broad-Coverage PII v2 adds explicit international/general PII classes for titles, generic dates, building numbers, national IDs, passports, driving licences, tax/social identifiers, payment cards and demographic attributes, plus broader contextual city, phone, address and person-name handling.

The new classes feed the existing:

- Universal Privacy IR
- entity fusion
- Identity Exposure Graph
- L1-L4 policy compiler
- human-review gate
- 12-attack Privacy Red Team
- Ed25519 proof/certificate pipeline

## Measurement discipline

- Pre-v2 external result is frozen in `competition/baselines/PIIMB_AI4PRIVACY_EN_PRE_V2_18538.json`.
- v2 records SHA-256 of the exact PIIMB file.
- `diagnostic_by_gold_label` is diagnostic only; official PIIMB metrics remain character-level and label-agnostic.
- `scripts/compare_piimb.sh` produces the before/after evidence after rerunning the same benchmark.
- No claim of improvement is made until that rerun completes.

## Status

Implementation: **ready for user verification**.

Acceptance requires:

1. `12 passed` from `run_broad_pii_matrix.sh`.
2. full regression gate green (expected **116 passed**).
3. same 5,000-row PIIMB smoke benchmark completes.
4. same full 18,538-row PIIMB benchmark completes.
5. before/after report is generated and reviewed.
