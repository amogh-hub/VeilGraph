# VeilGraph · Broad-Coverage PII Engine v2

## Purpose

The external PIIMB `ai4privacy-en` baseline exposed a precise weakness in the 104-test build: VeilGraph was highly precise but too conservative for broad international PII masking. The full 18,538-sentence baseline measured **98.266% precision**, **24.380% recall**, **39.067% F1**, and **28.695% F2**.

Broad-Coverage PII Engine v2 expands detection breadth without replacing the existing precise India-specific validators, local semantic NER, human-review gate, Identity Exposure Graph, gradational privacy compiler, or 12-attack fail-closed release verification.

## New explicit entity classes

- `PERSON_TITLE`
- `GENERIC_DATE`
- `BUILDING_NUMBER`
- `NATIONAL_ID`
- `PASSPORT_NUMBER`
- `DRIVER_LICENSE_NUMBER`
- `TAX_IDENTIFIER`
- `SOCIAL_IDENTIFIER`
- `PAYMENT_CARD_NUMBER`
- `DEMOGRAPHIC_ATTRIBUTE`

These complement existing `PERSON_NAME`, `PHONE`, `EMAIL`, `DATE_OF_BIRTH`, `AGE`, `STREET_ADDRESS`, `LOCALITY`, `POSTCODE`, `AADHAAR_LIKE`, `PAN_LIKE`, `EMPLOYER`, `JOB_TITLE`, and `CASE_REFERENCE` detections.

## Architecture

```text
Precise deterministic validators ─┐
Local Semantic NER               ├─> candidate fusion -> Identity Exposure Graph
Broad PII intelligence v2        ┘                         |
                                                         privacy compiler
                                                       L1 / L2 / L3 / L4
                                                               |
                                                        Privacy Red Team
                                                               |
                                                         signed release proof
```

Broad detection is context-aware. VeilGraph does not respond to the external benchmark by masking every number or capitalized word. Credential-like values require semantic labels/context, general dates remain a quasi-identifier rather than a direct credential, and low-confidence semantic clues still flow through human review.

## Benchmark integrity

The external PIIMB labels are **not** used as runtime inputs. PIIMB remains an unchanged held-out measurement corpus. v2 engineering was driven by the benchmark's public taxonomy and by observed aggregate weakness, not by changing gold spans or suppressing failures.

The v2 evaluator additionally produces `diagnostic_by_gold_label` so misses can be attributed to the benchmark's published labels. This diagnostic does **not** change PIIMB's official character-level, label-agnostic Precision/Recall/F1/F2/FPR calculation.

Every subsequent PIIMB run now records `input_sha256`, binding the report to the exact external benchmark file bytes.

## Privacy semantics

Broad PII participates in the same gradational system:

- **L1 Mask:** direct credentials are masked; broad contextual clues may remain.
- **L2 Protect:** direct credentials and high-impact exact context become opaque protected tokens.
- **L3 Generalize:** direct credentials are masked and quasi-identifiers are generalized.
- **L4 Relationship-safe pseudonymize:** direct credentials are consistently pseudonymized while contextual clues are generalized.

Generalization is deliberately non-reconstructive. Unknown city/street values are converted to coarse semantic categories rather than retaining the original clue inside strings such as `Waldorf area`.

## Security / release verification

The Privacy Red Team has been extended so newly introduced direct credentials are included in direct-rescan, known-original, fragment-leakage and output-consistency checks. A broad-identifier end-to-end test proves that the protected artifact reaches `VERIFIED_SAFE` only after all 12 mandatory attacks pass.

## Claim boundary

No v2 PIIMB improvement is claimed until the unchanged external dataset is rerun on the user's verified build. The preserved pre-v2 result exists specifically so a weak baseline cannot be overwritten or hidden.
