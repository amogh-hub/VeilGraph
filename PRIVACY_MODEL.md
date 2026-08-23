# VeilGraph Privacy Model

## Principle

VeilGraph protects against two classes of identity evidence:

- **direct identifiers** — values that identify a person or case directly;
- **reconstruction clues** — quasi-identifiers and relationships that can become identifying when combined.

Privacy therefore operates on canonical entities **and their relationships**, not only on isolated text spans.

## Entity classes

The current engine includes direct identifiers such as person names, phone numbers, email addresses, Aadhaar-like/PAN-like values, case references, national/passport/driver/tax/social identifiers and payment cards; quasi/context classes such as dates of birth, age, address/locality/postcode, employer, job title, generic dates, building numbers and demographic attributes; and visual classes including face, QR and signature candidates.

No claim is made that this list covers every possible PII class or language.

## Identity Exposure Graph

The IEG connects subjects, related people and privacy-bearing clues. It is used to expose high-risk paths that a flat detector list can miss. The graph is also bound into release proof so the evidence used for the decision cannot be silently swapped after certification.

## L1–L5 semantics

### L1 — Direct masking

Protect direct identifier classes while retaining lower-risk context. This is the least destructive level and is intended for cases where preserving context is more important than breaking broader linkage.

### L2 — Sensitive-entity protection

Protect direct identifiers plus selected high-impact contextual/credential fields with opaque stable tokens. It creates a meaningful gradation step between simple direct masking and broader context generalization.

### L3 — Context generalization

Mask direct identity and generalize quasi-identifying context into broader, less linkable descriptions. Audience can affect limited retention of operational context.

### L4 — Relationship-safe pseudonymization

Use stable pseudonyms for direct identity and selected relationship-bearing fields while generalizing quasi-identifying context. Stable aliases preserve analytical relationships within a job without retaining source identity values.

### L5 — Synthetic Twin

For structured CSV/JSON/XLSX datasets only. The source population is profiled in memory and a new population is generated with measured schema/distribution/correlation/time-order utility and explicit source-copy/source-identity-reuse checks.

Production releases use cryptographic randomization so repeated source data is not intentionally mapped to the same synthetic population across releases.

## Gradation evidence

The final same-source calibration executed all five levels and passed every release gate. Intervention coverage and context-protection coverage were non-decreasing across L1→L5. Residual Exposure itself is **not required to be numerically monotonic** between adjacent levels because different levels trade privacy and utility using different mechanisms.

## Human review

Ambiguous sensitive candidates can enter a review state. Where protection-critical review remains unresolved, transformation/release is blocked. This prevents the system from silently converting model uncertainty into a release decision.

## Audience and purpose

VeilGraph supports three audience profiles:

- `PUBLIC_RELEASE`
- `RESEARCH_PARTNER`
- `INTERNAL_OPERATIONS`

A deterministic recommendation engine considers audience, stated purpose/recipient, current exposure, file type and high-risk entities. Recommendation is advisory/governance input; it never certifies safety.

## Release rule

The output is safe to download only when every mandatory gate for its format/level is `PASS`. `FAIL` and `INCONCLUSIVE` both prevent release. The proof score is an operational product score tied to the implemented gates, not a legal anonymity certification.

## Synthetic-data boundary

VeilGraph does not claim that converting arbitrary prose into generated images/video is equivalent to statistically useful synthetic-data generation. L5 population synthesis is limited to structured datasets where source-copy, schema and utility evidence can be measured. Verified synthetic populations can then be exported into useful representations.

## Claims VeilGraph does not make

- guaranteed anonymity;
- impossibility of re-identification;
- differential privacy unless a future mechanism explicitly implements and proves it;
- universal PII/NER/face/signature accuracy;
- legal compliance certification for every jurisdiction;
- forensic destruction of SSD flash cells.

Use the phrase: **VeilGraph Residual Exposure Score — a calibrated product risk indicator, not a legal guarantee of anonymity.**
