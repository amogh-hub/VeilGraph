# VeilGraph L1-L5 Gradation Calibration

Same source fixture processed independently through every privacy level.

| Level | Policy | Intervention coverage | Context coverage | Exposure | Utility | Red Team | Release |
|---:|---|---:|---:|---:|---:|---:|---|
| L1 | Level 1 / Direct masking | 44% | 0% | 95 → 86 | 45% | 12/12 | VERIFIED_SAFE |
| L2 | Level 2 / Sensitive-entity protection | 67% | 40% | 95 → 85 | 45% | 12/12 | VERIFIED_SAFE |
| L3 | Level 3 / Context generalization | 100% | 100% | 95 → 86 | 45% | 12/12 | VERIFIED_SAFE |
| L4 | Level 4 / Relationship-safe pseudonymization | 100% | 100% | 95 → 78 | 45% | 12/12 | VERIFIED_SAFE |
| L5 | Level 5 / Synthetic Twin generation | 100% | 100% | 95 → 1 | 88% | 15/15 | VERIFIED_SAFE |

## Acceptance

- PASS — all levels executed
- PASS — all release gates passed
- PASS — intervention coverage non decreasing
- PASS — context protection non decreasing
- PASS — level5 source independent
- PASS — level5 has 15 gates

## Claim boundary

Gradation is calibrated as a non-decreasing scope of protected entity/context classes plus a distinct relationship-preserving L4 and source-independent L5. Residual Exposure is also reported as a measured product risk indicator; it is not forced to be numerically monotonic when two adjacent levels use different privacy/utility mechanisms.
