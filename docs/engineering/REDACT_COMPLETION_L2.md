# VeilGraph RE-DACT Completion — Level 2

This patch closes the missing selectable **Level 2 — Sensitive-entity protection** workflow in the existing `veilgraph-sih-final` competition codebase.

## Level semantics

- **L1 — Direct masking:** obvious direct identifiers are partially masked; quasi-identifiers remain.
- **L2 — Sensitive-entity protection:** high-impact sensitive entities become opaque stable structural tokens such as `[PERSON_001]`, `[DOB_001]`, `[ADDRESS_001]`; lower-risk context remains for later levels.
- **L3 — Context generalization:** exact context becomes broader categories.
- **L4 — Relationship-safe pseudonymization:** stable semantic aliases preserve cross-page relationships while removing source identity.

L2 currently protects person names, phone numbers, email, Aadhaar-like/PAN-like values, case references, exact date of birth, street address and postcode. Visual identifiers remain irreversibly removed. Age, locality, employer and job title remain at L2 so that the gradational difference to L3 is real and measurable rather than cosmetic.

## Proof added

Four regression tests were added:

1. L2 is a first-class API privacy level.
2. L2 policy maps the intended entity classes to `PROTECT` and later-level context to `RETAIN`.
3. L2 output uses stable opaque tokens and still passes the 12-attack fail-closed release gate.
4. The bundled identity dossier has strictly decreasing residual exposure across L1 → L2 → L3 → L4.

The deterministic dossier measured in the build environment:

| Level | Residual exposure | Utility |
| --- | ---: | ---: |
| L1 | 79 | 76 |
| L2 | 66 | 56 |
| L3 | 47 | 52 |
| L4 | 37 | 66 |

These values are product measurements for the bundled dossier, not universal privacy guarantees.

## Acceptance gate

After applying the patch, `./scripts/run_checks.sh` on the canonical Mac environment must report **60 passed**, TypeScript type-check success and a Vite production build.
