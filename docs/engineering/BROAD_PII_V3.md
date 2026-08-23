# VeilGraph Broad-Coverage PII Engine v3

This patch is built against the verified `veilgraph-sih-final-116passed-v2` source snapshot.

## Purpose

v3 is a targeted hardening pass driven by the frozen PIIMB v2 diagnostic profile. It does not change the frozen benchmark corpus or weaken VeilGraph's production fail-closed controls.

The v3 layer expands:

- address intelligence: building numbers, street suffixes, city/locality context, international postcode shapes;
- person intelligence: strong contextual name phrases and sentence-start person/action patterns;
- credential intelligence: broader passport, driving-licence, national-ID, tax/social-ID label variants;
- payment-card validation: context-aware detection plus Luhn validation for unlabeled card-like numbers;
- contextual quasi-identifiers: additional age and demographic-language forms.

Existing v1/v2 detector ownership is preserved where an earlier detector already controls the transformation span, preventing overlapping replacement conflicts.

## Claim boundary

PIIMB remains an external development/regression benchmark after the v2 failure analysis. v3 benchmark improvements must be measured on the user's unchanged dataset; this patch does not claim an improved external score before that measurement.

## Local acceptance

Run:

```bash
./scripts/run_broad_pii_v3_matrix.sh
./scripts/run_checks.sh
```

Expected v3 matrix: `18 passed`.

Since v2 had 116 tests and v3 adds 18, the expected full regression count is `134 passed`.
