# VeilGraph Slice E — Build Report + Final Hardening Passes 1–2

Generated 2026-08-07.

## Delivered

- all Slice A–D functionality retained;
- Ed25519 local device signing identity;
- signed privacy proof certificate automatically issued only after `VERIFIED_SAFE`;
- certificate binding to output/input/manifest/graph/verification/audit hashes;
- printable certificate PDF;
- SHA-256 tamper-evident per-job audit ledger;
- independently recomputable proof bundle containing manifest, Identity Exposure Graph and per-file hash index;
- Ed25519-signed exact-bundle receipt plus post-export audit checkpoint;
- complete signed proof package ZIP;
- standalone offline certificate/artifact verifier and complete-package verifier;
- signed application-level destruction receipt;
- VeilBench v0.1 reproducible benchmark harness and evidence files;
- competition judge demo script, evidence matrix, claims/boundaries and technical one-pager;
- Slice E UI showing signer fingerprint, certificate ID, signature validity, certificate hashes and audit integrity.

## Verification executed in this environment

### Python compilation and API contracts

```text
python -m compileall: PASS
backend/openapi.json generation: PASS
frontend/src/api/schema.d.ts generation: PASS
```

### Backend tests

```text
46 tests collected
```

All test groups passed. OCR/OpenCV/ASGI groups were executed in isolated Python invocations because the shared Linux runner can intermittently hang during native-library teardown when every group is kept in one long process.

```text
test_detection.py                 7 passed
test_security.py                  2 passed
test_verification_qr_review.py   13 passed
test_ts_type_generator.py         1 passed
test_slice_d.py                    6 passed
test_end_to_end.py                 5 passed
test_slice_c.py                    5 passed
test_slice_e.py                    6 passed
test_final_hardening.py            1 passed
-------------------------------------------
TOTAL                             46 passed
```

### Frontend source validation

```text
tsc -p tsconfig.sandbox.json --pretty false
PASS
```

A real Vite production bundle is not installed in this sandbox. The target Mac must independently run `./scripts/setup_once.sh` then `./scripts/run_checks.sh`; acceptance requires the real TypeScript typecheck and Vite production build to pass there.

## Slice E proof tests

The new regression suite verifies:

- Ed25519 sign/verify and tamper rejection;
- audit-chain tamper detection;
- certificate blocked before proof-gate success;
- Level 4 verified output automatically receives a valid certificate;
- certificate PDF generation;
- proof-bundle composition;
- protected-artifact SHA-256 equals certificate commitment;
- bundle certificate remains independently verifiable;
- audit trail records verification, certificate issuance, protected download and bundle export;
- signed destruction receipt validates;
- destruction removes audit and certificate rows.

## VeilBench v0.1 build-time run

The reproducible benchmark completed **2/2 PASS**.

### Digital identity-reconstruction dossier · Level 4

```text
15 canonical entities
17 mentions
16 graph nodes
34 graph edges
Exposure: 100 → 37
Utility retained: 66
17 transformations
12/12 mandatory attacks PASS
Proof score: 100/100
Certificate signature: valid
```

### Scanned multimodal dossier · Level 1

```text
7 canonical entities
8 mentions
2/2 OCR pages
2 visual mentions
Exposure: 50 → 10
Utility retained: 75
8 transformations
12/12 mandatory attacks PASS
Proof score: 100/100
Certificate signature: valid
```

Combined mandatory attack result: **24/24 PASS**.

The exact generated evidence is in `competition/veilbench-results.json` and `competition/VEILBENCH_REPORT.md`.

## Security semantics

A certificate is never issued for a `RELEASE_BLOCKED` output. A proof bundle is unavailable until every mandatory Privacy Red Team gate is PASS, proof score is 100/100 and critical blockers are zero. Proof-bundle export additionally verifies the stored certificate signature and current audit-chain integrity.

The device signing key is local and establishes continuity of the VeilGraph installation, not an external certificate authority or government endorsement.

## Final Hardening Pass 1 verification

Focused execution in this environment:

```text
tests/test_final_hardening.py: 1 passed
tests/test_slice_e.py: 6 passed
Python compileall: PASS
OpenAPI export: PASS
OpenAPI-derived TypeScript schema generation: PASS
Sandbox TypeScript compile: PASS
Complete proof-package smoke verification: 19/19 package checks PASS
Certificate PDF full 88-character Base64 Ed25519 signature extraction: PASS
```

The Linux runner can intermittently remain alive during teardown after mixed PyMuPDF/OpenCV/Tesseract suites, so the target Mac remains authoritative for the single-process `./scripts/run_checks.sh` gate. The user's prior unpatched Slice E baseline passed 45/45 plus the real Vite build; after this patch the expected count is 46.


## Final Hardening Pass 2

New backend regression coverage adds 10 tests, taking collection from 46 to **56 tests**. Focused Pass 2 execution in this build environment:

```text
tests/test_final_hardening_pass2.py: 10 passed
Python compileall: PASS
OpenAPI export: PASS
OpenAPI-derived TypeScript schema generation: PASS
```

The reproducible offline stress harness passed **7/7** cases: rotated scan detection, 12-page cross-page consistency, encrypted-PDF rejection, extreme render-budget rejection, malformed-PDF rejection, filename-injection normalization, and hidden metadata/attachment/text scrubbing.

As with prior passes, the user's target Mac remains authoritative for the single-process full suite and real Vite production build. The required target result after applying Pass 2 is `56 passed` plus TypeScript typecheck and Vite build PASS.
