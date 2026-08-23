# VeilGraph — Phase 2 Final Report

## Status
**PHASE 2 — PRODUCTION, SECURITY & SCALE: MACHINE GATES COMPLETE; MANUAL ACCEPTANCE REQUIRED**

- Security self-test: 9/9 PASS
- Full regression: 254 passed, 0 failed
- OpenAPI generation: PASS
- TypeScript: PASS
- Vite production build: PASS
- Sanitized release package SHA-256: `5050e199b1ca9759f0e64a8751b1df096f2faa19dd5b397dd90f28c34367f950`
- Detector concurrency: 4/4 deterministic workers
- Integrated API-job concurrency: 4/4 isolated jobs
- Process lifetime high-water RSS after benchmark: 348.56 MiB

## Measured performance
| Case | p50 ms | p95 ms | CPU p50 ms | CPU core-equiv % | KiB/s p50 | Python peak MiB | Process high-water RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| full_detection_text_1k | 45.032 | 45.491 | 45.029 | 99.99 | 22.21 | 0.08 | 145.58 |
| full_detection_text_8k | 431.047 | 431.148 | 431.043 | 100.0 | 18.56 | 0.61 | 146.61 |
| full_detection_text_24k | 1344.732 | 1347.017 | 1344.121 | 99.95 | 17.85 | 1.99 | 166.81 |
| full_detection_text_64k | 3801.226 | 3810.501 | 3788.486 | 99.66 | 16.84 | 5.75 | 217.48 |
| validation_text_8mb | 282.728 | 286.941 | 282.633 | 99.97 | 28974.87 | 8.0 | 222.72 |
| structured_extraction_1000_rows | 44.028 | 48.411 | 43.686 | 99.22 | 1726.07 | 6.75 | 225.14 |
| structured_extraction_5000_rows | 269.108 | 269.824 | 269.07 | 99.99 | 1443.64 | 35.13 | 257.19 |
| pdf_extraction_5_pages | 384.005 | 385.565 | 383.995 | 100.0 | 47.39 | 0.43 | 327.14 |

## Production/security controls ready for manual freeze acceptance
- finite heavy-operation concurrency admission;
- PII-free operational metrics honoring configured metric-window capacity;
- offline localhost boundary plus fail-closed Python DNS/socket egress guard;
- secure-online bearer-token boundary with trusted-proxy-only forwarded HTTPS;
- 0700 workspace directories, 0600 encrypted blobs and atomic encrypted writes;
- hardened proof ZIP verification limits/path checks;
- preserved retention/destruction and signed proof architecture;
- deterministic sanitized competition release builder excluding private/runtime material and enforcing exact manifest membership;
- COTS/industry capability comparison plus frozen Phase-3 quantitative benchmark protocol;
- strict regression closure derived from observed pytest/OpenAPI/TypeScript/Vite gates.

## Claim boundaries
- Python allocator peak does not include all native allocations.
- Process high-water RSS is not per-case resident memory.
- Commercial COTS quantitative results are not claimed until actually measured under the frozen protocol.

## Next
Run `scripts/verify_phase2_freeze.py`, inspect the generated evidence manually, and only then mark Phase 2 authoritative and move to **PHASE 3 — EVIDENCE & FINAL RELEASE**.
