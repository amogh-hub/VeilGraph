# VeilGraph — Phase 2 Scope Lock

## Phase
**PHASE 2 — PRODUCTION, SECURITY & SCALE**

## Finite completion rule
Phase 2 is complete when the agreed production/security/scale controls are implemented, tested, measured, manually reviewed and frozen. It does not remain open merely because a future machine or workload could produce a faster latency number.

Completion gates:
1. Phase-1 Broad PII v5 freeze remains byte-identical and the Phase-1 closure manifest remains unchanged.
2. Production-boundary tests pass: offline localhost-only mode and authenticated HTTPS secure-online mode.
3. Forwarded HTTPS is accepted only when proxy-header trust is explicitly enabled and the immediate peer is inside an explicit trusted proxy network; arbitrary clients cannot spoof `X-Forwarded-Proto` to bypass HTTPS enforcement.
4. In-process external DNS/socket egress fails closed in competition offline mode.
5. Bounded heavy-operation concurrency is enforced.
6. PII-free operational metrics expose p50/p95, concurrency and error counts without request bodies/query strings/job IDs, and honor the configured metrics-window capacity.
7. Workspace blobs use AES-256-GCM as before, with 0700 job directories, 0600 encrypted blobs and atomic writes.
8. Proof-package verifier rejects unsafe ZIP paths, symlinks, excessive archive sizes and suspicious compression ratios.
9. Retention/destruction regression remains green.
10. Security self-test is green.
11. Performance/scale benchmark completes and records wall-clock p50/p95, process CPU time, per-case Python allocator peak, explicitly labelled process high-water RSS, throughput and deterministic behavior.
12. Scale evidence includes bounded larger inputs plus both detector concurrency and real API/DB/encrypted-workspace concurrent-job isolation.
13. Sanitized competition release excludes runtime databases, workspaces, private keys, caches, virtual environments, build output and environment-secret files, and the verifier requires the archive member set to exactly equal the signed manifest member set.
14. COTS/industry capability comparison is documented with claim boundaries; a common quantitative COTS protocol is frozen for Phase 3 external-evidence execution where vendor access is available.
15. Full project regression, OpenAPI generation, TypeScript typecheck and Vite production build are green, and the closure record derives `all_passed` from those observed gates rather than hardcoding it.
16. A Phase-2 freeze manifest records hashes of the production/security/scale surface and evidence and is signed with Ed25519.

## Performance interpretation
The benchmark records real hardware measurements. Phase completion is not tied to an arbitrary laptop-specific latency target. Catastrophic hangs, crashes, nondeterminism, cross-job contamination, unbounded resource behavior or failed concurrency gates are blockers; ordinary optimization opportunities are recorded for Phase 3/future work.

`python_peak_alloc_mib` is Python allocator evidence measured with `tracemalloc`. It does not include all native-library allocations. `process_high_water_rss_mib` is a process-lifetime high-water mark from `getrusage`; it is intentionally not described as per-case resident memory.

## COTS interpretation
Phase 2 freezes the capability comparison and a reproducible common benchmark protocol. Quantitative commercial-product accuracy/latency/cost numbers are not invented when vendor accounts/credentials are unavailable. Those measurements, when obtained, belong to Phase 3 evidence and must use the frozen common protocol.

## Accuracy boundary
Broad PII v5 remains the frozen Phase-1 detector. Phase 2 does not reopen the Phase-1 model/holdout loop.
