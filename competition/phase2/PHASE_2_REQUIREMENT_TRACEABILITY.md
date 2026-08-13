# VeilGraph — Phase 2 Requirement Traceability

| Evaluation concern | Phase-2 evidence/control | Completion evidence |
|---|---|---|
| Speed | Machine-measured steady-state wall-clock p50/p95 and throughput | `PHASE2_BENCHMARK_RESULTS.json` |
| CPU efficiency | Per-case process CPU p50/p95 and CPU core-equivalent ratio | benchmark report |
| Memory | Per-case Python allocator peak + explicitly labelled process lifetime high-water RSS | benchmark report |
| Scalability | 4-worker deterministic detector probe + 4 concurrent isolated API/DB/encrypted-workspace analysis jobs + bounded heavy-request admission | benchmark + production tests |
| Larger inputs | 64 KiB full detection, 8 MiB ingestion, 5,000-row structured extraction and 5-page PDF extraction plus configured hard limits | benchmark + regression |
| Offline operation | localhost boundary + DNS/socket egress guard + zero external model calls | security self-test |
| Secure online option | explicit HTTPS + bearer token; forwarded HTTPS trusted only from configured proxy networks | production security tests + self-test |
| Minimal API dependency | offline mode remains the competition default | configuration + status endpoint |
| Cybersecurity by design | request boundary, security headers, archive hardening, secret-free release builder | tests + self-test |
| Proof integrity | Ed25519 evidence retained; proof ZIP path/size/compression safety hardened | proof regression + Phase-2 tests |
| Retention/destruction | existing automatic/manual/restart-key-loss lifecycle retained | retention regression |
| Operational observability | configurable PII-free request metrics, p50/p95, errors, admission state, DB quick check | `/api/v1/ops/status` |
| Failure recovery | RAM-key restart destruction + SQLite quick check + bounded admission | regression + self-test |
| COTS comparison | capability comparison plus frozen common quantitative benchmark protocol; no fabricated vendor measurements | `COTS_CAPABILITY_COMPARISON.md` + `COTS_BENCHMARK_PROTOCOL.md` |
| Sanitized final package | deterministic release builder excludes keys/DB/cache/env/workspaces; exact archive member-set verification | release package report |
| Regression closure | pytest + OpenAPI + TypeScript + Vite evidence combined into computed `all_passed` | `PHASE2_FULL_REGRESSION.json` |
| Phase-1 preservation | Broad PII v5 22-file freeze and Phase-1 closure manifest reverified before/after Phase 2 | freeze verifier |
