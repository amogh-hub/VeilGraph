# VeilGraph SIH26171 Engineering Standard

This standard is mandatory for all new SIH26171 code.

## Correctness

- Type all public interfaces.
- Validate every untrusted boundary with explicit schemas.
- No silent exception swallowing in security/privacy paths.
- No mutable global sensitive state unless lifecycle, ownership and destruction are explicit.
- Deterministic decisions wherever AI is not necessary.
- AI/model output is evidence/input, never an implicit authorization primitive.

## Privacy and security

- Fail closed on privacy/security ambiguity.
- Raw browser context is local-only.
- External egress is centralized and policy gated.
- Least privilege for extension/API permissions.
- No `eval`, dynamic remote code, arbitrary shell execution or arbitrary returned JavaScript.
- Cryptographic commitments use canonical serialization.
- Signed decisions bind the exact payload they authorize.
- Sensitive state is bounded in time and memory.
- Logs/telemetry must not reintroduce protected values.

## Interfaces

- Version every network schema.
- Reject unknown critical enum variants rather than guessing.
- Stable local element IDs must never expose raw values.
- External payloads must use allow-list serialization, never dump internal objects.

## Testing

Every security- or privacy-relevant feature requires:

1. unit tests;
2. negative tests;
3. integration tests;
4. adversarial tests;
5. regression fixture(s);
6. benchmark impact where applicable.

A test that only checks the happy path is insufficient for a release-control feature.

## Performance

- Measure before optimizing.
- Collect median and p95 for latency.
- Bound screenshot size, element count, payload size, model memory and processing time.
- Prefer incremental/delta perception after the first page observation.
- No unbounded DOM traversal, JSON serialization or model queue.

## Browser engineering

- Manifest V3.
- Strict CSP.
- Avoid `<all_urls>` host permission when an optional/scoped mechanism suffices.
- Content script performs page-local capture only.
- Service worker owns privileged egress.
- Typed internal messages with runtime validation.
- Frame/navigation changes invalidate stale target handles.
- Shadow DOM and same-origin iframes are handled explicitly; inaccessible cross-origin frames are reported, never silently assumed safe.

## Evidence and claims

- Metrics come from reproducible runners committed to the repository.
- No cherry-picked single-run latency.
- No “100% accuracy” claim unless the exact evaluated scope is named.
- Internal benchmarks are called internal benchmarks.
- Identity Exposure is a calibrated product indicator, not literal re-identification probability.
- Signed release proof proves the recorded checks and payload binding, not universal anonymity.
