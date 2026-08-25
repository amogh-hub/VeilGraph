# SIH26171 Problem-Statement Traceability

| Problem-statement requirement | VeilGraph implementation | Evidence |
|---|---|---|
| Client-side browser component | MV3 extension with service worker/content/UI | extension build |
| Popular browsers: Chrome, Firefox | Chrome package + generated Firefox package | live loop evidence |
| Local visual processing | ONNX Runtime Web/WASM UltraFace + local visual fusion | model/perception contracts |
| Read/evaluate screen state locally | DOM + accessibility + visible screenshot capture | capture contract |
| Detect sensitive/PII dynamically | direct/broad/quasi/credential/visual detectors | VeilBench + privacy tests |
| Blur/black/mask sensitive visual data | flattened local raster sanitization | redaction ROI + visual rescan |
| Sanitize before network request | local privacy compiler + mandatory release gate | release tests |
| Only anonymized/unidentifiable task context transmitted | task-minimal release + egress witness | egress evidence |
| Central LLM/VLM integration | Qwen open-weight reasoner | real secure-loop trace |
| Server aware of redaction scheme | signed typed sanitized payload schema | reasoning validation |
| Server returns browser action | typed BrowserActionPlan | reasoning/action contracts |
| Local client executes action | live-DOM security executor | Chrome/Firefox loop evidence |
| End-to-end task | PrismCare two-action controlled flow | COMPLETE loop samples |
| Balance latency/accuracy | five-metric scorecard + p50/p90/p95 + resource measurement | scorecard |

## Differentiation beyond the minimum

- relationship-aware Identity Exposure Graph;
- task-aware minimization before server release;
- 12 mandatory privacy attack gates;
- Ed25519 payload authorization;
- authenticated encrypted raw localhost transport;
- central authorization replay protection;
- deterministic action confidence separate from privacy minimization;
- independent high-impact confirmation;
- mandatory fresh post-action recapture;
- terminal DONE/WAIT constrained reasoning;
- external egress canary witness;
- claim registry that refuses unsupported final claims.
