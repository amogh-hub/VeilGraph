# SIH26171 Requirement Traceability

| Requirement | Final implementation | Baseline reuse | Required evidence | Status at SIH26171 start |
|---|---|---|---|---|
| Client-side browser extension | Manifest V3 extension | none | clean install + browser compatibility | PLANNED |
| Local screen perception | WebGPU/WASM local visual model | OCR/CV concepts | visual context benchmark | PLANNED |
| DOM-based sensitive-data awareness | local semantic DOM capture | text/context detectors | DOM-labelled benchmark | PLANNED |
| Sensitive/PII detection | multimodal fusion + existing hybrid detector | strong | precision/recall/F1 | PARTIAL |
| Visual redaction/obfuscation | local regions + semantic minimization | image/video transforms | leakage/over-redaction benchmark | PARTIAL |
| Sanitization before external request | Browser Privacy Red Team + Network Release Gate | fail-closed artifact release | network capture proving raw context absent | PARTIAL |
| Send only anonymized/unidentifiable context | allow-list release envelope | policy compiler/IEG | payload inspection + adversarial rescan | PARTIAL |
| Server-side LLM/VLM integration | sanitized-context reasoning service | none | end-to-end task success | PLANNED |
| Action returned to browser | typed action schema | none | schema/negative tests | PLANNED |
| Browser executes action | local validated executor | none | task benchmark | PLANNED |
| Chrome support | extension build | none | install/run suite | PLANNED |
| Firefox support | compatible WebExtension build | none | Firefox suite | PLANNED |
| Visual context accuracy 25% | benchmarked fused perception | extraction concepts | accuracy report | PLANNED |
| PII precision/recall 20% | VeilBench-Browser | detectors | class + aggregate metrics | PARTIAL |
| Redaction precision 20% | browser privacy verifier | Red Team pattern | leakage/precision report | PARTIAL |
| Resource utilization 20% | live telemetry + benchmark runner | ops metrics | CPU/RAM/browser/GPU report | PLANNED |
| E2E latency 15% | stage timing instrumentation | ops metrics | median/p95 report | PLANNED |
| VeilGraph differentiation | IEG + task-aware minimization + fail-closed network proof | strong | ablation + judge demo | PARTIAL |
