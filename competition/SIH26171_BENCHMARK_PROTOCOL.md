# SIH26171 Final Benchmark Protocol

VeilGraph maps the five published evaluation categories to explicit, reproducible
measurements. It does **not** fabricate an organizer-issued SIH score.

## 1. Accuracy of visual context from screen — 25%

Primary curated metric: correct preservation of the unique task-relevant browser
target from a complete local browser capture containing sensitive fields and
distractor controls.

Reported: Precision, Recall and F1.

Boundary: this is a named browser-screen grounding benchmark, not a universal
computer-vision accuracy claim.

## 2. Recall and precision for sensitive / PII detection — 20%

Primary bundled metric: frozen VeilBench curated detector corpus with explicit
gold spans.

Reported: Precision, Recall, F1 and Macro-F1. External PIIMB/OpenPII results, when
run, remain separately named and are never relabelled as the bundled benchmark.

## 3. Precision of redaction — 20%

Curated browser cases define two sensitive ROIs and one required safe-task ROI.

- sensitive ROI redacted = true positive;
- sensitive ROI left visible = false negative;
- required safe-task ROI redacted = false positive.

Irrelevant-context minimization is a separate privacy mechanism and is not
mislabelled as a redaction false positive.

## 4. Client-side resource utilization — 20%

Evidence combines:
- aggregate Chrome process-tree RSS/CPU sampled during real controlled loops;
- local privacy-pipeline median/P95;
- packaged UltraFace model footprint.

The browser-process measurement is explicitly not represented as extension-only
RSS.

## 5. Overall end-to-end latency — 15%

Only real `SECURE_AGENT_LOOP_V1` results with `status=COMPLETE` are accepted.
Five Chrome runs are required before p50/p90/p95 is treated as a distribution.

## External egress privacy proof

`egress_witness.py` observes the exact serialized extension → reasoning-server
request. It checks all eight controlled PrismCare raw canaries and forbidden
raw/local-only schema keys, then proxies the exact request to the real reasoner.

Raw request bodies are never persisted.

## Release rule

`RELEASE_READY` requires:
- measured visual grounding;
- measured PII precision/recall;
- measured redaction precision/recall;
- live browser resource evidence;
- >=5 real Chrome COMPLETE loops;
- >=1 real Firefox COMPLETE loop;
- live egress proof with zero raw-canary/raw-key hits;
- adversarial closure;
- full 17-gate repository verification.

Missing evidence is reported as missing. It is never converted into an assumed
score.
