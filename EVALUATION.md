# VeilGraph SIH26171 Evaluation

The published evaluation weights are treated as first-class engineering outputs:

1. visual context accuracy — 25%;
2. sensitive/PII recall and precision — 20%;
3. redaction precision — 20%;
4. client resource utilization — 20%;
5. end-to-end latency — 15%.

## Evidence discipline

VeilGraph does not convert privacy-gate pass rates into PII precision/recall.
It does not convert curated metrics into universal claims.
It does not report latency distributions from a single run.

## Visual context

The final scorecard uses a named curated browser grounding corpus containing
one gold task target, distractor controls and sensitive regions. It reports
precision/recall/F1 for correct target preservation.

Live browser perception additionally records DOM, accessibility and visual
capability status, model evidence and local capture timings.

## PII precision/recall

The bundled frozen VeilBench corpus provides explicit gold-span detection metrics.
External datasets, when available, are separately identified.

## Redaction

The browser ROI benchmark measures sensitive-region redaction and preservation of
the required task-safe region. Separate task-minimization of irrelevant pixels is
not counted as a redaction error.

## Resources

The final workflow records:
- aggregate Chrome process-tree RSS/CPU during controlled live loops;
- local privacy pipeline latency;
- packaged UltraFace model footprint.

The aggregate browser measurement is explicitly scoped and not presented as
extension-only memory.

## End-to-end latency

At least five real COMPLETE Chrome secure-agent loops are required. The scorecard
reports p50/p90/p95 from start/end timestamps of the actual controlled loop.

## External boundary

The egress witness proves whether any controlled raw PrismCare canary or forbidden
raw schema field appears in the exact reasoning-server request.

## Final readiness

The generated scorecard remains `RELEASE_READY=false` until all mandatory live,
cross-browser, egress, resource and adversarial evidence exists.
