# VeilGraph Frozen-Detector Holdout — Nemotron-PII

Generated: 2026-08-09T08:53:17.205181+00:00

## Evaluation integrity

- Detector frozen before evaluation: **True**
- Frozen detector: **Broad-Coverage PII Engine v3**
- Locked production files verified: **49/49**
- Frozen source snapshot SHA-256: `89d6a287c71b6d4010d5e40100dc0a0f22b89e743ab912011ecf6b665713b01d`
- Benchmark input SHA-256: `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f`
- Holdout feedback policy: **results are evidence only; Broad PII v3 must not be tuned from this task**.

## Holdout result

- Task: **nemotron-pii**
- Rows scored: **77907**
- Characters scored: **4737260**
- Precision: **85.52%**
- Recall: **32.81%**
- F1: **47.43%**
- F2: **37.42%**
- Character FPR: **0.84%**
- Median latency: **0.662 ms/sentence**
- P95 latency: **1.605 ms/sentence**
- Throughput: **1205.041 sentences/s**

## Claim boundary

This is post-freeze generalization evidence on the named external task. It is not a universal accuracy or anonymity guarantee. The detector was frozen before this task was evaluated, and the result must not be used to tune Broad PII v3.

## Post-freeze label diagnostics

The JSON result contains `diagnostic_by_gold_label`. These diagnostics are recorded only after the frozen evaluation and do not alter the official label-agnostic masking scores.
