# VeilGraph — SIH26171 Official-Metric Evidence Scorecard

Generated: `2026-08-25T13:42:53.301856+00:00`

> This is measured engineering evidence against the five published metric categories. It is not an organizer-issued official score.

## 1. Visual context accuracy — 25%
- Precision: **100.00%**
- Recall: **100.00%**
- F1: **100.00%**
- Cases: **12**

## 2. PII precision / recall — 20%
- Precision: **97.70%**
- Recall: **100.00%**
- F1: **98.84%**
- Macro F1: **99.60%**

## 3. Redaction precision — 20%
- ROI precision: **96.00%**
- ROI recall: **100.00%**
- ROI F1: **97.96%**
- Safe task regions preserved: **11/12**

## 4. Client resource utilization — 20%
- Status: **MEASURED_LIVE_BROWSER**
- Chrome baseline RSS: **3061.766 MB**
- Chrome peak RSS: **3144.328 MB**
- Chrome peak delta: **82.562 MB**
- Chrome p95 aggregate CPU: **49.3%**
- UltraFace model: **1.212 MB**

## 5. End-to-end latency — 15%
- COMPLETE Chrome runs: **5**
- p50: **17893.0 ms**
- p90: **31874.2 ms**
- p95: **36435.6 ms**

## External privacy boundary
- Witness requests: **19**
- Raw canary hits: **0**
- Forbidden raw-key hits: **0**
- Status: **PASS**

## Cross-browser
- Chrome COMPLETE: **5**
- Firefox COMPLETE: **1**

## Release gates
- visual_context_accuracy: **PASS**
- pii_precision_recall: **PASS**
- redaction_precision: **PASS**
- client_resource_measured: **PASS**
- e2e_latency_distribution: **PASS**
- external_egress_proof: **PASS**
- chrome_live_validation: **PASS**
- firefox_live_validation: **PASS**
- adversarial_closure: **PASS**
- curated_release_safety: **PASS**

# RELEASE_READY = True
