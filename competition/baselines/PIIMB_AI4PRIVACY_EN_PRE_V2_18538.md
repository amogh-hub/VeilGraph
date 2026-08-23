# PIIMB ai4privacy-en baseline · pre Broad-Coverage PII v2

This file freezes the external benchmark result already produced by the verified 104-test VeilGraph build **before** Broad-Coverage PII Engine v2 is applied.

It is retained so later improvements can be shown as a same-benchmark before/after comparison rather than replacing the weak baseline.

## Baseline

- Task: `ai4privacy-en`
- Rows scored: **18,538**
- Characters scored: **1,774,805**
- Gold mask spans: **38,481**
- Predicted mask spans: **6,800**
- Exact mask matches: **6,060**
- Precision: **0.982660**
- Recall: **0.243798**
- F1: **0.390671**
- F2: **0.286950**
- FPR: **0.001229**
- TP characters: **96,168**
- FP characters: **1,697**
- FN characters: **298,289**
- Throughput: **960.437 sentences/s**
- P95 latency: **2.092 ms/sentence**
- Peak process RSS: **179.422 MB**

## Claim boundary

These are corpus-specific external masking metrics. They are not a claim of universal accuracy or anonymity. The original baseline report did not record the external file SHA-256; v2 adds automatic dataset hashing so subsequent runs bind the measurements to the exact benchmark bytes.
