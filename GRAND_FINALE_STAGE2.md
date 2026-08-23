# NTRO Grand Finale Stage-2 Evaluation Protocol

The only externally pending VeilGraph requirement is evaluation on the private NTRO Stage-2 dataset when NTRO supplies it.

## Non-negotiable rules

- preserve the pre-Grand-Finale frozen build before touching private data;
- do not silently add NTRO uploads to training data;
- hash and inventory the received dataset before evaluation;
- run the frozen pipeline first and record baseline metrics before any permitted adaptation;
- keep any permitted adaptation versioned and separately evaluated;
- never tune on a consumed final holdout and then describe it as untouched.

## Procedure

```text
Receive private dataset
  ↓
Record source/package SHA-256 + access boundary
  ↓
Offline format inventory and ingestion validation
  ↓
Run frozen VeilGraph pipeline
  ↓
Compute required Precision / Recall / F1 (+ F2/FPR where labels permit)
  ↓
Measure redaction/anonymization efficacy + release-gate outcomes
  ↓
Measure latency / throughput / resource behavior
  ↓
Create error taxonomy without modifying the frozen baseline result
  ↓
If NTRO permits adaptation:
  approved labels → new versioned corpus/candidate model → independent evaluation
  ↓
Run final evaluation on a still-unconsumed holdout split
  ↓
Generate signed Stage-2 report + hashes + claim boundaries
```

## Required report sections

1. dataset provenance/hash and format distribution;
2. evaluation protocol and split integrity;
3. P/R/F1 (and supporting metrics where appropriate);
4. per-format efficacy / Red Team results;
5. speed/scale evidence;
6. error taxonomy;
7. baseline-vs-adapted comparison if adaptation is allowed;
8. exact model/build version and signed evidence;
9. limitations and unresolved failure modes.

## Training boundary

VeilGraph's controlled learning lifecycle is **approved feedback → versioned corpus → offline retraining → independent evaluation → signed promotion**. Sensitive operational uploads are never silently turned into training data.
