# Fresh external holdout protocol — SPIA PANORAMA test

VeilGraph Broad PII v4 is frozen **before** this dataset is opened. The external source is `spia-bench/SPIA-benchmark`, file `02_spia_panorama_151.jsonl`, identified by its dataset card as a 151-document PANORAMA test subset. SPIA is an English privacy/anonymization benchmark and is inference-aware: it annotates information that can be inferred about data subjects as well as literal surface PII.

VeilGraph therefore reports a strictly defined **taxonomy-overlap, surface-visible** evaluation. A SPIA annotation is scored only when:

1. its tag maps directly to a current VeilGraph detector class; and
2. its annotated keyword literally appears in the document text.

Inference-only PIIs and unsupported labels are counted separately and are not silently treated as false negatives. The external raw JSONL is not bundled into the VeilGraph source package; only aggregate metrics, source SHA-256, freeze SHA-256, and methodology are retained.

The evaluator verifies `BROAD_PII_V4_FREEZE_MANIFEST.json` both before and after the run. Any subsequent modification to a frozen detector/model file invalidates this holdout as evidence for the modified detector and requires a new untouched holdout.
