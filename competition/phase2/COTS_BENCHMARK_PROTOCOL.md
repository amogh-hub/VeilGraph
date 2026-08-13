# VeilGraph — Frozen COTS Quantitative Benchmark Protocol

## Purpose
NTRO explicitly asks for performance benchmarked against COTS solutions. Phase 2 therefore freezes the protocol now, before any vendor measurements are observed, so later Phase-3 comparison cannot be quietly redesigned around whichever result looks best.

## Claim boundary
This protocol does **not** invent vendor Precision/Recall/F1, latency, price, compliance or availability. A vendor/product row is quantitative only after the same frozen evaluation corpus and taxonomy have actually been executed against that product under a documented account/configuration.

## Common corpus
Use a separately versioned comparison corpus that is not a consumed VeilGraph model-development holdout. Record:
- corpus name/version;
- source and license/usage permission;
- SHA-256 of the exact evaluation file(s);
- row/document count;
- format distribution;
- language/domain distribution;
- entity-label distribution.

Do not use TAB, ARI or any other consumed Phase-1 holdout as development data.

## Common entity mapping
Before running any product, freeze a mapping from each product's native labels into the common benchmark taxonomy. Unmappable labels are reported as `UNMAPPED`, not silently discarded or reinterpreted after results are known.

## Accuracy metrics
For products that return entity spans/regions, measure on the same ground truth:
- Precision;
- Recall;
- F1;
- F2;
- False-positive rate where a defensible denominator exists;
- per-entity Precision/Recall/F1;
- macro and micro summaries.

Record both strict-span and normalized-overlap matching if both are used; never mix them in one headline number.

## Performance metrics
On the same executing client machine and network condition, record where technically meaningful:
- request/input bytes;
- end-to-end wall latency p50/p95;
- documents or KiB per second;
- retries/errors/timeouts;
- local CPU/RAM only for locally executed products;
- network condition and region for cloud products.

Cloud latency is not compared to local CPU usage as though they are the same resource boundary.

## Privacy/deployment capability matrix
Separately record qualitative capabilities such as:
- local/offline availability;
- text/structured/image/PDF/DOCX/video support;
- configurable transformations;
- relationship-aware reconstruction analysis;
- synthetic-data workflow;
- fail-closed independent verification;
- signed release proof/audit evidence;
- retention/destruction controls.

Qualitative capability rows are not converted into fake accuracy points.

## Reproducibility record
Each quantitative product run must preserve:
- product/version or API version;
- configuration and enabled detectors;
- date/time;
- region/end-point class without storing credentials;
- corpus SHA-256;
- mapping-table SHA-256;
- raw machine-readable outputs where licensing/security permits;
- evaluation script SHA-256;
- final results SHA-256.

## Phase-3 rule
If commercial credentials are unavailable before submission, present the capability comparison and this frozen protocol, explicitly marking quantitative vendor measurements as **NOT EXECUTED**. Do not fabricate or borrow marketing accuracy claims as if independently measured by VeilGraph.
