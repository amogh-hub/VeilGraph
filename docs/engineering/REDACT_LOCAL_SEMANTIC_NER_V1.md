# VeilGraph Local Semantic NER v1

This phase adds a local semantic span-classification layer for sensitive entities that are often missed by label/regex-only extraction: prose person names, street addresses, employers and job titles.

## Design boundary

- Runtime is fully offline and makes no API/network calls.
- Candidate spans are generated conservatively from sentence context.
- A frozen local linear logistic classifier scores each candidate using contextual NLP features.
- The model has explicit version and independent synthetic-training-corpus provenance.
- Semantic person-name detections are fail-closed into human review.
- Existing deterministic identifiers remain authoritative for high-structure IDs.
- Aadhaar-like detection is context-hardened against software/build-version false positives; it does not claim UIDAI authenticity.

## Benchmark discipline

The existing VeilBench Curated Identity Exposure Corpus v1 is hash-frozen. This patch does not modify it. The same corpus must be rerun before and after semantic integration so any improvement is measured against unchanged ground truth.

The internal curated benchmark remains an engineering regression corpus, not the NTRO-required external open-source testing dataset. That requirement stays open until the external benchmark is actually run and reported.
