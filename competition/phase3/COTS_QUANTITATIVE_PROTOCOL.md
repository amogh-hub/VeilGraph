# VeilGraph COTS Quantitative Benchmark Protocol

This protocol closes NTRO's requirement that performance be benchmarked against off-the-shelf solutions without inventing vendor numbers.

## Common corpus and metric

All executed systems receive the **same ordered PIIMB `ai4privacy-en` rows** and are scored using the same character-level, label-agnostic masking metric:

- precision = predicted PII characters overlapping gold / all predicted PII characters
- recall = gold PII characters covered / all gold PII characters
- F1 = harmonic mean of precision and recall
- latency = wall-clock per row and total throughput

The dataset file SHA-256, row count and exact adapter version/status are written into the result.

## Adapters

- **VeilGraph** — frozen Broad PII v5 / Semantic NER v3 pipeline.
- **Microsoft Presidio** — off-the-shelf open-source comparison, if installed in the isolated benchmark environment.
- **AWS Comprehend PII** — commercial COTS adapter, only if valid credentials are explicitly supplied.
- **Azure AI Language PII** — commercial COTS adapter, only if valid credentials are explicitly supplied.

A vendor that cannot be executed is recorded as `NOT_EXECUTED`; no public marketing number is substituted for a controlled result.

## Cost/safety rule

Commercial calls are disabled unless the runner receives the explicit `--allow-commercial-calls` flag. The benchmark must use a deliberately bounded row limit. VeilGraph competition/runtime code remains API-independent; vendor SDKs live only in an isolated benchmark environment.

## Acceptance rule

For literal pre-finale closure, the final evidence should contain:

1. VeilGraph result;
2. at least one off-the-shelf external comparator result; and
3. preferably at least one **commercial COTS** result if credentials are available.

If commercial credentials are unavailable before the internal round, the report must say so explicitly rather than fabricate a comparison.
