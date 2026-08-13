# External Holdout Protocol — TAB (Phase 1 v9.3)

## Why TAB

Broad PII v4 was frozen before any external Phase-1 replacement holdout was evaluated. The prior SPIA acquisition attempts failed at DNS/HTTP transport before any SPIA records were successfully retrieved or scored. The replacement holdout is therefore selected for **availability**, not because of a known result.

The replacement is the official **Text Anonymization Benchmark (TAB) v1.0** repository from Norsk Regnesentral (Norwegian Computing Center), specifically `echr_test.json` on the repository's `master` branch.

TAB is appropriate because it is an open text-anonymization corpus of English ECHR court cases with manually annotated semantic categories, masking decisions, confidential attributes and co-reference relations. Its annotations explicitly distinguish identifiers that should be masked (`DIRECT` / `QUASI`) from `NO_MASK` entities.

## One-shot sequence

1. Verify `BROAD_PII_V4_FREEZE_MANIFEST.json` and every frozen production/model file.
2. Create a temporary directory outside the VeilGraph repository.
3. Shallow-clone the official TAB GitHub repository.
4. Record the exact Git commit before opening `echr_test.json`.
5. Read and SHA-256 hash only the official test file.
6. Validate that all records are test records and that the source is not suspiciously truncated.
7. Run frozen Broad PII v4 once.
8. Score required-to-mask DIRECT/QUASI mentions; report TAB NO_MASK hits separately.
9. Verify the Broad PII v4 freeze again.
10. Persist aggregate results/provenance only; temporary raw source is deleted automatically.

## Metric boundary

VeilGraph reports exact normalized span-value precision, recall, F1 and F2 as a **cross-benchmark** measure. It also reports direct-identifier recall, quasi-identifier recall, per-TAB-category recall, and TAB `NO_MASK` hit rate.

These numbers must **not** be described as the official TAB leaderboard metrics. TAB is a target-person anonymization benchmark, while VeilGraph deliberately uses a broader release-safety policy; therefore some VeilGraph detections may overlap TAB `NO_MASK` entities without being bugs in VeilGraph's policy.

## Scientific integrity rule

After this holdout is evaluated, do not tune Broad PII v4 from TAB examples or scores. If the result identifies weaknesses, preserve the result, develop a future detector version on separate development data, freeze it, and use a different untouched holdout.
