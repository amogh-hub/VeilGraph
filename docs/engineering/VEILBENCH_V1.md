# VeilGraph — VeilBench v1.0

VeilBench v1.0 separates three different questions that must not be conflated:

1. **Detection accuracy** — Precision, Recall and F1 on labelled data.
2. **Standardized masking performance** — character-level Precision, Recall, F1, F2 and FPR on an external open-source benchmark.
3. **Release safety** — whether the transformed artifact passes VeilGraph's adversarial Privacy Red Team and cryptographic release gate.

## Bundled curated corpus

`backend/benchmark_corpus/veilbench_curated_v1.json`

- 32 fictional cases
- 85 labelled sensitive spans
- 13 currently claimed textual entity classes
- deliberate negative cases
- deliberate context/NER challenge cases
- CC0-1.0 project corpus
- no real PII

Run only the fast local accuracy benchmark:

```bash
./scripts/run_veilbench_accuracy.sh
```

## Standardized open-source benchmark

VeilBench supports the **PIIMB PII Masking Benchmark** `sentences` JSONL schema.
PIIMB is not bundled with VeilGraph. The benchmark corpus must be obtained separately and its own license/attribution terms followed.

Run:

```bash
./scripts/run_veilbench_piimb.sh /path/to/piimb-sentences.jsonl 5000
```

By default VeilGraph scores the `ai4privacy-en` task. The evaluator is label-agnostic and uses character-level masking metrics:

- Precision
- Recall
- F1
- F2
- FPR over non-PII characters

Negative rows are retained because they are required to measure over-redaction/FPR.

## Optional OpenPII entity-type benchmark

VeilBench also contains an adapter for Ai4Privacy OpenPII JSONL. Only labels that map to VeilGraph's claimed entity taxonomy are scored; every unmapped label is counted and disclosed.

```bash
./scripts/run_veilbench_openpii.sh /path/to/openpii.jsonl 500
```

## Full benchmark

```bash
./scripts/run_veilbench.sh
```

This runs the curated accuracy corpus plus the slower end-to-end PDF/OCR release evidence cases.

## Output

- `competition/veilbench-results.json` — machine-readable evidence
- `competition/VEILBENCH_REPORT.md` — judge/auditor-readable report

## Claim boundary

A benchmark score applies only to the named corpus, task, sample, code revision and environment used to produce it. A high F1 score is not an anonymity guarantee, and a 12/12 Privacy Red Team result is not presented as an accuracy metric.
