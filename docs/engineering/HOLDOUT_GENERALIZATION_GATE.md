# Frozen-Detector Generalization Gate

This patch adds **evaluation tooling only**. It does not modify `backend/app/`, the semantic model, policy compiler, Identity Exposure Graph, transformation engine, or Red Team.

## Why this exists

Broad-Coverage PII Engine v3 was frozen after the full Ai4Privacy-English PIIMB development/regression run. The next evidence point must therefore be produced without changing detection logic.

The holdout runner:

1. verifies SHA-256 for every production Python file under `backend/app/` plus the frozen semantic model;
2. verifies the exact PIIMB JSONL SHA-256 already used in the v3 evidence run;
3. evaluates only task `nemotron-pii`;
4. verifies the production hashes again after evaluation;
5. writes separate `HOLDOUT_NEMOTRON_RESULTS.json` and `HOLDOUT_NEMOTRON_REPORT.md` files;
6. explicitly records that holdout feedback may not be used to tune Broad PII v3.

This makes the second source a genuine **post-freeze generalization measurement** rather than another tuning loop.

## Run

```bash
./scripts/run_holdout_nemotron.sh ~/Downloads/test_sentences.jsonl
```

Do not modify detector code before or after this run. If the lock does not match, the benchmark refuses to execute.
