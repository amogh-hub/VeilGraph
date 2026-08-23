# SIH26171 Verification Harness

VeilGraph uses one verification entry point for local engineering checkpoints and CI:

```bash
./scripts/verify_sih_checkpoint.sh
```

The command runs the extension security/build gates, perception contract checks, Python↔browser interoperability, focused browser/privacy tests, full backend regression, frontend checks, deterministic API generation, and Git diff-integrity checks.

Detailed command output is written to `artifacts/verification/logs/`. The compact machine-readable result is written to:

```text
artifacts/verification/latest.json
```

This directory is intentionally ignored by Git. A failed checkpoint should be diagnosed from the JSON report and only the referenced failed-gate logs; developers should not need to copy the entire terminal transcript.

## Modes

- `./scripts/verify_sih_checkpoint.sh` — full local validation.
- `./scripts/verify_sih_checkpoint.sh --quick` — focused iteration gate; skips only the full backend regression and reports `QUICK_PASS`, never `VALIDATED`.
- `./scripts/verify_sih_checkpoint.sh --ci` — full validation plus a clean-checkout requirement after generated/build outputs are reproduced.
- `./scripts/verify_sih_checkpoint.sh --list` — lists gates without executing them.

A component is not `VALIDATED` merely because this harness exists. The harness is evidence infrastructure: each checkpoint still needs the relevant tests and benchmarks for the SIH26171 requirement it claims to satisfy.
