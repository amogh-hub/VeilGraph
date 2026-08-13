# PIIMB before / after

Comparable task + row count: **YES**

| Metric | Pre-v2 | Current | Delta |
|---|---:|---:|---:|
| PRECISION | 98.266% | 94.127% | -4.139 pp |
| RECALL | 24.380% | 56.574% | +32.194 pp |
| F1 | 39.067% | 70.672% | +31.605 pp |
| F2 | 28.695% | 61.480% | +32.785 pp |
| FPR | 0.123% | 1.009% | +0.886 pp |

- Task: `ai4privacy-en`
- Rows: **18538**
- Current dataset SHA-256: `5ff46f3a80316318794f94596fa374060d70f2f32a85909f958cbabc70bae41f`
- Baseline dataset SHA-256: `not recorded by pre-v2 runner`

## Interpretation guardrail

An improvement is accepted only together with the full VeilGraph regression/security gate. Recall/F2 improvement obtained by indiscriminate masking is not sufficient; precision and FPR remain visible in the same report.
