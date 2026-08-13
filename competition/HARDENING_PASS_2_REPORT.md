# Final Hardening Pass 2 — Stress Evidence

VeilGraph was exercised against seven synthetic adversarial classes after Final Hardening Pass 1.

| Stress case | Required behavior | Build-time result |
|---|---|---|
| 90° rotated identity scan | auto-orient locally and recover key identifiers | PASS |
| 12-page repeated identity document | retain every cross-page occurrence | PASS |
| AES-256 password-protected PDF | reject before ingestion | PASS |
| extreme PDF page geometry | reject before rasterization | PASS |
| malformed PDF object graph | fail closed | PASS |
| path/CRLF-style filename | normalize to header-safe basename | PASS |
| hidden metadata + attachment + hidden identifier | scrub from protected PDF | PASS |

The exact machine-readable run is stored in `competition/stress-matrix-results.json` and can be regenerated offline with:

```bash
./scripts/run_stress_matrix.sh
```

### Boundaries

This matrix is intentionally reproducible and synthetic. It does not claim perfect OCR on every camera capture, handwriting, language, corruption level, or future adversarial PDF parser behavior. Unsupported or over-budget inputs are rejected rather than silently processed.
