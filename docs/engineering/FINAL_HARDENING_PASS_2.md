# VeilGraph Final Hardening Pass 2

This patch hardens the existing Slice E baseline against ugly real-world inputs without creating a new product slice.

## Added

- orientation-aware local OCR for 90/180/270-degree scans using Tesseract OSD;
- inverse coordinate mapping so protection rectangles still target the original rotated page/image;
- local low-resolution OCR upscaling and autocontrast preprocessing;
- OCR-tolerant email detection when spaces appear around `@` or `.`;
- password/encrypted-PDF rejection before workspace ingestion;
- per-page and total PDF render-pixel budgets;
- standalone-image pixel-decoding budget;
- header-safe filename normalization against path/header injection;
- regression coverage for malformed PDFs and magic/extension mismatches;
- 12-page cross-page mention-consistency test;
- hidden metadata / embedded attachment / hidden-text sanitization regression;
- reproducible offline stress matrix in `backend/run_stress_matrix.py`.

## Security posture

The new resource limits are fail-closed. VeilGraph rejects documents that would exceed bounded local rendering/decoding budgets instead of attempting potentially unsafe processing. Encrypted PDFs are rejected because VeilGraph cannot prove complete privacy transformation over content it cannot inspect.

Rotation handling remains entirely local and does not call an external model or service.

## New authoritative gate

The backend suite now collects **56 tests**. The target Mac must pass:

```text
56 passed
TypeScript type-check passed
Vite production build passed
```

Then run:

```bash
./scripts/run_stress_matrix.sh
```

Required final JSON fields:

```text
"passed": 7
"total": 7
"all_passed": true
```

The stress matrix is synthetic and adversarial. It increases confidence in the tested cases; it is not a guarantee of universal OCR recall or anonymity.
