# VeilGraph Judge Dataset Pack — v1

This pack contains two **strictly separate, fully fictional** datasets for SIH/NTRO evaluation.

## 1. Judge Showcase Dataset

`judge_showcase_v1/`

Purpose: polished, reproducible demonstrations that judges can inspect directly. It contains 11 files spanning native text, digital/scanned PDF, image, DOCX, CSV, JSON, XLSX and MP4. The structured files are suitable for demonstrating L5 Synthetic Twin; non-structured files are for L1-L4.

Use it to show:
- direct + quasi/contextual PII;
- repeated identity and relationship context;
- OCR and visual evidence;
- cross-page/body/header/footer/table behavior;
- video transient/QR evidence;
- L1-L4 privacy trade-offs;
- L5 on CSV/JSON/XLSX;
- annotated evidence and proof-gated release.

## 2. Judge Chaos / Generalization Dataset

`judge_chaos_v1/`

Purpose: deliberately difficult development/regression cases. It contains 12 files with tabs, blank rows, dense inline identifiers, Unicode/mixed script, two-column PDF, low-contrast scans, rotated images, long OCR lines, DOCX routing stress, messy CSV, nested JSON, multi-sheet XLSX and transient video identifiers.

This dataset exists to **find failures**, not to make VeilGraph look good.

## Ground truth

Each split contains:
- `manifest.json` — file hashes, format coverage, use case and stress tags;
- `manifest.sha256` — manifest commitment;
- `ground_truth.jsonl` — entity-level expected labels and logical/physical locators;
- `DATA_CARD.md` — intended use, limitations and contamination rules.

## Evaluation integrity

Neither dataset is an untouched external holdout. They are allowed for development, debugging and regression. Final generalization claims must come from a **new untouched external holdout after Broad PII v4 is frozen**.

Do not merge or relabel the three evidence classes:

1. Showcase → demonstration quality.
2. Chaos → robustness development.
3. Untouched external holdout → scientific validation.
