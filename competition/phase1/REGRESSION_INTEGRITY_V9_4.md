# VeilGraph Phase 1 Regression Integrity v9.4

Purpose: repair three regressions exposed by the first post-TAB full-suite run **without modifying Broad PII v4 or its frozen model surface**.

## Repairs

1. **Historical v3 freeze evidence**
   - The original `competition/HOLDOUT_FREEZE_MANIFEST.json` remains unchanged.
   - A byte-exact v3 detector snapshot is stored under `competition/frozen/broad_pii_v3/`.
   - Historical freeze tests verify that snapshot rather than requiring the live production pipeline to remain v3 forever after later generations are introduced.

2. **DOCX location/component duplication**
   - Broad PII v4 remains frozen.
   - The product routing layer now lets stronger DOCX structural evidence own a complete labelled location span, suppressing v4 component duplicates contained inside it.

3. **DOCX/video title false-person compatibility**
   - Broad PII v4 remains frozen.
   - The product routing layer suppresses recall-oriented `broad-pii-v4:person-context` candidates when the candidate is overwhelmingly document-title vocabulary (for example a support/case/video heading), preventing needless human-review items.

The TAB v4 result remains historical evidence and is not rerun or rewritten by this patch.
