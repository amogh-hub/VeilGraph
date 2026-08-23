# VeilGraph Final Competition Polish 3

Final judge-time UI compression only. No backend, OCR, graph, transformation, verification, signing, audit, proof-package, or destruction logic is changed.

Changes:
- Human Review Gate moved above the document preview so the required action is immediately visible.
- Level 4 policy list replaced by a compact action-count summary with optional technical disclosure.
- Document preview enlarged for projector readability.
- Protected preview caption changes from `release locked` to `verified for release` after the Red Team passes.
- Review-complete copy no longer says transformation “can proceed” after transformation has already been applied.
- `VERIFIED_SAFE` is displayed as the judge-friendly `VERIFIED SAFE`.
- Duplicate verified-output download action is suppressed once the signed certificate area is available.
- Judge demo script compressed to ~2:15 with technical details collapsed by default.
