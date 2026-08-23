# VeilGraph — RE-DACT Native Text Formats

This completion step adds first-class native text support to the verified VeilGraph competition build without creating a parallel privacy engine.

## Formats
- `.txt` — UTF-8/UTF-16/legacy CP1252 safe decoding, canonical UTF-8 protected export
- `.md` — native Markdown preserved as Markdown, canonical UTF-8 protected export
- `.rtf` — visible content extracted locally and protected output regenerated as canonical metadata-free RTF

All three formats enter the same Universal Privacy IR, identity detection, Identity Exposure Graph, L1–L4 policy compiler, fail-closed human review, transformation, Red Team and signed proof pipeline.

## Security properties
- binary/spoofed text inputs are rejected
- hidden RTF metadata/object destinations do not survive export
- exact character spans are committed and transformed for native text
- visual detectors are not run against text-only sources
- native text uses a format-aware 12-gate Privacy Red Team profile
- original values are checked in decoded text, raw bytes, fragments and hidden markup channels
- non-sensitive lexical utility is measured independently

## Verification target
The prior verified baseline contains 64 tests. This patch adds 8 native-text regression tests.

Expected gate after applying:

```text
72 passed
TypeScript type-check passed
Vite production build passed
```
