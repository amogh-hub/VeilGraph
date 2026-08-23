# VeilGraph Final Competition Polish 2

Presentation-only hardening based on the full 4:05 judge-flow screen recording.

## Changes
- Fixes stale browser title (`VeilGraph — Slice B` -> `VeilGraph — SIH Competition Build`).
- Makes the human-review gate the only detailed entity section shown by default.
- Moves the full detection inventory behind an explicit technical-inspection control.
- Replaces confusing `0/2 OCR pages` on digital PDFs with `TEXT / digital text layer`.
- Collapses all 12 attack details behind progressive disclosure while keeping the 12/12, 100/100, blocker count, risk, utility, and ALLOW/BLOCK verdict immediately visible.
- Collapses raw cryptographic hashes behind an inspection disclosure while keeping Ed25519 validity and artifact/graph/audit binding visible.
- Tightens the opening viewport so the first action arrives sooner on a laptop projector.
- Simplifies judge-facing section wording without altering privacy/security logic.

No backend, OCR, graph, policy, transformation, verification, signing, audit, proof-package, or destruction logic is modified.
