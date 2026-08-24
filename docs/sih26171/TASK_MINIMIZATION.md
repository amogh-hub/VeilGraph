# TASK_MINIMIZATION_V1 — Browser Context Minimization Contract

Status target: **VALIDATED** only after the full SIH26171 verification harness passes.

## Purpose

VeilGraph must not treat redaction as permission to transmit an entire page. After
privacy compilation, the browser release path derives the smallest semantic and
visual context that still preserves the user's task.

## Contract

1. Classify the sanitized task into CLICK, TYPE, SELECT, READ, NAVIGATE, SUBMIT, or GENERAL.
2. Score visible DOM/accessibility elements against task tokens and role compatibility.
3. Select a small set of required task anchors.
4. Add only nearby/relevant dependency anchors needed to interpret those controls.
5. Drop unrelated controls, including unrelated sensitive controls.
6. Preserve viewport coordinates but mask every pixel outside retained task regions.
7. Apply privacy redactions before visual minimization, then encode a fresh flattened raster.
8. Record semantic, visual, and conservative overall minimization evidence.
9. Independently verify the exact candidate payload with the existing 12-gate Browser Privacy Red Team.
10. FAIL or INCONCLUSIVE still denies network release.

## Evidence

`BrowserMinimizationEvidence` records:

- raw / candidate / released / dropped element counts;
- required and dependency anchor IDs;
- task intent;
- semantic, visual, and overall minimization basis points;
- task-token coverage;
- actionability preservation;
- utility sufficiency;
- retained visual-region count.

`overall_minimization_basis_points` is deliberately conservative: it is the lower
of semantic and visual minimization, not an average that could hide a weak side.

## Security properties

- Sensitive values are sanitized before relevance scoring.
- Compiler placeholders such as `[EMAIL PROTECTED]` are excluded from task-token relevance.
- Generic clickable controls do not survive merely because they are actionable.
- Sensitive controls with no task overlap are penalized unless an explicit input/select task needs them.
- The full screenshot is never restored after minimization; non-retained pixels are opaque.
- The exact minimized raster remains bound into the signed release-payload commitment.

## Claim boundary

This checkpoint validates the minimization mechanism and its regression tests. It
does **not** by itself establish final SIH benchmark scores for task utility, resource
usage, visual accuracy, PII recall/precision, redaction precision, or end-to-end latency.
