# PIIMB hardening protocol

1. Preserve the pre-v2 full baseline.
2. Do not modify external PIIMB gold spans.
3. Run the new 12-test broad-PII matrix.
4. Run the full VeilGraph regression gate.
5. Rerun 5,000 `ai4privacy-en` sentences as a smoke measurement.
6. Inspect `diagnostic_by_gold_label` for remaining recall gaps.
7. Rerun all 18,538 `ai4privacy-en` sentences on the same dataset file.
8. Generate `PIIMB_BEFORE_AFTER.md` with the comparator.
9. Accept v2 only if external recall/F2 improves materially without an unacceptable precision/FPR collapse and all existing security/release tests remain green.
10. If recall is still inadequate, do not tune on the PIIMB gold test labels. Build the next semantic model using separate public training data, disclose the training source, and rerun PIIMB unchanged.
