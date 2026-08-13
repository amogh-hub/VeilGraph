# VeilGraph — Phase 1 Limitations

## 1. External-domain generalization
Broad PII v5 remains weaker on substantially different unseen PII corpora than on VeilGraph's development/judge corpora.

The ARI synthetic TEST holdout measured:
- Exact F1: 0.4105
- Relaxed F1: 0.4757
- Critical shared recall: 0.5280
- Contextual shared recall: 0.6886

This is the principal accuracy limitation carried forward from Phase 1.

## 2. Benchmark scores are corpus-specific
Showcase, Chaos, TAB and ARI use different data distributions and annotation/taxonomy assumptions. Their raw metric values must not be presented as directly interchangeable leaderboard scores.

## 3. Product scores are not legal anonymity guarantees
Identity Exposure, residual exposure, privacy/utility previews and Synthetic Twin scores are calibrated product evidence. They are not claims of legal anonymity, differential privacy, or mathematical impossibility of re-identification.

## 4. Human review remains intentional
Uncertain person/visual candidates remain fail-closed until reviewed. This is a safety property, not a detector-completeness claim.

## 5. L5 scope
Synthetic Twin is restricted to supported structured datasets (CSV/JSON/XLSX). Unstructured document requests are routed to the strongest appropriate non-L5 privacy level rather than mislabelled as fully synthetic data.

## 6. Future model improvements
Later evidence may justify detector/model improvements. Such work must preserve benchmark provenance and must not retroactively relabel already-consumed holdouts as untouched.
