# VeilGraph — Phase 1 Requirement Traceability

| Problem requirement / evaluation concern | Phase-1 implementation/evidence | Status |
|---|---|---|
| Easy-to-use redaction/anonymization workflow | Single GUI flow: Discover → Transform → Attack → Prove | COMPLETE |
| Gradational user-defined privacy | L1–L5 policy ladder with explainable recommendation | COMPLETE |
| Preserve useful structure while removing identity | Universal Privacy IR, format-aware transforms, privacy/utility preview | COMPLETE |
| Direct identifier detection | Deterministic validators + Broad PII v5 + Semantic NER v3 | COMPLETE |
| Indirect/contextual identity clues | Quasi identifiers + Identity Exposure Graph | COMPLETE |
| Text and image support | Text/document/image pipelines and visual evidence paths | COMPLETE |
| Expanded structured/document formats | TXT/MD/RTF, CSV/JSON/XLSX, PDF, DOCX and existing video path | COMPLETE |
| Offline/no third-party retrievability | Local competition mode; external model calls disabled | COMPLETE |
| User control and human review | Fail-closed review gate and explicit protect/false-positive decisions | COMPLETE |
| Precision/Recall/F1 evaluation | Showcase, Chaos, TAB and ARI evidence packages | COMPLETE |
| Explainability | Entity inventory, source geometry/evidence, IEG reconstruction paths | COMPLETE |
| Gradational calibration | Purpose/recipient/audience/file-type/sensitivity recommendation engine | COMPLETE |
| Synthetic output objective | Genuine L5 Synthetic Twin for structured datasets | COMPLETE |
| Evaluation on unseen data | TAB historical holdout + ARI v5 untouched holdout | COMPLETE |
| Generalization limitations disclosed | ARI/TAB limitations retained, not hidden or overwritten | COMPLETE |
| Regression quality | 237 backend tests + TypeScript + Vite production build | COMPLETE |
