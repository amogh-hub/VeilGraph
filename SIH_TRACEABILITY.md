# SIH260381 — RE-DACT Traceability

**Organization:** NTRO  
**Theme:** Blockchain & Cybersecurity  
**Type:** Software

This is the public/judge-readable index. The signed pre-Grand-Finale evidence matrix remains at [`competition/phase3/SIH260381_FINAL_TRACEABILITY.md`](competition/phase3/SIH260381_FINAL_TRACEABILITY.md).

`CLOSED` means implemented with executable/release evidence in the frozen pre-Grand-Finale build. The only item that cannot be executed before the event is the NTRO-provided private Stage-2 dataset evaluation.

| RE-DACT requirement | VeilGraph implementation / evidence | Status |
|---|---|---|
| Secure redaction / masking / anonymization | Browser workflow + L1–L5 compiler + review + fail-closed verification | **CLOSED** |
| User-defined privacy gradation | L1 direct masking → L5 Synthetic Twin | **CLOSED** |
| Increasing degree increases protection scope | Same-source gradation calibration proves non-decreasing intervention/context coverage | **CLOSED** |
| Customized output | Audience + purpose + privacy-level compilation | **CLOSED** |
| NLP / ML | Broad PII v5 + local Semantic NER v3 + deterministic detection fusion | **CLOSED** |
| Preserve logical structure/usefulness | Native format transformers + schema/structure/utility gates | **CLOSED** |
| Strip direct and indirect clues | Direct/quasi/contextual/visual detection + Identity Exposure Graph | **CLOSED** |
| Obfuscate correlations by degree | L3 generalization + L4 relationship-safe pseudonymization + L5 source-independent synthesis | **CLOSED** |
| Easy GUI | React/TypeScript review, graph, policy, verification and release workflow | **CLOSED** |
| Offline + online operation | localhost offline mode + real TLS secure-online acceptance | **CLOSED** |
| Common formats | TXT/MD/RTF, PDF/scanned PDF, DOCX, images, CSV/JSON/XLSX, MP4/MOV | **CLOSED** |
| No third-party retrieval / user control | local operational processing, encrypted workspaces, egress boundary, explicit retention/destruction | **CLOSED** |
| Authenticated output | SHA-256 commitments + Ed25519 certificate/proof package | **CLOSED** |
| Gradation up to realistic synthetic data | L5 Synthetic Twin for structured datasets | **CLOSED** |
| Synthetic data in useful sought representation | verified synthetic population export to CSV/JSON/XLSX/DOCX/PDF | **CLOSED** |
| Own Stage-1 curated data | Judge Showcase v1 + Judge Chaos v1 | **CLOSED** |
| Text/images/basic output/logs | implemented and covered by fixtures/evidence | **CLOSED** |
| Web version | browser application; secure-online acceptance | **CLOSED** |
| P/R/F1 evaluation | bundled evaluation pipeline + frozen external evidence + COTS benchmark | **CLOSED** |
| PDFs/videos | digital/scanned PDF and MP4/MOV implemented | **CLOSED** |
| Annotated outputs | separate evidence exports bound to verified artifact | **CLOSED** |
| Efficacy of anonymization | transform + independent Privacy Red Team + release lock | **CLOSED** |
| Minimal retention | TTL/manual destruction + encrypted workspace + signed tombstone | **CLOSED** |
| Speed / compute / scale | p50/p95, CPU, memory, throughput and concurrent-job isolation evidence | **CLOSED** |
| UI / UX | final judge workflow | **CLOSED** |
| COTS comparison | identical-row Presidio + commercial Azure execution | **CLOSED** |
| Minimal external API dependency | no mandatory external AI inference API | **CLOSED** |
| Secure coding / cybersecurity by design | auth/TLS, egress control, encrypted workspace, package integrity, bounded inputs, signed proof | **CLOSED** |
| Model learns over time | approved labels → versioned corpus → offline candidate retraining → independent eval → new signed freeze | **CLOSED** |
| NTRO Stage-2 private dataset | frozen pipeline to be evaluated when NTRO supplies data at Grand Finale | **PENDING EXTERNAL DATA** |

## Important boundaries

- Operational uploads are **not** silently used as training data.
- L5 is real structured-data synthesis, not a claim of arbitrary generated image/video synthesis.
- `VERIFIED_SAFE` means the artifact passed the implemented mandatory gates; it is not a universal anonymity theorem.
- The COTS benchmark is isolated evaluation tooling, not an operational cloud dependency.
