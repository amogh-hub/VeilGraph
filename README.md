<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="frontend/public/veilgraph-brand-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="frontend/public/veilgraph-brand-light.png">
    <img alt="VeilGraph" src="frontend/public/veilgraph-brand-light.png" width="540">
  </picture>
</p>

# VeilGraph

**Relationship-aware privacy intelligence for SIH260381 — RE-DACT (NTRO).**

> Traditional redaction asks which obvious identifiers should be removed.  
> **VeilGraph asks whether identity can still be reconstructed from what remains.**

**Status:** `PRE-GRAND-FINALE COMPLETE & FROZEN` · final canonical regression: **268 passed, 0 failed** · only the NTRO Stage-2 private dataset evaluation remains externally pending.

VeilGraph is a local-first privacy compiler that combines deterministic PII detection, a lightweight offline semantic NER model, an **Identity Exposure Graph (IEG)**, user-selectable **L1–L5 privacy gradation**, native multi-format transformation, a fail-closed **Privacy Red Team**, and cryptographic release evidence.

## Understand → Protect → Verify → Release

```text
Input
  ↓
Local extraction / OCR / vision / schema-aware parsing
  ↓
Direct + quasi + contextual + visual identifier detection
  ↓
Human review for uncertain sensitive candidates
  ↓
Identity Exposure Graph
  ↓
Audience + purpose + L1–L5 privacy compilation
  ↓
Native protected artifact or L5 Synthetic Twin
  ↓
Format-specific fail-closed Privacy Red Team
  ↓
VERIFIED_SAFE / RELEASE_BLOCKED
  ↓
SHA-256 audit commitments + Ed25519 proof certificate/package
  ↓
Retention expiry / explicit destruction + signed tombstone
```

## Why VeilGraph is different

VeilGraph treats privacy as a **relationship problem**, not only a regex/NER problem. A locality, employer, age band, job title, event date, related person, or repeated identifier may be weak in isolation but highly identifying when linked. The IEG makes those relationships visible and the policy compiler changes how they are protected according to audience, purpose and privacy level.

The release decision is deliberately separated from detection and transformation. A model may nominate a sensitive span, but it cannot issue `VERIFIED_SAFE`, authorize a download, or sign proof. Release remains deterministic and fail closed.

## Privacy gradation

| Level | Name | Core behavior |
|---|---|---|
| **L1** | Direct masking | Masks direct identifiers; retains lower-risk context. |
| **L2** | Sensitive-entity protection | Replaces high-impact identity/credential fields with opaque stable tokens. |
| **L3** | Context generalization | Masks direct identifiers and generalizes quasi-identifying context. |
| **L4** | Relationship-safe pseudonymization | Stable pseudonyms preserve useful relationships while exact contextual clues are generalized. |
| **L5** | Synthetic Twin | For structured CSV/JSON/XLSX data, generates a new local synthetic population and verifies source independence/utility before release. |

L5 is intentionally **not** a claim of differential privacy or a universal anonymity guarantee. For non-dataset inputs, an L5 request fails closed rather than pretending pseudonymization is synthetic-data generation.

## Supported formats

**Inputs:** PDF, scanned PDF, PNG/JPG/JPEG, TXT, Markdown, safe RTF, DOCX, CSV, JSON, XLSX, MP4 and MOV.

**L5 Synthetic Twin source formats:** CSV, JSON and XLSX. A verified Synthetic Twin can additionally be exported into useful representations including CSV, JSON, XLSX, DOCX and PDF.

All formats feed the same downstream privacy model through a format-neutral privacy representation rather than independent ad-hoc redaction pipelines.

## Fail-closed verification

VeilGraph attacks its own protected output before allowing release:

- **12 mandatory gates** for non-video L1–L4;
- **13 mandatory gates** for video, including full-timeline/visual/audio checks;
- **15 mandatory gates** for structured L5 Synthetic Twin outputs.

The gates include independent extraction, secondary parser/OCR rescans, hidden-channel checks, region/replacement integrity, metadata inspection, policy coverage, relationship consistency, raw-object/byte scanning, direct-identifier fragment attacks, structure preservation and format-specific attacks. Any mandatory `FAIL` or `INCONCLUSIVE` result keeps the output `RELEASE_BLOCKED`.

## Security model

- local competition inference; no mandatory external AI/model API;
- AES-256-GCM encrypted per-job workspace blobs;
- random per-job master keys with HKDF-derived encryption/fingerprint keys;
- RAM-only job-key custody and fail-safe deletion after restart key loss;
- HMAC-SHA256 normalized entity fingerprints;
- SHA-256 tamper-evident audit chain;
- Ed25519 device signatures for privacy proof and destruction receipts;
- user-selected retention window plus automatic expiry worker;
- secure-online mode requires bearer authentication and HTTPS;
- offline-mode Python egress guard;
- bounded file/page/pixel/video/proof-package admission limits.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## Final acceptance evidence

| Evidence | Final result |
|---|---|
| Complete backend regression | **268 passed, 0 failed**; TypeScript typecheck and Vite production build passed |
| Native TXT defect fixture | **12/12**, `100/100`, `VERIFIED_SAFE`, 0 critical blockers |
| Digital PDF defect fixture | **12/12**, `100/100`, `VERIFIED_SAFE`, 0 critical blockers |
| Scanned PDF defect fixture | **12/12**, `100/100`, `VERIFIED_SAFE`, 0 critical blockers |
| Phase-2 security self-test | **9/9 passed** |
| Same-source L1–L5 calibration | all levels executed; all release gates passed; protection scope non-decreasing |
| COTS identical-row benchmark (100 PIIMB rows) | VeilGraph F1 **0.8362**; Presidio **0.6750**; Azure AI Language PII **0.7421** |
| Frozen external Nemotron holdout | Precision **85.52%**, Recall **32.81%**, F1 **47.43%**, FPR **0.84%** |

The Nemotron result is intentionally reported despite weak recall. It is untouched post-freeze generalization evidence and **must not be used to tune the frozen detector**.

Detailed evidence: [EVALUATION.md](EVALUATION.md) and [`competition/`](competition/).

## Authoritative pre-Grand-Finale freezes

```text
Phase 1
53701b65c668b181f1432783ea8bfe03b4b91821c1efe5a61aa2d431e3e55040

Phase 2
843ebc8f64fe5c906bc330a96a912d2c4c0d80b3b8a9a93e91f89aba05930042

Pre-Grand-Finale
864781e4eb48c23fe2cae8477427d146aa38814d47708676bd6cc7d7a71bdf6c
```

The signed manifests are under [`competition/final/`](competition/final/). This GitHub-oriented tree is a **sanitized public/judge copy**: device private keys, runtime databases/workspaces, dependency environments, the generated 138 MB competition archive, and raw machine-local regression logs are intentionally omitted. See [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md) for the provenance boundary and public verification command.

## Quick start

### Requirements

- macOS or Linux
- Python 3.11+
- Node.js 18+
- Tesseract OCR
- Poppler (`pdftotext`)

On macOS:

```bash
brew install python node tesseract poppler
```

### Install dependencies once

```bash
chmod +x scripts/*.sh
./scripts/setup_once.sh
```

Dependency installation requires network access. VeilGraph's judged offline runtime does not.

### Run the regression gate

```bash
./scripts/run_checks.sh
```

### Start local competition mode

```bash
./scripts/start_local.sh
```

Open `http://127.0.0.1:5173`.

For an offline demonstration, complete setup first, disconnect network access, then start VeilGraph. `start_local.sh` does not install packages or download models.

## Reproducible judge fixtures

Primary multi-format fixtures live in [`competition/datasets/judge_showcase_v1/`](competition/datasets/judge_showcase_v1/) and adversarial fixtures in [`competition/datasets/judge_chaos_v1/`](competition/datasets/judge_chaos_v1/).

The three final defect-closure fixtures are:

```text
competition/datasets/judge_showcase_v1/01_case_brief.txt
competition/datasets/judge_showcase_v1/04_case_packet.pdf
competition/datasets/judge_showcase_v1/05_scanned_application.pdf
```

Run their final acceptance path with:

```bash
backend/.venv/bin/python scripts/run_final_fixture_acceptance.py
```

## Repository map

```text
backend/                 FastAPI privacy engine, detectors, IEG, policy, transforms, verification, proof/security
frontend/                React + TypeScript judge interface
deployment/              secure-online deployment guidance
scripts/                 setup, regression, benchmark, freeze/proof verification and evidence runners
competition/             datasets, benchmarks, traceability, signed freeze evidence and judge artifacts
docs/engineering/        development-history and hardening notes retained as provenance
```

Start with:

- [Architecture](ARCHITECTURE.md)
- [SIH260381 traceability](SIH_TRACEABILITY.md)
- [Privacy model](PRIVACY_MODEL.md)
- [Threat model](THREAT_MODEL.md)
- [Evaluation](EVALUATION.md)
- [Security](SECURITY.md)
- [Public-release provenance](PUBLIC_RELEASE.md)
- [Grand Finale Stage-2 protocol](GRAND_FINALE_STAGE2.md)

## Claims boundary

VeilGraph does **not** claim guaranteed anonymity, impossibility of re-identification, universal PII recall, legal certification under every privacy law, or forensic SSD overwriting. `Residual Exposure Score` and synthetic utility/privacy scores are calibrated product indicators, not legal or mathematical anonymity guarantees.

## SIH status

Every implementable pre-Grand-Finale requirement tracked for **SIH260381 — RE-DACT — NTRO** is closed in the frozen build. The sole external dependency is evaluation against the NTRO-provided **Stage-2 private dataset** when it becomes available at the Grand Finale.
