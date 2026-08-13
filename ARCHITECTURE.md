# VeilGraph Architecture

## System goal

VeilGraph is a local-first privacy compiler and proof-gated release system. Its design separates four questions that conventional redaction tools often collapse into one:

1. **What sensitive information exists?**
2. **How can the remaining clues still reconstruct identity?**
3. **What transformation is appropriate for this audience and purpose?**
4. **Can the resulting artifact survive independent release attacks?**

The resulting product flow is **Understand → Protect → Verify → Release**.

## High-level data flow

```text
Browser UI
   │
   ▼
FastAPI API / job lifecycle
   │
   ├── admission + format validation
   ├── encrypted per-job workspace
   │
   ▼
Format adapters
PDF / image / text / DOCX / structured data / video
   │
   ▼
Universal privacy representation
   │
   ▼
Detection fusion
   ├── deterministic direct identifiers
   ├── quasi/contextual identifiers
   ├── local Semantic NER v3
   └── OCR / visual channels
   │
   ▼
Canonical entities + human review
   │
   ▼
Identity Exposure Graph
   │
   ▼
Audience/purpose recommendation + L1–L5 policy compiler
   │
   ├── native structure-preserving sanitizer (L1–L4)
   └── Synthetic Twin generator (L5 structured data)
   │
   ▼
Format-specific Privacy Red Team
   │
   ├── PASS all mandatory gates → VERIFIED_SAFE / ALLOW_RELEASE
   └── FAIL or INCONCLUSIVE     → RELEASE_BLOCKED
   │
   ▼
Protected artifact + separate evidence
   │
   ├── SHA-256 audit chain
   ├── Ed25519 proof certificate
   └── complete signed proof package
   │
   ▼
TTL/manual destruction → signed destruction tombstone
```

## Core components

| Component | Main implementation | Responsibility |
|---|---|---|
| API/job orchestration | `backend/app/api/routes.py` | Job lifecycle, review, transform, verify, release and export surfaces |
| Format extraction | `backend/app/extraction/` | Native text, PDF/scans, DOCX, structured data and video extraction |
| Detection | `backend/app/detection/` | Direct/quasi/contextual/visual detection plus Semantic NER v3 |
| Identity Exposure Graph | `backend/app/graph/exposure_graph.py` | Links subjects, identifiers, quasi-identifiers and related entities |
| Policy compiler | `backend/app/policy/compiler.py` | Deterministic L1–L5 actions and audience-sensitive transformations |
| Recommendation | `backend/app/policy/recommendation.py` | Transparent level recommendation; never a release certificate |
| Sanitizer | `backend/app/transformation/sanitizer.py` | Structure-aware L1–L4 transformation across supported formats |
| Synthetic Twin | `backend/app/transformation/synthetic_twin.py` | Local structured-data population synthesis for L5 |
| Synthetic export | `backend/app/transformation/synthetic_export.py` | Export of verified synthetic populations into supported representations |
| Privacy Red Team | `backend/app/verification/red_team.py` | Independent format-specific release attacks and proof score |
| Proof | `backend/app/proof/` | Certificate/package generation and exact artifact/evidence binding |
| Audit | `backend/app/audit/ledger.py` | SHA-256 chained event ledger |
| Workspace security | `backend/app/security/workspace.py` | Per-job AES-256-GCM encrypted blobs and RAM-only keys |
| Retention | `backend/app/security/retention.py` | TTL, manual destruction, restart key-loss erasure and tombstones |
| Deployment boundary | `backend/app/security/deployment.py`, `network_guard.py` | offline/secure-online controls, bearer auth, HTTPS and egress boundary |
| Frontend | `frontend/src/` | React/TypeScript judge workflow and evidence presentation |

## Detection architecture

VeilGraph does not depend on a single NER model. Detection is fused from complementary channels:

- deterministic syntax/context detectors for credentials and strong identifiers;
- quasi-identifier rules for age, dates, location, employer/job and related context;
- local **Semantic NER v3**, a bundled logistic-regression contextual span classifier for `PERSON_NAME`, `EMPLOYER`, `LOCALITY`, `STREET_ADDRESS` and `JOB_TITLE`;
- OCR and visual detection for scan/image/video channels;
- format-specific context recovery for DOCX/video.

Semantic NER v3 has 2,330 synthetic training examples and requires no runtime network. It proposes candidates; deterministic release gates remain authoritative.

## Identity Exposure Graph

The IEG models privacy risk as relationships rather than a flat list. Node kinds include document, subject, related person, direct identifier, quasi-identifier and visual identifier. Edges include containment, identification, description, related-person and co-occurrence relationships.

This enables VeilGraph to surface reconstruction paths where individually weak clues become identifying in combination.

## Privacy compilation

The compiler maps entity type + privacy level + audience to a deterministic action:

- `RETAIN`
- `MASK`
- `PROTECT`
- `GENERALIZE`
- `PSEUDONYMIZE`
- `REMOVE`
- `SYNTHESIZE`

Audience profiles are `PUBLIC_RELEASE`, `RESEARCH_PARTNER` and `INTERNAL_OPERATIONS`. The recommendation engine can suggest a stronger level based on purpose, recipient, exposure and high-risk identifiers, but the user-facing policy remains transparent and the Red Team remains the release authority.

## Verification architecture

The Privacy Red Team is format-specific rather than a single string search. Depending on the artifact it combines:

- direct identifier rescans;
- independent extraction;
- secondary text/structured/DOCX parsers;
- OCR rescans;
- hidden markup/channel inspection;
- replacement/region integrity;
- metadata inspection;
- policy coverage;
- relationship consistency;
- raw object/stream/byte scans;
- fragment attacks;
- structure preservation;
- video visual/audio/timeline attacks;
- L5 source-record copy, utility/privacy and output-commitment attacks.

A mandatory `INCONCLUSIVE` is treated as unsafe for release, not as a pass.

## Workspace cryptography and retention

Each job creates a random 32-byte master key. HKDF-SHA256 derives separate workspace encryption and entity-fingerprint keys. Persisted job blobs use **AES-256-GCM** with per-blob random nonces and job/filename associated data. Normalized entity fingerprints use **HMAC-SHA256**.

Keys live only in the running process. On destruction, Python-owned key bytearrays are best-effort zeroed and encrypted job blobs are deleted. After a process restart, surviving encrypted directories are erased because their RAM-only keys are intentionally unrecoverable.

This is application-level cryptographic erasure. VeilGraph does not claim forensic overwriting of SSD flash cells or elimination of every possible runtime copy outside application control.

## Audit and proof

Every major job event is chained with SHA-256 by committing to the prior event hash. A verified output receives an **Ed25519** certificate bound to the exact protected artifact and supporting evidence. The proof package includes machine-readable verification material and offline verification instructions.

The signing key is generated locally on first use and is intentionally excluded from this public repository.

## Offline and secure-online modes

**Offline competition mode** binds to localhost and enables the outbound Python network guard. Operational privacy processing does not require a cloud model or external AI API.

**Secure-online mode** retains the same application pipeline but requires bearer authentication and HTTPS; forwarded HTTPS is accepted only from configured trusted proxy networks. The bundled secure-online acceptance proves application behavior over a real local TLS socket; production public deployment still requires organization-managed DNS/TLS/reverse-proxy infrastructure.

## Admission and resource bounds

The backend sets explicit limits for file size, PDF page count/render pixels, image pixels, video duration/frame count/resolution, heavy-request concurrency and proof-package size/structure. Oversized or uninspectable inputs fail closed rather than silently bypassing analysis.

## Design boundary

VeilGraph is not a mathematical anonymity proof system. Its graph, exposure score, privacy levels, Red Team and signed evidence create a rigorous operational release protocol for the implemented threat model; they do not prove that all possible future auxiliary datasets or linkage attacks are impossible.
