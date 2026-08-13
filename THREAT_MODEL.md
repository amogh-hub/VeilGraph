# VeilGraph Threat Model

## Protected assets

VeilGraph is designed to protect:

- source documents, images, datasets and video;
- detected plaintext identifiers and their relationships;
- transformation mappings and protected outputs;
- proof/audit integrity;
- local signing identity;
- retained job state until its configured destruction deadline.

## Adversaries considered

### 1. Accidental or incomplete redaction

A protected artifact may visually appear safe while source text remains in a PDF stream, DOCX XML part, structured field, OCR-visible raster region, metadata or another parseable channel.

**Controls:** independent extraction, secondary parsers, OCR rescans, hidden-channel checks, raw object/byte scans, replacement/region integrity and format-specific structure checks.

### 2. Identity reconstruction from remaining context

An attacker may link employer, location, age, date, job, related-person or repeated clues to infer identity even after direct identifiers are removed.

**Controls:** quasi/contextual detection, Identity Exposure Graph, L3/L4 policy compilation and relationship-consistency verification.

### 3. Partial identifier recovery

Fragments of a phone, email, credential or other identifier may survive even if the exact original string no longer exists.

**Controls:** direct-identifier fragment attack plus independent rescans.

### 4. Visual/multimedia leakage

PII may survive in scanned pages, QR codes, video frames, transient frames or audio.

**Controls:** OCR/visual processing, post-transform OCR verification, video physical-frame change screening, independent QR recovery attack, video structure validation and fail-closed audio stripping/absence verification.

### 5. Proof or artifact tampering

An attacker may replace a protected file, graph, manifest or evidence after verification.

**Controls:** SHA-256 commitments, chained audit ledger, Ed25519 certificate/signature and exact proof-package receipts.

### 6. Local persistence after intended deletion

Sensitive material may remain in application-managed job storage longer than requested.

**Controls:** encrypted per-job blobs, RAM-only keys, user-configured TTL, automatic sweep, explicit destruction, restart key-loss cleanup and signed destruction tombstones.

### 7. Network exfiltration during offline operation

Application code could attempt outbound access even though sensitive processing is expected to remain local.

**Controls:** localhost bind, no mandatory external model API, offline Python egress guard and no model download in startup.

### 8. Unauthenticated/insecure secure-online access

An online deployment may expose endpoints without appropriate transport/authentication.

**Controls:** mandatory bearer token, HTTPS requirement and trusted-proxy handling. Public deployment still requires organization-managed perimeter/TLS infrastructure.

### 9. Resource-exhaustion or parser-abuse inputs

Huge, malformed, encrypted or pathologically rendered files can force unsafe resource use or make complete inspection impossible.

**Controls:** file/page/pixel/video/proof-package bounds, malformed/encrypted PDF handling, concurrent heavy-request admission controls and fail-closed rejection.

### 10. Malicious proof/release archives

ZIP path traversal, unmanifested members or dangerous compression/structure can undermine package integrity.

**Controls:** proof/release package member validation, exact member-set enforcement, traversal rejection and configured package size/compression limits.

## Out of scope / bounded claims

VeilGraph does not claim to defeat:

- every future linkage attack using arbitrary unknown auxiliary datasets;
- a fully compromised host OS/hypervisor with access to process memory;
- forensic recovery from storage layers outside application control;
- universal semantic detection across every language/domain;
- legal or mathematical anonymity in all contexts.

The system's security claim is therefore **bounded, testable and fail closed**: within the implemented formats, policies and attack gates, release is blocked whenever required verification cannot establish a pass.
