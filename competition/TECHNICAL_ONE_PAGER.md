# VeilGraph Technical One-Pager

**Positioning:** local-first privacy compiler and proof-gated release system.

**Pipeline:** ingest → local extraction/OCR/vision → canonical entities → Identity Exposure Graph → audience policy → Level 1/3/4 transformation → 12-channel Privacy Red Team → signed certificate → recomputable proof bundle → signed exact-bundle receipt → complete proof package → signed destruction receipt.

**Security primitives:** AES-256-GCM per-job encrypted blobs; random per-job master key; HKDF-derived encryption/fingerprint keys; HMAC-SHA256 entity fingerprints; SHA-256 graph/audit/artifact commitments; Ed25519 device signing identity.

**Fail-closed rule:** download is available only when every mandatory attack is PASS, proof score is 100/100 and critical blockers are zero.

**Portable proof:** the complete signed proof package contains the protected output, machine-readable/printable certificate, verification evidence, manifest, Identity Exposure Graph, certification and export audit ledgers, a per-file hash index, offline verification instructions, and an Ed25519-signed receipt for the exact inner proof-bundle bytes.

**Competition mode:** localhost-only API, outbound network guard, bundled OCR/vision components, no runtime model download.
