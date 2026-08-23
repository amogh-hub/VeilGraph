# VeilGraph Security

## Security posture

VeilGraph is designed for sensitive privacy transformation where uncertainty should block release rather than be silently ignored. The core security policy is **fail closed**.

## Operational boundary

In offline competition mode:

- the API binds to `127.0.0.1`;
- operational model inference is local;
- `start_local.sh` performs no package/model download;
- Python outbound network access is guarded;
- source artifacts are stored only as encrypted job blobs under application control.

The COTS benchmark tooling is an explicitly separate evaluation path and may contact commercial services only when the operator supplies credentials/flags. It is not part of operational privacy processing.

## Data-at-rest handling

`backend/app/security/workspace.py` uses:

- random 256-bit per-job master keys;
- HKDF-SHA256 to derive separate encryption and fingerprint keys;
- AES-256-GCM for encrypted job blobs with random nonces and AAD;
- `0700` workspace directory / `0600` blob permissions where the host supports them;
- HMAC-SHA256 for normalized entity fingerprints.

Plaintext identity values may exist in process memory while a job is active. VeilGraph does not claim that a compromised OS can be prevented from reading process memory.

## Signing and integrity

VeilGraph creates a local Ed25519 device key on first use. Verified outputs can receive certificates/proof packages bound to exact artifact, graph, verification and audit commitments. Audit events form a SHA-256 previous-hash chain.

**Never publish or copy the private device key.** This public repository intentionally excludes `.veilgraph/device-ed25519.key`.

## Retention and destruction

Jobs use a configured retention window. Destruction removes encrypted blobs, destroys in-process keys, removes sensitive database rows and leaves only a non-sensitive signed destruction tombstone. If the process restarts and job keys are lost, orphaned encrypted job directories are deleted because they are intentionally unrecoverable.

This is application-level cryptographic erasure, not forensic SSD-cell overwriting.

## Secure-online mode

Secure-online mode requires:

- a valid bearer token;
- HTTPS;
- trusted proxy networks before forwarded HTTPS headers are honored.

The bundled acceptance uses a real local TLS socket. Production internet exposure still requires organization-managed DNS/TLS, reverse proxy/firewall and normal infrastructure security controls.

## Resource / archive hardening

The application enforces bounded file/PDF/image/video/proof-package limits. Proof/release packages reject unsafe member paths and unmanifested entries.

## Public repository hygiene

The GitHub-oriented release excludes:

- private signing keys;
- runtime databases/workspaces/uploads;
- `.env`/credential material;
- Python/COTS virtual environments;
- `node_modules` and caches;
- raw machine-local regression logs;
- generated large competition archives.

See [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md).

## Reporting a vulnerability

Do **not** publish a sensitive exploit, credential, private dataset sample or real PII in a public issue. Use a private GitHub Security Advisory if the repository enables it, or contact the project team through the private SIH coordination channel.

## Claims boundary

VeilGraph security evidence is bounded to the implementation, threat model and tested environments. It is not a substitute for host hardening, organizational access control, independent penetration testing or formal certification in a production government deployment.
