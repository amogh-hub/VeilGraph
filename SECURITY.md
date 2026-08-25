# VeilGraph SIH26171 Security Model

## Primary invariant

**Raw browser screen context must not reach the central reasoning service.**

The central service accepts only a sanitized `BrowserReleasePayload` accompanied
by a valid signed `ALLOW_NETWORK_RELEASE` authorization.

## Controls

- explicit trust-on-first-use companion identity pin;
- persistent Ed25519 signer fingerprint;
- P-256 ECDH ephemeral transport session;
- HKDF-SHA256 key derivation;
- AES-256-GCM authenticated raw local transport;
- one-time endpoint-bound transport session;
- local PII / credential / quasi-identifier / visual detection;
- task-minimal release;
- flattened sensitive visual redaction;
- 12 mandatory fail-closed privacy gates;
- payload hash commitment;
- short-lived network authorization;
- replay protection;
- reasoning-server signer pin;
- typed action schema;
- target allow-list;
- same-origin navigation validation;
- deterministic action confidence;
- high-impact confirmation independent of confidence;
- fresh live-DOM preflight;
- fresh observation after every execution;
- terminal DONE/WAIT-only reasoning after positive completion evidence.

## External egress evidence

The final evidence workflow places an independent witness on the exact
extension-to-reasoning HTTP boundary. It checks every controlled PrismCare raw
canary and forbidden raw schema field before proxying the exact request.

The witness stores hashes/counts/metadata only. It does not persist the outbound
request body.

## Fail-closed behavior

Release is blocked when:
- a mandatory privacy gate FAILs or is INCONCLUSIVE;
- visual coverage is insufficient for the requested policy;
- signer trust changes;
- payload or signature is altered;
- authorization expires or is replayed;
- target ID is absent/disabled/stale;
- frame/tab/origin continuity fails;
- high-impact confirmation is absent;
- loop limits or repeated-action protections trip.

## Claim boundary

Security tests demonstrate the implemented threat model and fixtures. They are
not a mathematical proof that no future implementation bug or browser exploit
can exist.
