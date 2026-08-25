# VeilGraph SIH26171 Architecture

## Trust zones

### Zone A — Browser-local raw context
Contains raw DOM values, accessibility semantics, visible screenshot pixels,
credentials, direct identifiers, quasi-identifiers and visual sensitive regions.
This zone is never eligible for central reasoning.

### Zone B — Trusted local companion
Receives raw browser material only over the authenticated encrypted localhost
transport. It performs local analysis, Identity Exposure Graph construction,
task minimization, visual redaction and privacy red-team verification.

### Zone C — Authorized sanitized release
The only representation eligible to reach a reasoning server is
`BrowserReleasePayload`, bound byte-for-byte to an Ed25519-signed
`ALLOW_NETWORK_RELEASE` authorization.

### Zone D — Central reasoning
Open-weight Qwen reasons over sanitized/task-minimal semantic and, when useful,
sanitized visual context. It emits typed actions, never executable code.

## Local perception

The extension captures:
- DOM role/name/text geometry;
- accessibility semantics;
- visible screenshot;
- frame coverage;
- local visual findings.

The browser visual stack includes the pinned UltraFace RFB-320 ONNX model through
ONNX Runtime Web/WASM plus browser/native visual providers where available.

## Privacy compiler

The privacy layer:
- detects direct identifiers and credentials;
- detects broader/quasi-identifying context;
- fuses DOM, OCR and visual evidence;
- builds relationship-aware identity exposure;
- selects only task-required anchors and dependencies;
- creates a new flattened sanitized raster;
- drops irrelevant screen context;
- calculates exposure/utility/minimization evidence.

## Mandatory release gate

All mandatory privacy gates must PASS. FAIL or INCONCLUSIVE blocks release.
Authorization commits to the exact payload hash, identity exposure, task utility,
gate summary, expiry and nonce.

## Raw localhost transport

A persistent Ed25519 companion identity is explicitly paired/pinned.

Each raw capture uses:
- fresh browser P-256 ECDH key;
- signed companion ephemeral P-256 key;
- HKDF-SHA256 key derivation;
- AES-256-GCM authenticated encryption;
- endpoint-bound AAD;
- 96-bit IV;
- short TTL;
- one-time session consumption.

This protects raw capture even if an untrusted process observes/intercepts the
localhost HTTP body after pairing.

## Reasoning and action security

The server:
- verifies signer trust;
- verifies authorization signature/hash/expiry;
- prevents authorization replay;
- enforces privacy invariants;
- validates structured output;
- allows only target IDs present in the released payload.

The browser:
- computes deterministic action confidence;
- revalidates the live DOM before action;
- refuses stale/disabled/wrong-frame targets;
- independently preserves high-impact confirmation;
- executes no arbitrary JavaScript/eval;
- forces a fresh observation after every action.

## Secure loop invariant

```text
OBSERVE → PRIVACY → REASON → VALIDATE → ACT
                                   ↓
                     mandatory fresh OBSERVE
```

No action result is trusted as the next state.

## Browser packages

Chrome:
- Manifest V3;
- side panel UI;
- service worker;
- content scripts;
- ONNX/WASM model assets.

Firefox:
- generated MV3 validation package;
- same local security/perception core;
- toolbar popup UI replaces Chrome-only sidePanel;
- real runtime status is recorded only after a Firefox COMPLETE loop.
