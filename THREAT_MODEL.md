# VeilGraph SIH26171 Threat Model

| Threat | Control | Evidence |
|---|---|---|
| Central model receives raw screenshot | sanitized release type + release gate | egress witness |
| Local port squatting / raw HTTP interception | signed ECDH session + AES-256-GCM | secure transport tests |
| Companion key substitution | persistent Ed25519 pin | pairing tests |
| Capture transport replay | one-time consumed session | secure transport tests |
| Ciphertext tampering | AES-GCM authentication | secure transport tests |
| PII in semantic release | local detector + minimizer + forbidden-field gate | privacy regression |
| PII still visible in image | flattened local redaction + visual rescan | privacy regression |
| Weak/inconclusive privacy evidence | mandatory gate fails closed | release gate tests |
| Payload changed after verification | signed SHA-256 commitment | release gate tests |
| Authorization replay | reasoning replay cache | reasoning tests |
| Untrusted reasoning request | signer fingerprint pin | reasoning tests |
| Model invents target | released target-ID allow-list | reasoning/action tests |
| Model emits arbitrary executable code | typed action schema | protocol/action tests |
| Wrong tab/frame/stale node | local fresh DOM validation | local action contract |
| Ambiguous low-impact click | deterministic confidence margin | ACTION_CONFIDENCE_V2 |
| Consequential action auto-executes | independent high-impact confirmation | loop/action tests |
| Agent acts on stale post-action state | mandatory fresh recapture | secure loop contract |
| Terminal completion hallucination | local terminal evidence + DONE/WAIT schema | terminal reasoning tests |
| Infinite/repeated action loop | loop governor / step bound | secure loop contract |

## Out of scope / explicitly not claimed

- universal anonymity;
- mathematical non-reidentifiability for every possible auxiliary dataset;
- protection against a fully compromised browser/OS kernel;
- WebGPU validation where the tested runtime is WASM;
- arbitrary-site autonomy beyond measured tasks.
