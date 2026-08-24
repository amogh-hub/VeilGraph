# SANITIZED_REASONING_ACTION_V1

Status: implementation checkpoint. It becomes VALIDATED only when `./scripts/verify_sih_checkpoint.sh` reports `RESULT: VALIDATED`.

## Boundary

The centralized reasoning endpoint accepts only:

- `BrowserReleasePayload`: already sanitized and task-minimized.
- `BrowserNetworkAuthorization`: short-lived Ed25519 authorization bound to that exact payload.

Raw DOM, raw input values, raw screenshots, full URLs, privacy hints, local analysis evidence and the Identity Exposure Graph are structurally absent from the reasoning request schema.

## Fail-closed admission

The server requires an explicitly enabled reasoning service, configured model, pinned VeilGraph signer fingerprint, valid unexpired signed ALLOW, exact payload hash match, 100 proof score, all mandatory gates passed, zero critical failures, privacy-floor compliance, residual Identity Exposure <= 25, and one-time authorization consumption.

## Model adapter

The reasoning adapter uses Ollama `/api/chat`, sends the Pydantic action-plan JSON Schema in `format`, also grounds the prompt with the schema, sets temperature to 0, and passes only the sanitized visual raster through the model message `images` field. The base64 raster is removed from the textual JSON prompt.

## Typed actions

Allowed: `CLICK`, `SCROLL`, `TYPE`, `SELECT`, `NAVIGATE`, `READ`, `WAIT`.

There are no CSS-selector, XPath, JavaScript, `eval`, shell-command, or arbitrary executable fields.

The backend validates payload/session binding, released target IDs, role compatibility, disabled controls, generated identifier-like values, same-origin navigation, high-impact confirmation and action-count bounds.

The extension independently validates the returned plan again. This checkpoint does **not** execute actions.

## Dedicated service

From `backend/`:

```bash
VEILGRAPH_REASONING_ENABLED=true VEILGRAPH_REASONING_OLLAMA_MODEL=<vision-capable-model> VEILGRAPH_REASONING_TRUSTED_SIGNER_SHA256=<paired-device-fingerprint> uvicorn reasoning_server:app --host 127.0.0.1 --port 8001
```

For remote SIH deployment, use HTTPS at the reasoning-service boundary.

## Claim boundary

After the repository harness validates this checkpoint, we may claim that signed sanitized reasoning admission, typed action planning, Ollama structured-output/vision integration, signer pinning, replay protection, and independent client/server action-plan validation are implemented and regression-tested.

We must not yet claim a measured model task-success rate, final browser execution, or official SIH benchmark performance.
