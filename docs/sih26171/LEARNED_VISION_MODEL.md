# Packaged Browser-Local Learned Vision — Checkpoint V1

## Scope

This checkpoint adds the first packaged learned visual model to VeilGraph's browser-side perception stack. It is deliberately narrow: **local face detection for privacy redaction**. It does not yet claim final SIH26171 visual-context benchmark performance.

## Runtime

- Model: UltraFace `version-RFB-320.onnx`
- Model ID: `ultraface-rfb-320`
- Expected SHA-256: `34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017`
- Expected size: `1,270,727` bytes
- Runtime: `onnxruntime-web@1.27.0`
- Preferred execution provider: WebGPU
- Deterministic local fallback: WASM
- Input: RGB, `1×3×240×320`, `(pixel - 127) / 128`
- Output contract: score tensor `1×4420×2`, box tensor `1×4420×4`

The model is provisioned once during engineering setup from a pinned upstream revision, verified by SHA-256, committed with the source tree, and copied into the built extension. **Runtime model download is not permitted.**

## Trust boundary

The learned detector receives only the locally captured viewport raster. It does not call any network endpoint. The model bytes are fetched only from `chrome-extension://.../models/...`, hash-verified in the extension, and then passed to ONNX Runtime Web.

If WebGPU initialization fails or is unavailable, VeilGraph attempts the packaged WASM path. If learned inference still fails, the capability is reported `ERROR`/`UNAVAILABLE`; it is never silently treated as safe.

Browser-native `FaceDetector` remains a corroborative source rather than the mandatory face path. The Identity Exposure / sanitizer / Red Team / Network Release Gate remain downstream and unchanged in authority.

## Evidence emitted

Each learned inference records:

- `model_id`
- `model_sha256`
- runtime/version
- actual execution provider (`webgpu` / `wasm` / `unavailable`)
- model load time
- inference time
- input dimensions
- detection count
- whether fallback occurred and why

## Validation gate

`browser-extension/scripts/verify_learned_model_contract.mjs` verifies the model hash and size, built-extension asset packaging, CSP support for WebAssembly, ONNX Runtime WASM model loading, a real zero-input inference, and expected output tensor shapes.

This is an **engineering validation checkpoint**, not the final accuracy benchmark. The later labelled SIH browser benchmark will measure face recall/precision, visual-context accuracy, memory/resource use, WebGPU/WASM latency, and redaction precision.


## Multimodal fusion contract

The learned detector is not treated as an oracle. Browser-local fusion is recall-first: non-overlapping findings from independent detectors are retained, while overlapping findings of the same semantic type are merged conservatively. For faces, the merged redaction box is the union of learned and browser-native boxes so disagreement cannot shrink the protected region.

Each fused finding carries `supportingProviders`, `supportCount`, and a `SINGLE_SOURCE` or `CORROBORATED` consensus label. Agreement between the packaged UltraFace detector and the browser-native face detector is recorded explicitly in the perception report as `learnedNativeFaceAgreements`. A single-source finding is still retained for privacy; corroboration increases confidence but is never required to redact a potentially sensitive region.
