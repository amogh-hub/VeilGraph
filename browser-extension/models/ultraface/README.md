# Packaged UltraFace model

VeilGraph packages `version-RFB-320.onnx` as the first learned browser-local privacy model.
It is a lightweight face detector intended for edge devices and is used only for local visual
privacy detection. The browser extension verifies the model SHA-256 before creating an ONNX
Runtime session.

The model is provisioned from the pinned upstream revision recorded in `MODEL_MANIFEST.json`.
Runtime network fetching is forbidden: the built extension reads only the copy bundled under
`dist/models/ultraface/`.

This checkpoint establishes a learned local face path. It does **not** yet claim final visual-context
benchmark performance; that requires the later SIH26171 labelled accuracy/resource/latency suite.

License note: the upstream model README/SPDX identifies the model as MIT, while the pinned Hugging Face repository metadata currently labels the repository `apache-2.0`. VeilGraph records both rather than silently reconciling the discrepancy.
