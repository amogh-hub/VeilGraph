from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MODEL = ROOT / "models" / "ultraface" / "version-RFB-320.onnx"
MODEL_SHA256 = "34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017"
ORT_DIST = ROOT / "node_modules" / "onnxruntime-web" / "dist"
ORT_FILES = (
    "ort.wasm.bundle.min.mjs",
    "ort-wasm-simd-threaded.wasm",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if DIST.exists():
    shutil.rmtree(DIST)
DIST.mkdir(parents=True)

tsc_name = "tsc.cmd" if os.name == "nt" else "tsc"
tsc = ROOT / "node_modules" / ".bin" / tsc_name

esbuild_name = "esbuild.exe" if os.name == "nt" else "esbuild"
esbuild = ROOT / "node_modules" / ".bin" / esbuild_name

if not tsc.exists():
    raise SystemExit(
        "Local TypeScript compiler is missing. Run `npm ci` in browser-extension before building."
    )
if not esbuild.exists():
    raise SystemExit("Local esbuild is missing. Run npm ci.")

if not MODEL.exists():
    raise SystemExit(
        "Packaged UltraFace model is missing. Run `python3 ../scripts/provision_learned_vision.py` from browser-extension or the root bootstrap script."
    )
model_digest = sha256(MODEL)
if model_digest != MODEL_SHA256:
    raise SystemExit(
        f"Packaged UltraFace SHA-256 mismatch: expected {MODEL_SHA256}, got {model_digest}"
    )
for filename in ORT_FILES:
    if not (ORT_DIST / filename).exists():
        raise SystemExit(
            f"Pinned ONNX Runtime Web asset is missing: {filename}. Run `npm ci` in browser-extension."
        )

subprocess.run([str(tsc), "-p", str(ROOT / "tsconfig.json")], check=True)

content_bundle = DIST / "content" / "contentScript.js"

subprocess.run(
    [
        str(esbuild),
        str(ROOT / "src" / "content" / "contentScript.ts"),
        "--bundle",
        "--format=iife",
        "--platform=browser",
        "--target=chrome121",
        f"--outfile={content_bundle}",
    ],
    check=True,
)

built_content = content_bundle.read_text(encoding="utf-8")

if "import " in built_content or "export " in built_content:
    raise SystemExit("Bundled content script still contains ES-module syntax")

shutil.copy2(ROOT / "manifest.json", DIST / "manifest.json")

sidepanel = DIST / "sidepanel"
sidepanel.mkdir(parents=True, exist_ok=True)
shutil.copy2(ROOT / "public" / "sidepanel.html", sidepanel / "index.html")
shutil.copy2(ROOT / "public" / "styles.css", sidepanel / "styles.css")

model_dist = DIST / "models" / "ultraface"
model_dist.mkdir(parents=True, exist_ok=True)
shutil.copy2(MODEL, model_dist / MODEL.name)

vendor_dist = DIST / "vendor" / "onnxruntime"
vendor_dist.mkdir(parents=True, exist_ok=True)
for filename in ORT_FILES:
    shutil.copy2(ORT_DIST / filename, vendor_dist / filename)

print(DIST)
print(f"Packaged learned model: ultraface-rfb-320 sha256={MODEL_SHA256}")
print("Packaged ONNX Runtime Web: 1.27.0 (WASM live-browser path)")
