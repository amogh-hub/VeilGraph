#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "browser-extension" / "models" / "ultraface" / "MODEL_MANIFEST.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest() -> dict[str, object]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    required = {"filename", "sha256", "size_bytes", "download_url", "model_id"}
    missing = required.difference(data)
    if missing:
        raise SystemExit(f"Model manifest missing fields: {sorted(missing)}")
    return data


def verify(path: Path, expected_hash: str, expected_size: int) -> tuple[bool, str]:
    if not path.exists():
        return False, "missing"
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        return False, f"size mismatch: expected {expected_size}, got {actual_size}"
    actual_hash = sha256(path)
    if actual_hash != expected_hash:
        return False, f"sha256 mismatch: expected {expected_hash}, got {actual_hash}"
    return True, actual_hash


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "VeilGraph-SIH26171-model-provisioner/1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=120) as response, tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False
    ) as temporary:
        temp_path = Path(temporary.name)
        shutil.copyfileobj(response, temporary, length=1024 * 1024)
    temp_path.replace(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision the pinned VeilGraph browser-local learned vision model.")
    parser.add_argument("--verify-only", action="store_true", help="Do not download; only verify the packaged model.")
    args = parser.parse_args()

    manifest = load_manifest()
    filename = str(manifest["filename"])
    expected_hash = str(manifest["sha256"])
    expected_size = int(manifest["size_bytes"])
    url = str(manifest["download_url"])
    model_id = str(manifest["model_id"])
    destination = MANIFEST.parent / filename

    ok, detail = verify(destination, expected_hash, expected_size)
    if ok:
        print(f"MODEL READY: {model_id} sha256={detail} size={expected_size}")
        return 0
    if args.verify_only:
        print(f"MODEL NOT READY: {model_id}: {detail}")
        return 1

    if destination.exists():
        destination.unlink()
    print(f"Provisioning pinned model {model_id} ({expected_size} bytes)...")
    download(url, destination)
    ok, detail = verify(destination, expected_hash, expected_size)
    if not ok:
        destination.unlink(missing_ok=True)
        raise SystemExit(f"Downloaded model failed integrity verification: {detail}")
    print(f"MODEL READY: {model_id} sha256={detail} size={expected_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
