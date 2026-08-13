#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.security.signing import verify_payload


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    path = ROOT / "competition/phase2/PHASE_2_FREEZE_MANIFEST.json"
    if not path.is_file():
        print("Phase-2 freeze manifest not found")
        return 1
    signed = json.loads(path.read_text(encoding="utf-8"))
    payload = signed.get("payload", {})
    signer = payload.get("signer", {})
    if payload.get("schema") != "veilgraph.phase2-freeze.v2":
        print("Phase-2 freeze schema is not the final-hardening v2 schema")
        return 1
    if payload.get("status") != "COMPLETE_AND_FROZEN":
        print("Phase-2 freeze status is not COMPLETE_AND_FROZEN")
        return 1
    if signed.get("signature_algorithm") != "Ed25519" or not verify_payload(
        payload, signed.get("signature_b64", ""), signer.get("public_key_b64", "")
    ):
        print("Phase-2 freeze signature INVALID")
        return 1

    phase1 = ROOT / "competition/phase1/PHASE_1_FREEZE_MANIFEST.json"
    expected_phase1 = payload.get("phase1_freeze_manifest_sha256")
    if not phase1.is_file() or sha256(phase1) != expected_phase1:
        print("Phase-1 closure manifest changed after Phase-2 freeze")
        return 1

    mismatches = []
    for rel, expected in payload.get("production_surface_sha256", {}).items():
        file = ROOT / rel
        if not file.is_file() or sha256(file) != expected:
            mismatches.append(rel)
    for rel, expected in payload.get("evidence_sha256", {}).items():
        file = ROOT / rel
        if not file.is_file() or sha256(file) != expected:
            mismatches.append(rel)
    if mismatches:
        print("Phase-2 freeze INVALID; changed/missing:", mismatches)
        return 1

    release = payload.get("release", {})
    release_rel = release.get("path")
    if not isinstance(release_rel, str):
        print("Phase-2 freeze release path is missing")
        return 1
    release_path = ROOT / release_rel
    if not release_path.is_file() or sha256(release_path) != release.get("sha256"):
        print("Phase-2 sanitized release ZIP no longer matches signed freeze")
        return 1

    print(f"Phase 2 freeze VALID: {len(payload.get('production_surface_sha256', {}))} production/security/scale files byte-identical")
    print("Phase 2 evidence hashes, Phase-1 closure hash, release ZIP hash and Ed25519 signature: VALID")
    print("Status: MACHINE CLOSURE VALID — manual acceptance still required before Phase 3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
