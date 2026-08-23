#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "competition" / "final"

MANIFESTS = [
    ("Phase 1", FINAL / "PHASE_1_AUTHORITATIVE_FREEZE_MANIFEST.json", ("detector_model_surface_sha256", "scientific_evidence_sha256")),
    ("Phase 2", FINAL / "PHASE_2_AUTHORITATIVE_FREEZE_MANIFEST.json", ("production_backend_surface_sha256", "evidence_sha256")),
    ("Pre-Grand-Finale", FINAL / "PRE_GRAND_FINALE_AUTHORITATIVE_FREEZE_MANIFEST.json", ("final_surface_sha256", "final_evidence_sha256")),
]

ALLOWED_SANITIZED_OMISSIONS = {
    "competition/final/FINAL_FULL_REGRESSION.log": "25c152eaa0e73348bd6da5186e133b17231051822293e0b6604def71ea858363",
}


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_signature(signed: dict) -> bool:
    try:
        payload = signed["payload"]
        signer = payload["signer"]
        public_key = base64.b64decode(signer["public_key_b64"], validate=True)
        signature = base64.b64decode(signed["signature_b64"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical_json_bytes(payload))
        return True
    except Exception:
        return False


def main() -> int:
    errors: list[str] = []
    omitted_seen: set[str] = set()

    for label, manifest_path, groups in MANIFESTS:
        if not manifest_path.is_file():
            errors.append(f"{label}: missing manifest {manifest_path.relative_to(ROOT)}")
            continue
        signed = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not verify_signature(signed):
            errors.append(f"{label}: Ed25519 signature invalid")
            continue
        payload = signed["payload"]
        checked = 0
        for group in groups:
            for rel, expected in payload.get(group, {}).items():
                checked += 1
                path = ROOT / rel
                if not path.is_file():
                    allowed_hash = ALLOWED_SANITIZED_OMISSIONS.get(rel)
                    if allowed_hash == expected:
                        omitted_seen.add(rel)
                        continue
                    errors.append(f"{label}: unexpected missing signed file: {rel}")
                    continue
                actual = sha256(path)
                if actual != expected:
                    errors.append(f"{label}: hash mismatch: {rel}")
        print(f"{label}: signature valid; checked {checked} signed paths")

    if errors:
        print("PUBLIC_RELEASE_PROVENANCE_INVALID")
        for error in errors:
            print(f"- {error}")
        return 1

    unexpected_absent = set(ALLOWED_SANITIZED_OMISSIONS) - omitted_seen
    # It is acceptable if an archival copy restores an allowed omission; it will
    # have been hash-verified above. Only print omissions that are actually absent.
    print("PUBLIC_RELEASE_PROVENANCE_VALID")
    for rel in sorted(omitted_seen):
        print(f"Allowed sanitized omission: {rel}")
    if not omitted_seen and unexpected_absent:
        print("No allowed signed evidence omissions are absent in this tree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
