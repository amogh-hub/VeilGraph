#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.proof.certificate import verify_certificate  # noqa: E402


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        print("Usage: python3 scripts/verify_certificate.py <certificate.json> [protected-artifact]")
        return 2
    cert_path = Path(sys.argv[1])
    certificate = json.loads(cert_path.read_text(encoding="utf-8"))
    if not verify_certificate(certificate):
        print("INVALID_SIGNATURE")
        return 1
    payload = certificate["payload"]
    print("SIGNATURE_VALID")
    print(f"certificate_id={payload['certificate_id']}")
    print(f"signer_fingerprint={payload['signer']['public_key_sha256']}")
    print(f"release_decision={payload['release_decision']}")
    print(f"proof_score={payload['proof_score']}/100")
    if len(sys.argv) == 3:
        artifact = Path(sys.argv[2])
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        print(f"artifact_sha256={digest}")
        if digest != payload["output_sha256"]:
            print("ARTIFACT_HASH_MISMATCH")
            return 1
        print("ARTIFACT_HASH_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
