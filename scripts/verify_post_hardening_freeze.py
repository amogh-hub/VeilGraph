#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FINAL = ROOT / "competition" / "final"
sys.path.insert(0, str(BACKEND))

from app.security.signing import verify_payload

MANIFESTS = [
    ("Phase 1", FINAL / "PHASE_1_AUTHORITATIVE_FREEZE_MANIFEST.json", "veilgraph.phase1-authoritative-freeze.v2", "COMPLETE_AND_FROZEN", ("detector_model_surface_sha256", "scientific_evidence_sha256")),
    ("Phase 2", FINAL / "PHASE_2_AUTHORITATIVE_FREEZE_MANIFEST.json", "veilgraph.phase2-authoritative-freeze.v2", "COMPLETE_AND_FROZEN", ("production_backend_surface_sha256", "evidence_sha256")),
    ("Pre-Grand-Finale", FINAL / "PRE_GRAND_FINALE_AUTHORITATIVE_FREEZE_MANIFEST.json", "veilgraph.pre-grand-finale-authoritative-freeze.v2", "PRE_GRAND_FINALE_COMPLETE_AND_FROZEN", ("final_surface_sha256", "final_evidence_sha256")),
]


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    all_bad: list[str] = []
    for label, path, schema, status, groups in MANIFESTS:
        if not path.is_file():
            all_bad.append(f"{label}: manifest missing")
            continue
        signed = json.loads(path.read_text(encoding="utf-8"))
        payload = signed.get("payload", {})
        signer = payload.get("signer", {})
        if payload.get("schema") != schema:
            all_bad.append(f"{label}: wrong schema")
        if payload.get("status") != status:
            all_bad.append(f"{label}: wrong status")
        if not verify_payload(payload, signed.get("signature_b64", ""), signer.get("public_key_b64", "")):
            all_bad.append(f"{label}: Ed25519 signature invalid")
        checked = 0
        for group in groups:
            for rel, expected in payload.get(group, {}).items():
                p = ROOT / rel
                checked += 1
                if not p.is_file():
                    all_bad.append(f"{label}: missing {rel}")
                elif sha(p) != expected:
                    all_bad.append(f"{label}: hash mismatch {rel}")
        print(f"{label} authoritative freeze: signature/hash verification checked {checked} files")

    if all_bad:
        print("VEILGRAPH AUTHORITATIVE FREEZE INVALID")
        for item in all_bad:
            print(f"- {item}")
        return 1

    p3 = json.loads((FINAL / "PRE_GRAND_FINALE_AUTHORITATIVE_FREEZE_MANIFEST.json").read_text(encoding="utf-8"))["payload"]
    pending = p3.get("only_external_pending_item", {})
    if pending.get("status") != "PENDING_EXTERNAL_DATA" or "Stage-2" not in pending.get("requirement", ""):
        print("External-pending boundary invalid")
        return 1

    print("All three authoritative post-hardening Ed25519 signatures VALID")
    print("All signed source/evidence hashes byte-identical")
    print("Only NTRO Stage-2 private Grand Finale dataset evaluation remains pending external data")
    print("VEILGRAPH PRE-GRAND-FINALE — COMPLETE & FROZEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
