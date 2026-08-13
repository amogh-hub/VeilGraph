#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "competition/phase1/BROAD_PII_V4_FREEZE_MANIFEST.json"
SNAPSHOT_ROOT = ROOT / "competition/frozen/broad_pii_v4"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad: list[str] = []
    for item in payload["frozen_files"]:
        path = SNAPSHOT_ROOT / item["path"]
        if not path.exists():
            bad.append(f"MISSING historical snapshot {item['path']}")
            continue
        actual = sha(path)
        if actual != item["sha256"]:
            bad.append(f"HASH_MISMATCH historical snapshot {item['path']} expected={item['sha256']} actual={actual}")
    vb = ROOT / "backend/benchmark_corpus/veilbench_curated_v1.json"
    if sha(vb) != payload["veilbench_curated_v1_sha256"]:
        bad.append("HASH_MISMATCH backend/benchmark_corpus/veilbench_curated_v1.json")
    if bad:
        print("Broad PII v4 historical freeze INVALID")
        print("\n".join(bad))
        return 1
    print(f"Broad PII v4 historical freeze VALID: {len(payload['frozen_files'])} snapshot files byte-identical")
    print(f"Semantic NER v2: {payload['semantic_model']['version']} | runtime network required: {payload['semantic_model']['runtime_network_required']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
