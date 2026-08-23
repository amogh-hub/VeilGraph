#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "competition/phase1/BROAD_PII_V5_FREEZE_MANIFEST.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad: list[str] = []
    for item in payload["frozen_files"]:
        path = ROOT / item["path"]
        if not path.is_file():
            bad.append(f"MISSING {item['path']}")
            continue
        actual = sha(path)
        if actual != item["sha256"]:
            bad.append(f"HASH_MISMATCH {item['path']} expected={item['sha256']} actual={actual}")
    vb = ROOT / "backend/benchmark_corpus/veilbench_curated_v1.json"
    if sha(vb) != payload["veilbench_curated_v1_sha256"]:
        bad.append("HASH_MISMATCH backend/benchmark_corpus/veilbench_curated_v1.json")
    if bad:
        print("Broad PII v5 freeze INVALID")
        print("\n".join(bad))
        return 1
    model = payload["semantic_model"]
    print(f"Broad PII v5 freeze VALID: {len(payload['frozen_files'])} production/model files byte-identical")
    print(f"Semantic NER v3: {model['version']} | training examples: {model['training_examples']} | runtime network required: {model['runtime_network_required']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
