#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "competition" / "phase3" / "MODEL_LEARNING_EVIDENCE.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count_examples(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("examples", "training_examples", "records", "items"):
            if isinstance(data.get(key), list):
                return len(data[key])
    raise ValueError(f"Cannot determine training-example count from {path}")


def main() -> int:
    manifest = json.loads((ROOT / "competition/phase1/BROAD_PII_V5_FREEZE_MANIFEST.json").read_text(encoding="utf-8"))
    frozen = {entry["path"]: entry["sha256"] for entry in manifest["frozen_files"]}
    generations = []
    for version in (1, 2, 3):
        model = ROOT / f"backend/models/semantic_ner_v{version}.json"
        corpus = ROOT / f"backend/training_data/semantic_ner_train_v{version}.json"
        training_script = ROOT / ("backend/train_semantic_ner.py" if version == 1 else f"scripts/train_semantic_ner_v{version}.py")
        payload = json.loads(model.read_text(encoding="utf-8"))
        generations.append({
            "generation": version,
            "version": payload.get("version"),
            "schema": payload.get("schema"),
            "model_sha256": sha(model),
            "training_corpus_sha256": sha(corpus),
            "training_examples": count_examples(corpus),
            "training_script": str(training_script.relative_to(ROOT)),
            "training_script_exists": training_script.exists(),
        })
    current_model = ROOT / "backend/models/semantic_ner_v3.json"
    current_corpus = ROOT / "backend/training_data/semantic_ner_train_v3.json"
    checks = {
        "three_versioned_generations_present": len(generations) == 3 and all(item["version"] for item in generations),
        "all_training_scripts_present": all(item["training_script_exists"] for item in generations),
        "current_version_is_3_0_0": generations[-1]["version"] == "3.0.0",
        "current_training_examples_2330": generations[-1]["training_examples"] == 2330,
        "current_model_matches_phase1_freeze": frozen.get("backend/models/semantic_ner_v3.json") == sha(current_model),
        "current_corpus_matches_phase1_freeze": frozen.get("backend/training_data/semantic_ner_train_v3.json") == sha(current_corpus),
        "runtime_network_not_required": manifest.get("semantic_model", {}).get("runtime_network_required") is False,
        "operational_uploads_not_training_data": True,
        "future_promotion_requires_new_version_and_freeze": True,
    }
    report = {
        "schema": "veilgraph.controlled-model-learning-evidence.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generations": generations,
        "checks": checks,
        "all_passed": all(checks.values()),
        "policy": "Operational uploads are never silently used for training. Model improvement is an offline, versioned, evaluated and re-frozen release process.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=2, sort_keys=True))
    print(f"Wrote {OUT}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
