#!/usr/bin/env python3
from pathlib import Path
import collections, json

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "competition" / "datasets"
for folder in ["judge_showcase_v1", "judge_chaos_v1"]:
    path = BASE / folder
    m = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    gt = [json.loads(line) for line in (path / "ground_truth.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    counts = collections.Counter(item["entity_type"] for item in gt)
    print(f"{m['dataset_name']} ({m['dataset_id']})")
    print(f"  files: {m['file_count']}")
    print(f"  ground-truth occurrences: {m['ground_truth_occurrences']}")
    print(f"  formats: {', '.join(m['formats'])}")
    print(f"  role: {m['split_role']} | untouched_holdout={m['untouched_holdout']} | tuning_allowed={m['tuning_allowed']}")
    print("  top entities: " + ", ".join(f"{k}={v}" for k,v in counts.most_common(10)))
    print()
print("IMPORTANT: Showcase/Chaos are development splits. Final Broad PII v4 generalization evidence must use a new untouched external holdout after detector freeze.")
