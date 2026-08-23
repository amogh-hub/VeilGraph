from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from app.core.enums import EntityType, FileType
from app.detection.semantic_ner import generate_semantic_candidates, semantic_features
from app.extraction.document_processor import process_document

ROOT = Path(__file__).resolve().parent
TRAINING = ROOT / "training_data" / "semantic_ner_train_v1.json"
MODEL = ROOT / "models" / "semantic_ner_v1.json"
TYPES = (
    EntityType.PERSON_NAME,
    EntityType.STREET_ADDRESS,
    EntityType.EMPLOYER,
    EntityType.JOB_TITLE,
)


def sigmoid(value: float) -> float:
    value = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def train_binary(rows: list[tuple[dict[str, float], int]], epochs: int = 1200, lr: float = 0.08, l2: float = 0.002):
    feature_names = sorted({name for features, _ in rows for name in features if name != "bias"})
    weights = {name: 0.0 for name in feature_names}
    intercept = 0.0
    for _ in range(epochs):
        grad_w = {name: 0.0 for name in feature_names}
        grad_b = 0.0
        for features, label in rows:
            score = intercept + sum(weights[name] * features.get(name, 0.0) for name in feature_names)
            error = sigmoid(score) - label
            grad_b += error
            for name in feature_names:
                grad_w[name] += error * features.get(name, 0.0)
        n = float(max(1, len(rows)))
        intercept -= lr * grad_b / n
        for name in feature_names:
            grad = grad_w[name] / n + l2 * weights[name]
            weights[name] -= lr * grad
    # Keep the portable model small and auditable.
    weights = {name: round(value, 6) for name, value in weights.items() if abs(value) >= 0.03}
    return round(intercept, 6), weights


def main() -> None:
    raw = json.loads(TRAINING.read_text(encoding="utf-8"))
    if raw.get("schema") != "veilgraph.semantic-ner-training.v1":
        raise SystemExit("Unsupported training schema")
    by_type: dict[EntityType, list[tuple[dict[str, float], int]]] = {entity_type: [] for entity_type in TYPES}
    counts = {entity_type.value: {"positive": 0, "negative": 0} for entity_type in TYPES}
    for index, item in enumerate(raw["examples"]):
        entity_type = EntityType(item["entity_type"])
        document = process_document(str(item["text"]).encode("utf-8"), FileType.TEXT, f"train-{index}.txt")
        candidates = [candidate for candidate in generate_semantic_candidates(document) if candidate.entity_type == entity_type]
        if len(candidates) != 1:
            raise SystemExit(f"Training example {index} expected one {entity_type.value} candidate, got {len(candidates)}")
        label = 1 if bool(item["accept"]) else 0
        by_type[entity_type].append((semantic_features(candidates[0]), label))
        counts[entity_type.value]["positive" if label else "negative"] += 1

    classifiers = {}
    for entity_type in TYPES:
        intercept, weights = train_binary(by_type[entity_type])
        classifiers[entity_type.value] = {
            "threshold": 0.70,
            "intercept": intercept,
            "weights": weights,
            "training_examples": counts[entity_type.value],
        }

    payload = {
        "schema": "veilgraph.semantic-ner.linear.v1",
        "version": "1.0.0",
        "model_family": "local logistic-regression span classifier",
        "training_source": "VeilGraph independent fictional semantic-context corpus v1",
        "training_corpus_sha256": hashlib.sha256(TRAINING.read_bytes()).hexdigest(),
        "runtime_network_required": False,
        "classifiers": classifiers,
    }
    MODEL.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {MODEL}")
    print(json.dumps(counts, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
