from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "competition/phase1/BROAD_PII_V5_FREEZE_MANIFEST.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v5_freeze_is_byte_exact_and_contains_new_local_ml_surface():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["schema"] == "veilgraph.broad-pii-v5-freeze.v1"
    assert len(payload["frozen_files"]) == 22
    paths = {item["path"] for item in payload["frozen_files"]}
    assert "backend/app/detection/semantic_ner_v3.py" in paths
    assert "backend/app/detection/generalization_v5.py" in paths
    assert "backend/models/semantic_ner_v3.json" in paths
    for item in payload["frozen_files"]:
        path = ROOT / item["path"]
        assert path.is_file(), item["path"]
        assert _sha(path) == item["sha256"], item["path"]


def test_v5_freeze_declares_untouched_ari_synthetic_test_protocol_before_acquisition():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    holdout = payload["planned_untouched_holdout"]
    assert holdout["repo"] == "Ari-S-123/pii-detection-english-consolidated"
    assert holdout["revision"] == "61e7c4fcd6c569d4cc89db9cba79deab833df085"
    assert holdout["split"] == "test"
    assert holdout["filter"] == "data_source == synthetic"
    assert holdout["test_parquet_lfs_sha256"] == "768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471"
    assert holdout["expected_full_test_rows"] == 31361
    assert holdout["expected_synthetic_test_rows"] == 1201
    assert holdout["opened_before_freeze"] is False
    assert holdout["used_for_v5_tuning"] is False
    assert holdout["ai4privacy_rows_excluded"] is True

def test_v5_freeze_keeps_v4_tab_as_consumed_historical_evidence():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    names = {item["name"] for item in payload["consumed_holdouts"]}
    assert "TAB ECHR test" in names
    assert all(item["may_be_used_as_untouched_for_v5"] is False for item in payload["consumed_holdouts"])
    assert payload["semantic_model"]["runtime_network_required"] is False
    assert payload["semantic_model"]["training_examples"] == 2330
