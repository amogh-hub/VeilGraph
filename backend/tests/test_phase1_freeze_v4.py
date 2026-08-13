from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "competition/phase1/BROAD_PII_V4_FREEZE_MANIFEST.json"
SNAPSHOT_ROOT = ROOT / "competition/frozen/broad_pii_v4"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_broad_pii_v4_historical_freeze_manifest_is_byte_exact():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["schema"] == "veilgraph.broad-pii-v4-freeze.v1"
    assert len(payload["frozen_files"]) >= 15
    for item in payload["frozen_files"]:
        path = SNAPSHOT_ROOT / item["path"]
        assert path.exists(), item["path"]
        assert _sha(path) == item["sha256"], item["path"]


def test_v4_freeze_preserves_original_veilbench_corpus():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    path = ROOT / "backend/benchmark_corpus/veilbench_curated_v1.json"
    assert _sha(path) == payload["veilbench_curated_v1_sha256"] == "ea868e30cf474a8c286c2c87d76dd9679f090c2b5ae4b4792684b3ab5f4bb8df"


def test_v4_freeze_declares_split_integrity_local_runtime_and_tab_history():
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["development_splits"] == ["VG-JUDGE-SHOWCASE-1.0", "VG-JUDGE-CHAOS-1.0"]
    assert payload["excluded_prior_holdout"]["used_for_v4_tuning"] is False
    assert payload["semantic_model"]["runtime_network_required"] is False
    assert payload["semantic_model"]["training_corpus_sha256"] == "8f604867077c48beedd793ec808f882c06b65bc016cb1a0c5c8b418c690cf840"
    # The untouched TAB result is preserved as v4 evidence; live v5 development
    # must not rewrite the historical detector bytes that produced it.
    result = ROOT / "competition/phase1/EXTERNAL_HOLDOUT_TAB_RESULTS.json"
    if result.exists():
        tab = json.loads(result.read_text(encoding="utf-8"))
        assert tab.get("schema") == "veilgraph.external-holdout.tab.v1"
        assert tab.get("results", {}).get("documents") == 127
        assert tab.get("raw_holdout_persisted_in_repository") is False
        assert tab.get("detector_tuned_on_holdout") is False
