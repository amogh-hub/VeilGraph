from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "backend" / "run_holdout_nemotron.py"
MANIFEST = ROOT / "competition" / "HOLDOUT_FREEZE_MANIFEST.json"
SNAPSHOT_ROOT = ROOT / "competition" / "frozen" / "broad_pii_v3"


def _module():
    spec = importlib.util.spec_from_file_location("run_holdout_nemotron", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _detector_locked_items(manifest: dict) -> list[dict]:
    return [
        item for item in manifest["locked_files"]
        if item["path"].startswith("backend/app/detection/")
        or item["path"] == "backend/models/semantic_ner_v1.json"
    ]


def test_holdout_manifest_remains_historical_pre_evaluation_evidence():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["frozen_detector"] == "Broad-Coverage PII Engine v3"
    assert manifest["verified_test_baseline"] == 135
    assert manifest["holdout_task"] == "nemotron-pii"
    assert manifest["policy"]["holdout_must_not_be_used_to_tune_v3"] is True
    # Keep the original broad source lock unchanged as historical evidence of
    # exactly what was frozen when the untouched holdout was first executed.
    assert len(manifest["locked_files"]) >= 30


def test_broad_pii_v3_detector_itself_still_matches_pre_holdout_hashes():
    """Verify the immutable historical v3 snapshot, not today's production generation.

    The original Nemotron manifest remains untouched.  Later detector generations
    are allowed to evolve the live pipeline, while this byte-exact snapshot keeps
    the source that was actually frozen for the v3 holdout independently auditable.
    """
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    detector_items = _detector_locked_items(manifest)
    assert len(detector_items) >= 8
    mismatches: list[str] = []
    for item in detector_items:
        path = SNAPSHOT_ROOT / item["path"]
        if not path.is_file() or _sha256(path) != item["sha256"]:
            mismatches.append(item["path"])
    assert mismatches == [], f"Historical frozen v3 detector snapshot changed: {mismatches}"


def test_holdout_uses_separate_evidence_files_and_historical_runner_stays_locked():
    module = _module()
    assert module.OUT_JSON.name == "HOLDOUT_NEMOTRON_RESULTS.json"
    assert module.OUT_MD.name == "HOLDOUT_NEMOTRON_REPORT.md"
    assert module.OUT_JSON.name != "veilbench-results.json"
    # The original runner intentionally continues to verify the full historical
    # source snapshot. Post-holdout product work (L5, DOCX, video, UI) must not
    # rewrite that manifest or masquerade as a second untouched evaluation.
    manifest = module.load_manifest()
    assert len(manifest["locked_files"]) >= 30
