from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ROOT / "competition" / "datasets"
SHOW = DATASETS / "judge_showcase_v1"
CHAOS = DATASETS / "judge_chaos_v1"


def _manifest(path: Path) -> dict:
    return json.loads((path / "manifest.json").read_text(encoding="utf-8"))


def _ground_truth(path: Path) -> list[dict]:
    return [json.loads(line) for line in (path / "ground_truth.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _assert_manifest_integrity(dataset_dir: Path) -> None:
    manifest_path = dataset_dir / "manifest.json"
    manifest = _manifest(dataset_dir)
    commitment = (dataset_dir / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == commitment
    assert manifest["fictional_only"] is True
    assert manifest["contains_real_personal_data"] is False
    assert manifest["untouched_holdout"] is False
    assert manifest["tuning_allowed"] is True
    assert len(manifest["files"]) == manifest["file_count"]
    for item in manifest["files"]:
        target = dataset_dir / item["path"]
        assert target.is_file(), target
        assert target.stat().st_size == item["bytes"]
        assert _sha256(target) == item["sha256"]


def test_showcase_manifest_integrity() -> None:
    _assert_manifest_integrity(SHOW)
    m = _manifest(SHOW)
    assert m["dataset_id"] == "VG-JUDGE-SHOWCASE-1.0"
    assert m["file_count"] == 11
    assert m["ground_truth_occurrences"] == 409


def test_chaos_manifest_integrity() -> None:
    _assert_manifest_integrity(CHAOS)
    m = _manifest(CHAOS)
    assert m["dataset_id"] == "VG-JUDGE-CHAOS-1.0"
    assert m["file_count"] == 12
    assert m["ground_truth_occurrences"] == 108


def test_showcase_covers_every_current_format_family() -> None:
    formats = set(_manifest(SHOW)["formats"])
    assert {"TXT", "MD", "RTF", "PDF", "PNG", "DOCX", "CSV", "JSON", "XLSX", "MP4"} <= formats
    names = {item["path"] for item in _manifest(SHOW)["files"]}
    assert "04_case_packet.pdf" in names
    assert "05_scanned_application.pdf" in names
    assert "10_research_records.xlsx" in names
    assert "11_privacy_clip.mp4" in names


def test_chaos_contains_required_adversarial_stress_classes() -> None:
    tags = {tag for item in _manifest(CHAOS)["files"] for tag in item["stress_tags"]}
    required = {
        "blank-lines", "tabs", "unicode", "dense-inline", "two-column",
        "low-contrast", "rotation", "long-line", "header", "footer",
        "quoted-newline", "nested-json", "multi-sheet", "transient-frame", "qr",
    }
    assert required <= tags


def test_ground_truth_references_real_files_and_has_supported_locators() -> None:
    allowed_locator_types = {
        "char_span", "decoded_text_value", "bbox", "page_value", "docx_unit",
        "cell", "json_pointer", "frame_value", "source_value", "xlsx_cell",
    }
    total = 0
    for dataset_dir in (SHOW, CHAOS):
        manifest = _manifest(dataset_dir)
        listed = {item["path"] for item in manifest["files"]}
        gt = _ground_truth(dataset_dir)
        assert len(gt) == manifest["ground_truth_occurrences"]
        for item in gt:
            assert item["file"] in listed
            assert (dataset_dir / item["file"]).exists()
            assert item["entity_type"]
            assert str(item["value"]).strip()
            assert item["locator"]["type"] in allowed_locator_types
            if item["locator"]["type"] == "char_span":
                assert 0 <= item["locator"]["start"] < item["locator"]["end"]
        total += len(gt)
    assert total == 517


def test_ground_truth_uses_safe_fictional_contact_domains() -> None:
    all_gt = _ground_truth(SHOW) + _ground_truth(CHAOS)
    emails = [item["value"] for item in all_gt if item["entity_type"] == "EMAIL"]
    assert emails
    assert all(str(email).casefold().endswith("@example.org") for email in emails)
    mock_ids = [item for item in all_gt if item["entity_type"] in {"AADHAAR_LIKE", "PAN_LIKE"}]
    assert mock_ids


def test_level5_recommendation_is_restricted_to_structured_data() -> None:
    structured = {"CSV", "JSON", "XLSX"}
    for dataset_dir in (SHOW, CHAOS):
        for item in _manifest(dataset_dir)["files"]:
            levels = item["recommended_levels"]
            if "L5" in levels:
                assert item["format"] in structured, item
            if item["format"] not in structured:
                assert "L5" not in levels, item


def test_showcase_chaos_are_development_splits_not_holdouts_and_case_ids_are_unique() -> None:
    show = _manifest(SHOW)
    chaos = _manifest(CHAOS)
    assert show["split_role"] == "judge_demo_and_development"
    assert chaos["split_role"] == "adversarial_development_and_regression"
    assert show["untouched_holdout"] is False and chaos["untouched_holdout"] is False
    assert show["tuning_allowed"] is True and chaos["tuning_allowed"] is True
    ids = [item["case_id"] for item in show["files"] + chaos["files"]]
    assert len(ids) == len(set(ids))
