from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_external_holdout_ari.py"


def _module():
    spec = importlib.util.spec_from_file_location("veilgraph_ari_holdout", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protocol_identity_is_pinned_before_test_acquisition():
    m = _module()
    assert m.DATASET == "Ari-S-123/pii-detection-english-consolidated"
    assert m.EXPECTED_REVISION == "61e7c4fcd6c569d4cc89db9cba79deab833df085"
    assert m.EXPECTED_SYNTHETIC_TEST_ROWS == 1201
    assert m.SPLIT == "test"
    assert "synthetic" in m.FILTER_WHERE
    assert m.EXPECTED_TEST_PARQUET_LFS_SHA256 == "768d415110c5726142c38bfe82270bb6109670977c9f4ac6a7e46f4f6838e471"


def test_protocol_excludes_ai4privacy_and_unknown_taxonomy_labels_instead_of_remapping():
    m = _module()
    row = {
        "source_text": "Alice used bc1qexample and alice@example.org",
        "privacy_mask": [
            {"label": "FIRSTNAME", "start": 0, "end": 5, "value": "Alice"},
            {"label": "BITCOINADDRESS", "start": 11, "end": 22, "value": "bc1qexample"},
            {"label": "EMAIL", "start": 27, "end": 44, "value": "alice@example.org"},
        ],
        "data_source": "synthetic",
    }
    gold, excluded = m._gold_for_row(row)
    assert [g.label for g in gold] == ["FIRSTNAME", "EMAIL"]
    assert excluded["BITCOINADDRESS"] == 1


def test_relaxed_compatible_span_coverage_allows_full_name_to_cover_first_and_last_gold():
    m = _module()
    first = m.Gold("FIRSTNAME", 0, 5, "Alice", frozenset({"PERSON_NAME"}))
    last = m.Gold("LASTNAME", 6, 11, "Brown", frozenset({"PERSON_NAME"}))
    pred = m.Pred("PERSON_NAME", 0, 11, "Alice Brown")
    assert m._relaxed_match(first, pred)
    assert m._relaxed_match(last, pred)
    assert not m._exact_match(first, pred)


def test_incompatible_family_overlap_never_counts_as_true_positive():
    m = _module()
    gold = m.Gold("EMAIL", 0, 17, "alice@example.org", frozenset({"EMAIL"}))
    wrong = m.Pred("PERSON_NAME", 0, 17, "alice@example.org")
    assert not m._relaxed_match(gold, wrong)


def test_quality_gate_uses_predeclared_thresholds():
    m = _module()
    result = {
        "exact": {"f1": 0.55},
        "relaxed_compatible_span_coverage": {"f1": 0.70},
        "critical_shared_recall": 0.80,
        "contextual_shared_recall": 0.60,
        "no_entity_fp_document_rate": 0.10,
    }
    gate = m.quality_gate(result)
    assert gate["pass"] is True
    result["critical_shared_recall"] = 0.50
    assert m.quality_gate(result)["pass"] is False


def test_filter_url_targets_only_synthetic_test_split():
    m = _module()
    url = m._page_url(100, 50)
    assert "split=test" in url
    assert "offset=100" in url
    assert "length=50" in url
    assert "data_source" in url
    assert "synthetic" in url


def test_acquisition_rejects_partial_holdout(monkeypatch):
    m = _module()
    monkeypatch.setattr(m, "EXPECTED_SYNTHETIC_TEST_ROWS", 2)
    responses = [
        {"num_rows_total": 2, "rows": [{"row_idx": 1, "row": {"source_text": "A", "privacy_mask": [], "data_source": "synthetic"}, "truncated_cells": []}]},
        {"num_rows_total": 2, "rows": []},
    ]
    monkeypatch.setattr(m, "_request_json", lambda _url: responses.pop(0))
    try:
        m.acquire_filtered_rows()
    except RuntimeError as exc:
        assert "Expected 2" in str(exc)
    else:
        raise AssertionError("partial holdout must be rejected")


def test_acquisition_stream_hash_is_deterministic(monkeypatch):
    m = _module()
    monkeypatch.setattr(m, "EXPECTED_SYNTHETIC_TEST_ROWS", 1)
    monkeypatch.setattr(m, "PAGE_SIZE", 100)
    payload = {
        "num_rows_total": 1,
        "rows": [{
            "row_idx": 7,
            "row": {"source_text": "Email: a@example.org", "privacy_mask": [], "data_source": "synthetic"},
            "truncated_cells": [],
        }],
    }
    monkeypatch.setattr(m, "_request_json", lambda _url: payload)
    first_rows, first_sha, _ = m.acquire_filtered_rows()
    second_rows, second_sha, _ = m.acquire_filtered_rows()
    assert first_rows == second_rows
    assert first_sha == second_sha
    assert len(first_sha) == 64

def test_repository_metadata_drift_is_allowed_only_when_test_artifact_is_byte_identical(monkeypatch):
    m = _module()
    new_head = "a3c2add092a3bfaa7dd541fdfa1185b5777f0749"
    monkeypatch.setattr(m, "_git_head", lambda: new_head)
    monkeypatch.setattr(
        m,
        "_hash_remote_test_artifact",
        lambda _revision: m.EXPECTED_TEST_PARQUET_LFS_SHA256,
    )
    provenance = m.verify_pinned_data_artifact()
    assert provenance["pinned_data_revision"] == m.EXPECTED_REVISION
    assert provenance["observed_repository_head"] == new_head
    assert provenance["test_parquet_sha256"] == m.EXPECTED_TEST_PARQUET_LFS_SHA256
    assert provenance["data_artifact_identity_verified"] is True


def test_changed_test_artifact_is_rejected_even_if_repository_is_reachable(monkeypatch):
    m = _module()
    monkeypatch.setattr(m, "_git_head", lambda: "a" * 40)
    monkeypatch.setattr(m, "_hash_remote_test_artifact", lambda _revision: "b" * 64)
    try:
        m.verify_pinned_data_artifact()
    except RuntimeError as exc:
        assert "test artifact changed" in str(exc)
    else:
        raise AssertionError("changed external holdout artifact must be rejected")

