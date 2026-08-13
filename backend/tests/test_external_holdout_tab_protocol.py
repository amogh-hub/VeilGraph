from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_external_holdout_tab.py"


def _load():
    spec = importlib.util.spec_from_file_location("vg_tab_holdout", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture_bytes() -> bytes:
    filler = "x" * 1_000_050
    text = "John Smith lives in Oslo. Reference 42552/98. Common court. " + filler
    return json.dumps([
        {
            "dataset_type": "test",
            "doc_id": "fixture-1",
            "text": text,
            "annotations": {
                "annotator-a": {
                    "entity_mentions": [
                        {
                            "entity_id": "e1",
                            "entity_type": "PERSON",
                            "identifier_type": "DIRECT",
                            "start_offset": 0,
                            "end_offset": 10,
                            "span_text": "John Smith",
                        },
                        {
                            "entity_id": "e2",
                            "entity_type": "LOC",
                            "identifier_type": "QUASI",
                            "start_offset": 20,
                            "end_offset": 24,
                            "span_text": "Oslo",
                        },
                        {
                            "entity_id": "e3",
                            "entity_type": "ORG",
                            "identifier_type": "NO_MASK",
                            "start_offset": 46,
                            "end_offset": 58,
                            "span_text": "Common court",
                        },
                    ]
                }
            },
        }
    ] * 25).encode("utf-8")


def test_runner_points_only_to_official_tab_test_split():
    m = _load()
    assert m.SOURCE_REPOSITORY == "NorskRegnesentral/text-anonymization-benchmark"
    assert m.SOURCE_FILE == "echr_test.json"
    assert m.SOURCE_BRANCH == "master"
    assert "train" not in m.SOURCE_FILE.lower()
    assert "dev" not in m.SOURCE_FILE.lower()


def test_parser_accepts_official_shape_and_rejects_non_test():
    m = _load()
    rows = m.parse_tab_bytes(_fixture_bytes())
    assert len(rows) == 25
    bad = json.loads(_fixture_bytes())
    bad[0]["dataset_type"] = "train"
    data = json.dumps(bad).encode()
    try:
        m.parse_tab_bytes(data)
    except ValueError as exc:
        assert "not test" in str(exc)
    else:
        raise AssertionError("non-test data was accepted")


def test_gold_separates_direct_quasi_from_no_mask():
    m = _load()
    record = m.parse_tab_bytes(_fixture_bytes())[0]
    _, mentions = m._annotation_sets(record)[0]
    gold, no_mask = m._gold_entries(record["text"], mentions)
    assert [x["identifier_type"] for x in gold] == ["DIRECT", "QUASI"]
    assert [x["identifier_type"] for x in no_mask] == ["NO_MASK"]


def test_strict_value_scorer_is_multiset_safe():
    m = _load()
    gold = [
        {"value": "john smith", "entity_type": "PERSON"},
        {"value": "john smith", "entity_type": "PERSON"},
        {"value": "oslo", "entity_type": "LOC"},
    ]
    tp, fp, fn, by_cat = m._score_values(gold, ["john smith", "oslo", "extra"])
    assert (tp, fp, fn) == (2, 1, 1)
    assert by_cat[("PERSON", "fn")] == 1


def test_runner_freeze_check_occurs_before_acquisition_and_after_evaluation():
    text = SCRIPT.read_text()
    main = text[text.index("def main"):]
    before = main.index("freeze_sha = verify_freeze()")
    acquire = main.index("acquire_official_source()")
    evaluate = main.index("evaluate_records(records)")
    after = main.index("freeze_after = verify_freeze()")
    assert before < acquire < evaluate < after


def test_runner_records_aggregate_only_and_uses_temp_clone():
    text = SCRIPT.read_text()
    assert "TemporaryDirectory" in text
    assert "raw_holdout_persisted_in_repository\": False" in text
    assert "EXTERNAL_HOLDOUT_TAB_RESULTS.json" in text
    assert "EXTERNAL_HOLDOUT_TAB_REPORT.md" in text
    assert "echr_test.json" in text
