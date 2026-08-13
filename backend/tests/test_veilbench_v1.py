from __future__ import annotations

import json
from pathlib import Path

from app.benchmark.openpii import load_openpii_jsonl, row_to_case
from app.benchmark.veilbench import BenchmarkCase, GoldSpan, benchmark_cases, load_curated_corpus
from app.core.enums import EntityType


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark_corpus" / "veilbench_curated_v1.json"


def test_curated_corpus_is_fictional_auditable_and_broad():
    raw = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = load_curated_corpus(CORPUS)
    assert raw["license"] == "CC0-1.0"
    assert len(cases) >= 30
    types = {gold.entity_type for case in cases for gold in case.gold}
    expected = {
        EntityType.PERSON_NAME, EntityType.PHONE, EntityType.EMAIL, EntityType.AADHAAR_LIKE,
        EntityType.PAN_LIKE, EntityType.DATE_OF_BIRTH, EntityType.AGE, EntityType.STREET_ADDRESS,
        EntityType.LOCALITY, EntityType.POSTCODE, EntityType.EMPLOYER, EntityType.JOB_TITLE,
        EntityType.CASE_REFERENCE,
    }
    assert expected <= types


def test_gold_spans_are_resolved_to_exact_source_text():
    for case in load_curated_corpus(CORPUS):
        for gold in case.gold:
            assert case.text[gold.start:gold.end] == gold.value


def test_benchmark_reports_real_tp_fp_fn_and_standard_metrics():
    case = BenchmarkCase(
        case_id="metric-test",
        domain="test",
        text="Email: alpha@example.org",
        gold=(GoldSpan(EntityType.EMAIL, "alpha@example.org", 7, 24),),
    )
    result = benchmark_cases([case])
    assert result["overall"]["tp"] == 1
    assert result["overall"]["fp"] == 0
    assert result["overall"]["fn"] == 0
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 1.0


def test_benchmark_keeps_per_entity_and_per_domain_evidence():
    result = benchmark_cases(load_curated_corpus(CORPUS)[:6])
    assert "EMAIL" in result["per_entity"]
    assert "government" in result["per_domain"]
    assert result["performance"]["median_case_ms"] >= 0
    assert result["performance"]["peak_process_rss_mb"] > 0


def test_openpii_new_schema_maps_supported_labels_and_discloses_unmapped():
    text = "Alice can be reached at alice@example.org; account 778899 is private."
    row = {
        "source_text": text,
        "language": "en",
        "privacy_mask": [
            {"label": "GIVENNAME", "start": 0, "end": 5, "value": "Alice"},
            {"label": "EMAIL", "start": 24, "end": 41, "value": "alice@example.org"},
            {"label": "ACCOUNTNUMBER", "start": 51, "end": 57, "value": "778899"},
        ],
    }
    case, counts = row_to_case(row, 0)
    assert case is not None
    assert [gold.entity_type for gold in case.gold] == [EntityType.PERSON_NAME, EntityType.EMAIL]
    assert counts["unmapped:ACCOUNTNUMBER"] == 1


def test_openpii_old_schema_is_supported():
    text = "Email alpha@example.org"
    row = {
        "unmasked_text": text,
        "language": "English",
        "span_labels": [[0, 6, "O"], [6, 23, "EMAIL_1"]],
    }
    case, counts = row_to_case(row, 1)
    assert case is not None
    assert len(case.gold) == 1
    assert case.gold[0].entity_type == EntityType.EMAIL
    assert counts["mapped:EMAIL"] == 1


def test_openpii_jsonl_loader_is_deterministic_and_language_filtered(tmp_path):
    rows = [
        {"source_text": "Email: a@example.org", "language": "en", "privacy_mask": [{"label": "EMAIL", "start": 7, "end": 20, "value": "a@example.org"}]},
        {"source_text": "Email: b@example.org", "language": "de", "privacy_mask": [{"label": "EMAIL", "start": 7, "end": 20, "value": "b@example.org"}]},
    ]
    path = tmp_path / "openpii.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    cases, counts = load_openpii_jsonl(path, limit=10, language="en")
    assert len(cases) == 1
    assert cases[0].case_id == "openpii-0000000"
    assert counts["language_filtered"] == 1


def test_entity_extraction_false_positive_rate_definition_is_explicit():
    result = benchmark_cases(load_curated_corpus(CORPUS)[:3])
    definitions = result["metric_definition"]
    assert "not a TN-based" in definitions["prediction_false_positive_rate"]
    assert definitions["precision"] == "TP / (TP + FP)"
    assert definitions["recall"] == "TP / (TP + FN)"

from app.benchmark.piimb import benchmark_piimb, load_piimb_jsonl


def test_piimb_loader_filters_task_and_preserves_negative_rows(tmp_path):
    rows = [
        {"uid": "a", "task_name": "ai4privacy-en", "text": "No PII here", "entities": [], "language": "en"},
        {"uid": "b", "task_name": "ai4privacy-en", "text": "Email a@example.org", "entities": [{"start": 6, "end": 19, "label": "EMAIL"}], "language": "en"},
        {"uid": "c", "task_name": "gretel", "text": "Email b@example.org", "entities": [{"start": 6, "end": 19, "label": "EMAIL"}], "language": "en"},
    ]
    path = tmp_path / "piimb.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    loaded, counters = load_piimb_jsonl(path, task="ai4privacy-en", limit=10)
    assert len(loaded) == 2
    assert loaded[0]["entities"] == []
    assert counters["task_filtered"] == 1


def test_piimb_character_metrics_produce_true_fpr(tmp_path):
    rows = [
        {"uid": "a", "task_name": "ai4privacy-en", "text": "Email: alpha@example.org", "entities": [{"start": 7, "end": 24, "label": "EMAIL"}], "language": "en"},
        {"uid": "b", "task_name": "ai4privacy-en", "text": "No private values here.", "entities": [], "language": "en"},
    ]
    path = tmp_path / "piimb.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    result = benchmark_piimb(path, task="ai4privacy-en", limit=10)
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 1.0
    assert result["overall"]["f2"] == 1.0
    assert result["overall"]["fpr"] == 0.0
