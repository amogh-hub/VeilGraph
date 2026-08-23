from __future__ import annotations

import hashlib
from pathlib import Path

from app.benchmark.veilbench import benchmark_curated
from app.core.enums import EntityType, FileType, ReviewStatus
from app.detection.pipeline import detect_all
from app.detection.semantic_ner import semantic_model_metadata
from app.extraction.document_processor import process_document


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark_corpus" / "veilbench_curated_v1.json"
# Frozen 94-test baseline corpus; semantic work must never edit the evaluation set.
FROZEN_CORPUS_SHA256 = "ea868e30cf474a8c286c2c87d76dd9679f090c2b5ae4b4792684b3ab5f4bb8df"


def _detect(text: str):
    document = process_document(text.encode("utf-8"), FileType.TEXT, "semantic.txt")
    return detect_all(document)


def _values(text: str, entity_type: EntityType) -> list[str]:
    return [m.plaintext for m in _detect(text) if m.entity_type == entity_type]


def test_frozen_veilbench_corpus_was_not_modified_by_semantic_work():
    assert hashlib.sha256(CORPUS.read_bytes()).hexdigest() == FROZEN_CORPUS_SHA256


def test_semantic_model_is_local_versioned_and_has_training_provenance():
    metadata = semantic_model_metadata()
    assert metadata["schema"] == "veilgraph.semantic-ner.linear.v1"
    assert metadata["version"] == "1.0.0"
    assert metadata["runtime_network_required"] is False
    training = ROOT / "training_data" / "semantic_ner_train_v1.json"
    assert metadata["training_corpus_sha256"] == hashlib.sha256(training.read_bytes()).hexdigest()


def test_semantic_ner_finds_unlabelled_prose_person_names_and_requires_review():
    detections = _detect("Aarav Testperson submitted the report yesterday and requested public release.")
    names = [m for m in detections if m.entity_type == EntityType.PERSON_NAME]
    assert [m.plaintext for m in names] == ["Aarav Testperson"]
    assert names[0].review_status == ReviewStatus.PENDING
    # v5 freezes Semantic NER v3 provenance. The entity/review contract is
    # unchanged; the context label now records the exact v3 strategy.
    assert names[0].context_label == "semantic-ner-v3:person_name:sentence-person"


def test_semantic_ner_finds_name_after_action_verb():
    assert _values(
        "The reviewer thanked Meera Sampleperson for completing the audit.", EntityType.PERSON_NAME
    ) == ["Meera Sampleperson"]


def test_semantic_ner_finds_address_employer_and_job_title_in_prose():
    assert _values(
        "The letter was delivered to 51 Example Avenue Bengaluru before noon.", EntityType.STREET_ADDRESS
    ) == ["51 Example Avenue Bengaluru"]
    text = "Kavya works at Example Institute of Technology as a Security Analyst."
    assert _values(text, EntityType.EMPLOYER) == ["Example Institute of Technology"]
    assert _values(text, EntityType.JOB_TITLE) == ["Security Analyst"]


def test_aadhaar_like_rejects_embedded_software_version_but_keeps_standalone_fixture():
    assert _values(
        "Build version 1234-5678-9012-alpha is not an Aadhaar number.", EntityType.AADHAAR_LIKE
    ) == []
    assert _values("Aadhaar: 1234 5678 9012", EntityType.AADHAAR_LIKE) == ["1234 5678 9012"]


def test_semantic_layer_does_not_promote_common_capitalized_role_phrase_to_person():
    assert _values("Security Analyst submitted a generic template.", EntityType.PERSON_NAME) == []


def test_frozen_legacy_veilbench_records_the_exact_v5_observation_without_rewriting_corpus():
    result = benchmark_curated(CORPUS)
    # The v1 corpus is frozen historical evidence. Broad PII v5 intentionally
    # expands person detection beyond that corpus's annotation scope; preserve
    # the measured v5 observation instead of mutating the corpus or post-holdout
    # detector to manufacture the old 1.0 score. Recall remains complete.
    assert result["overall"]["tp"] == 85
    assert result["overall"]["fp"] == 2
    assert result["overall"]["fn"] == 0
    assert result["overall"]["precision"] == 0.977011
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 0.988372
    assert result["exact_case_passes"] == 30
    assert result["case_count"] == 32
