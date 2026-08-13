from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dataclasses import replace

from app.core.enums import EntityType, FileType
from app.detection.pipeline import detect_all
from app.detection.semantic_ner_v3 import generate_semantic_candidates_v3, semantic_model_v3_metadata
from app.extraction.document_processor import processed_document_from_decoded_text

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _pairs(text: str):
    doc = processed_document_from_decoded_text(text)
    return {(item.entity_type, item.plaintext) for item in detect_all(doc)}


def _mentions(text: str):
    return detect_all(processed_document_from_decoded_text(text))


def test_semantic_v3_is_local_reproducible_and_bound_to_large_synthetic_corpus():
    meta = semantic_model_v3_metadata()
    corpus = BACKEND / "training_data" / "semantic_ner_train_v3.json"
    payload = json.loads(corpus.read_text(encoding="utf-8"))
    assert meta["schema"] == "veilgraph.semantic-ner.linear.v3"
    assert meta["version"] == "3.0.0"
    assert meta["runtime_network_required"] is False
    assert meta["model_family"] == "local logistic-regression contextual span classifier"
    assert len(payload["examples"]) == 2330
    assert payload["contains_real_pii"] is False
    assert hashlib.sha256(corpus.read_bytes()).hexdigest() == meta["training_corpus_sha256"]


def test_v5_long_form_legal_appositive_and_honorific_names_are_tight_spans():
    mentions = _mentions(
        "The applicant, John Michael Smith, submitted the claim. "
        "Mr. Smith later moved to London."
    )
    people = [m.plaintext for m in mentions if m.entity_type == EntityType.PERSON_NAME]
    assert "John Michael Smith" in people
    assert "Smith" in people
    assert not any("moved to London" in value for value in people)


def test_v5_employer_job_title_and_locality_generalize_unlabelled_prose():
    pairs = _pairs(
        "Dr. Alice Brown works at Meridian Health Trust as a Senior Analyst. "
        "She resides in Bristol."
    )
    assert (EntityType.PERSON_NAME, "Alice Brown") in pairs
    assert (EntityType.EMPLOYER, "Meridian Health Trust") in pairs
    assert (EntityType.JOB_TITLE, "Senior Analyst") in pairs
    assert (EntityType.LOCALITY, "Bristol") in pairs
    assert (EntityType.PERSON_NAME, "She") not in pairs


def test_v5_direct_field_coverage_does_not_consume_following_sentence_labels():
    pairs = _pairs(
        "Claimant: Maria Elena Torres. Passport Number: XG742901. "
        "Date of Birth: 14 March 1988. Policy Reference: PL-88219-A."
    )
    assert (EntityType.PERSON_NAME, "Maria Elena Torres") in pairs
    assert (EntityType.PASSPORT_NUMBER, "XG742901") in pairs
    assert (EntityType.DATE_OF_BIRTH, "14 March 1988") in pairs
    assert (EntityType.CASE_REFERENCE, "PL-88219-A") in pairs
    assert not any(t == EntityType.PASSPORT_NUMBER and value != "XG742901" for t, value in pairs)


def test_v5_single_token_first_and_surname_fields_are_detected():
    pairs = _pairs("First name: Alice\nSurname: Brown\nAccount reference: AC-88-19\nNHS number: 943 476 5919")
    assert (EntityType.PERSON_NAME, "Alice") in pairs
    assert (EntityType.PERSON_NAME, "Brown") in pairs
    assert (EntityType.CASE_REFERENCE, "AC-88-19") in pairs
    assert (EntityType.SOCIAL_IDENTIFIER, "943 476 5919") in pairs


def test_v5_generic_privacy_headings_and_pronouns_are_not_people():
    mentions = _mentions(
        "Public Release stated that Privacy Policy requires review. "
        "Support Case Brief. Support Video. She said the record was complete."
    )
    assert not any(m.entity_type == EntityType.PERSON_NAME for m in mentions)


def test_v5_preserves_structural_address_decomposition():
    pairs = _pairs("Residence: 397 Rochelle Street, Waldorf 95203")
    assert (EntityType.BUILDING_NUMBER, "397") in pairs
    assert (EntityType.STREET_ADDRESS, "Rochelle Street") in pairs
    assert (EntityType.LOCALITY, "Waldorf") in pairs
    assert (EntityType.POSTCODE, "95203") in pairs
    assert (EntityType.STREET_ADDRESS, "397 Rochelle Street, Waldorf 95203") not in pairs


def test_v5_semantic_free_text_layer_does_not_run_on_frozen_structured_adapters():
    text_doc = processed_document_from_decoded_text("The applicant, Alice Brown, filed the report.")
    assert generate_semantic_candidates_v3(text_doc)
    for file_type in (FileType.DATASET, FileType.DOCX, FileType.VIDEO):
        adapted = replace(text_doc, file_type=file_type)
        assert generate_semantic_candidates_v3(adapted) == []


def test_v5_same_class_overlap_fusion_keeps_one_tight_semantic_person_span():
    mentions = _mentions("Dr. Alice Brown works at Meridian Health Trust as a Senior Analyst.")
    people = [m for m in mentions if m.entity_type == EntityType.PERSON_NAME]
    assert len(people) == 1
    assert people[0].plaintext == "Alice Brown"
    assert (people[0].context_label or "").startswith("semantic-ner-v3:")


def test_v5_broad_international_label_coverage_for_unseen_forms():
    pairs = _pairs(
        "Full Name: Rajesh Kumar. Date of Birth: 15th March 1985. "
        "Driver License Number: MH7626586152129. Passport Number: Z40066530. "
        "Tax File Number: 184 392 675. National ID: L765A49231. "
        "Policy Number: POL-7473279424. Postal Code: 560001."
    )
    assert (EntityType.PERSON_NAME, "Rajesh Kumar") in pairs
    assert (EntityType.DATE_OF_BIRTH, "15th March 1985") in pairs
    assert (EntityType.DRIVER_LICENSE_NUMBER, "MH7626586152129") in pairs
    assert (EntityType.PASSPORT_NUMBER, "Z40066530") in pairs
    assert (EntityType.TAX_IDENTIFIER, "184 392 675") in pairs
    assert (EntityType.NATIONAL_ID, "L765A49231") in pairs
    assert (EntityType.CASE_REFERENCE, "POL-7473279424") in pairs
    assert (EntityType.POSTCODE, "560001") in pairs


def test_v5_bare_name_field_is_context_anchored_not_heading_guessing():
    pairs = _pairs("Name: María González López\nPrivacy Policy: public release review")
    assert (EntityType.PERSON_NAME, "María González López") in pairs
    assert not any(t == EntityType.PERSON_NAME and "Privacy" in value for t, value in pairs)
