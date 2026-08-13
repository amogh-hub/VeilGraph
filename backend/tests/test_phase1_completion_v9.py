from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.core.enums import EntityType, FileType
from app.detection.pipeline import detect_all
from app.detection.semantic_ner_v2 import semantic_model_v2_metadata
from app.extraction.document_processor import process_document, processed_document_from_decoded_text

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "competition" / "datasets"
BACKEND = ROOT / "backend"


def _pairs(text: str):
    doc = processed_document_from_decoded_text(text)
    return {(item.entity_type, item.plaintext) for item in detect_all(doc)}


def _job(client, *, purpose: str, recipient: str, audience: str, filename: str, data: bytes, media: str):
    created = client.post("/api/v1/jobs", json={
        "purpose": purpose,
        "recipient": recipient,
        "audience_profile": audience,
        "privacy_level": 1,
    })
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    upload = client.post(f"/api/v1/jobs/{job_id}/files", files={"file": (filename, data, media)})
    assert upload.status_code == 201, upload.text
    file_id = upload.json()["id"]
    analysis = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysis.status_code == 200, analysis.text
    return job_id, file_id


def test_semantic_v2_is_local_reproducible_and_bound_to_training_corpus():
    meta = semantic_model_v2_metadata()
    corpus = BACKEND / "training_data" / "semantic_ner_train_v2.json"
    payload = json.loads(corpus.read_text())
    assert meta["schema"] == "veilgraph.semantic-ner.linear.v2"
    assert meta["version"] == "2.0.0"
    assert meta["runtime_network_required"] is False
    assert meta["model_family"] == "local logistic-regression span classifier"
    assert len(payload["examples"]) == 97
    assert payload["contains_real_pii"] is False
    assert hashlib.sha256(corpus.read_bytes()).hexdigest() == meta["training_corpus_sha256"]


def test_broad_pii_v3_source_remains_frozen_while_later_generations_are_added():
    historical = ROOT / "competition" / "frozen" / "broad_pii_v3" / "backend" / "app" / "detection" / "broad_pii.py"
    assert historical.is_file()
    assert hashlib.sha256(historical.read_bytes()).hexdigest() == \
        "e842c6d390826586219196d6aab249b1303f42644c7faa63bc646f7fef30b852"


def test_v4_common_label_semantics_cover_direct_and_contextual_fields():
    pairs = _pairs(
        "Name: Rohan Das\nEmail: rohan.das@example.org\nPhone: +91 90000 10123\n"
        "Age: 31\nCity: Mysuru\nOrganisation: Meridian Research Labs\nCase Ref: CASE-RD-2609\nPostal: 570001\n"
    )
    expected = {
        (EntityType.PERSON_NAME, "Rohan Das"),
        (EntityType.EMAIL, "rohan.das@example.org"),
        (EntityType.PHONE, "+91 90000 10123"),
        (EntityType.AGE, "31"),
        (EntityType.LOCALITY, "Mysuru"),
        (EntityType.EMPLOYER, "Meridian Research Labs"),
        (EntityType.CASE_REFERENCE, "CASE-RD-2609"),
        (EntityType.POSTCODE, "570001"),
    }
    assert expected.issubset(pairs)


def test_v4_dense_inline_fields_are_format_agnostic():
    pairs = _pairs("owner=Tara Singh|mail=tara.singh@example.org|mobile=9000012345|city=Jaipur|case ref=TR-CASE-2609")
    assert (EntityType.PERSON_NAME, "Tara Singh") in pairs
    assert (EntityType.EMAIL, "tara.singh@example.org") in pairs
    assert any(t == EntityType.PHONE and "9000012345" in v for t, v in pairs)
    assert (EntityType.LOCALITY, "Jaipur") in pairs
    assert (EntityType.CASE_REFERENCE, "TR-CASE-2609") in pairs


def test_v4_unicode_labelled_person_and_transliterated_locality():
    pairs = _pairs("Participant: ಅನನ್ಯಾ ರಾವ್ — Ananya Rao\nCity: Mysuru (ಮೈಸೂರು)\n")
    assert any(t == EntityType.PERSON_NAME and "Ananya Rao" in v for t, v in pairs)
    assert (EntityType.LOCALITY, "Mysuru") in pairs


def test_v4_semantic_ml_detects_unlabelled_context_not_just_regex_fields():
    pairs = _pairs("Nisha Kulkarni submitted the fictional record. She works at Nimbus Research Foundation in Pune.")
    assert (EntityType.PERSON_NAME, "Nisha Kulkarni") in pairs
    assert any(t == EntityType.EMPLOYER and "Nimbus Research Foundation" in v for t, v in pairs)
    assert any(t == EntityType.LOCALITY and v == "Pune" for t, v in pairs)


def test_v4_does_not_turn_generic_privacy_phrases_into_people():
    pairs = _pairs("Public release requires identity exposure review. Machine learning supports data protection. End.")
    assert not any(t == EntityType.PERSON_NAME for t, _ in pairs)


def test_absolute_opc_xlsx_relationships_are_accepted_and_normalized():
    path = DATA / "judge_chaos_v1" / "11_merged_mixed.xlsx"
    doc = process_document(path.read_bytes(), FileType.DATASET, path.name)
    assert doc.metadata["structured_format"] == "XLSX"
    assert doc.metadata["structured_sheets"] == 2
    assert doc.metadata["structured_records"] == 8


def test_signature_detector_handles_mark_merged_into_same_ocr_line():
    path = DATA / "judge_showcase_v1" / "06_identity_card.png"
    doc = process_document(path.read_bytes(), FileType.IMAGE, path.name)
    detections = detect_all(doc)
    signatures = [item for item in detections if item.entity_type == EntityType.SIGNATURE_CANDIDATE]
    assert signatures
    assert signatures[0].rect[2] > signatures[0].rect[0]
    assert signatures[0].rect[3] > signatures[0].rect[1]


def test_public_release_recommends_l4_with_explainable_previews(client):
    data = b"Name: Rohan Das\nEmail: rohan.das@example.org\nAge: 31\nCity: Mysuru\n"
    job_id, file_id = _job(client, purpose="Public evidence release", recipient="Open citizen portal", audience="PUBLIC_RELEASE", filename="case.txt", data=data, media="text/plain")
    response = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/privacy-recommendation")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["recommended_level"] == 4
    assert result["minimum_level"] == 4
    assert result["policy_floor_enforced"] is False
    assert len(result["previews"]) == 5
    assert result["previews"][4]["supported"] is False
    assert result["previews"][3]["residual_risk"] <= result["previews"][0]["residual_risk"]


def test_internal_operations_default_to_l1_when_no_high_risk_credential(client):
    data = b"Name: Rohan Das\nEmail: rohan.das@example.org\n"
    job_id, file_id = _job(client, purpose="Internal operations", recipient="Same team", audience="INTERNAL_OPERATIONS", filename="case.txt", data=data, media="text/plain")
    result = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/privacy-recommendation").json()
    assert result["recommended_level"] == 1
    assert result["minimum_level"] == 1


def test_research_analytics_recommends_context_generalization(client):
    data = b"Name: Rohan Das\nAge: 31\nCity: Mysuru\n"
    job_id, file_id = _job(client, purpose="Cohort analytics study", recipient="University research partner", audience="RESEARCH_PARTNER", filename="case.txt", data=data, media="text/plain")
    result = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/privacy-recommendation").json()
    assert result["recommended_level"] in {3, 4}
    assert result["minimum_level"] == 2


def test_structured_training_dataset_recommends_real_l5(client):
    data = b"full_name,email,age,city\nRohan Das,rohan.das@example.org,31,Mysuru\n"
    job_id, file_id = _job(client, purpose="Create a shareable ML training dataset", recipient="Model development team", audience="RESEARCH_PARTNER", filename="cohort.csv", data=data, media="text/csv")
    result = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/privacy-recommendation").json()
    assert result["recommended_level"] == 5
    assert result["previews"][4]["supported"] is True


def test_nonstructured_synthetic_request_is_not_faked_as_l5(client):
    data = b"Name: Rohan Das\nEmail: rohan.das@example.org\n"
    job_id, file_id = _job(client, purpose="Create a synthetic shareable dataset", recipient="External partner", audience="PUBLIC_RELEASE", filename="case.txt", data=data, media="text/plain")
    result = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/privacy-recommendation").json()
    assert result["recommended_level"] == 4
    assert result["previews"][4]["supported"] is False
    assert any("L5" in reason for reason in result["reasons"])
