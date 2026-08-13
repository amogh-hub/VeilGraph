from __future__ import annotations

import hashlib
import json

from app.benchmark.openpii import row_to_case
from app.benchmark.piimb import benchmark_piimb
from app.core.enums import AudienceProfile, EntityType, FileType, PrivacyLevel
from app.detection.pipeline import detect_all
from app.extraction.document_processor import processed_document_from_decoded_text, process_document
from app.policy.compiler import action_for


def _detect(text: str):
    return detect_all(processed_document_from_decoded_text(text))


def _by_type(text: str, entity_type: EntityType) -> list[str]:
    return [item.plaintext for item in _detect(text) if item.entity_type == entity_type]


def test_broad_title_name_and_generic_date_are_detected_without_cloud_models():
    text = "Dear Dr Anika Sharma, your appointment is on 10th June 1999."
    assert _by_type(text, EntityType.PERSON_TITLE) == ["Dr"]
    assert _by_type(text, EntityType.PERSON_NAME) == ["Anika Sharma"]
    assert _by_type(text, EntityType.GENERIC_DATE) == ["10th June 1999"]


def test_residence_line_is_split_into_non_overlapping_structural_location_clues():
    text = "Residence: 397 Rochelle Street, Waldorf 95203"
    detections = _detect(text)
    values = {(item.entity_type, item.plaintext) for item in detections}
    assert (EntityType.BUILDING_NUMBER, "397") in values
    assert (EntityType.STREET_ADDRESS, "Rochelle Street") in values
    assert (EntityType.LOCALITY, "Waldorf") in values
    assert (EntityType.POSTCODE, "95203") in values
    spans = sorted((item.page_char_start, item.page_char_end) for item in detections)
    assert all(right_start >= left_end for (left_start, left_end), (right_start, right_end) in zip(spans, spans[1:]))


def test_government_id_and_passport_on_same_line_do_not_cross_assign():
    text = "For compliance, government ID (ILDP7YT664) and passport (NO0040894) are required."
    assert _by_type(text, EntityType.NATIONAL_ID) == ["ILDP7YT664"]
    assert _by_type(text, EntityType.PASSPORT_NUMBER) == ["NO0040894"]


def test_tax_social_and_driver_license_contexts_are_detected():
    assert _by_type("Tax Identification Number: 11007 18052", EntityType.TAX_IDENTIFIER) == ["11007 18052"]
    assert _by_type("SSN: 123-45-6789", EntityType.SOCIAL_IDENTIFIER) == ["123-45-6789"]
    assert _by_type("Driver's License Number: D123-456-7890", EntityType.DRIVER_LICENSE_NUMBER) == ["D123-456-7890"]


def test_payment_card_context_wins_over_aadhaar_like_digit_grouping():
    text = "Credit Card: 3157 5619 4311 6246"
    assert _by_type(text, EntityType.PAYMENT_CARD_NUMBER) == ["3157 5619 4311 6246"]
    assert _by_type(text, EntityType.AADHAAR_LIKE) == []


def test_demographic_labels_and_single_character_form_values_are_detected():
    assert _by_type("Gender Identity: Genderqueer", EntityType.DEMOGRAPHIC_ATTRIBUTE) == ["Genderqueer"]
    assert _by_type("Sex: Male", EntityType.DEMOGRAPHIC_ATTRIBUTE) == ["Male"]
    assert _by_type("F.", EntityType.DEMOGRAPHIC_ATTRIBUTE) == ["F"]


def test_filler_heavy_age_field_is_detected_without_duplicate_age_span():
    assert _by_type("Age: ___________________________________ 73", EntityType.AGE) == ["73"]
    # Existing label-aware detector owns this common form as one full span.
    assert _by_type("Age: 19 years", EntityType.AGE) == ["19 years"]


def test_contextual_city_and_international_phone_are_detected():
    text = "Employees based in Poway should contact +1 (212) 555-0198."
    assert _by_type(text, EntityType.LOCALITY) == ["Poway"]
    assert _by_type(text, EntityType.PHONE) == ["+1 (212) 555-0198"]


def test_broad_layer_does_not_turn_generic_build_numbers_or_version_strings_into_credentials():
    text = "Build version 1234-5678-9012-alpha shipped with order 123456 and no personal record."
    types = {item.entity_type for item in _detect(text)}
    assert EntityType.AADHAAR_LIKE not in types
    assert EntityType.PAYMENT_CARD_NUMBER not in types
    assert EntityType.NATIONAL_ID not in types
    assert EntityType.PASSPORT_NUMBER not in types


def test_new_taxonomy_obeys_gradational_policy_semantics():
    audience = AudienceProfile.PUBLIC_RELEASE
    direct = [
        EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER, EntityType.DRIVER_LICENSE_NUMBER,
        EntityType.TAX_IDENTIFIER, EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
    ]
    for entity_type in direct:
        assert action_for(entity_type, PrivacyLevel.DIRECT_MASKING, audience) == "MASK"
        assert action_for(entity_type, PrivacyLevel.SENSITIVE_ENTITY_PROTECTION, audience) == "PROTECT"
        assert action_for(entity_type, PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION, audience) == "PSEUDONYMIZE"
    for entity_type in (EntityType.GENERIC_DATE, EntityType.PERSON_TITLE, EntityType.DEMOGRAPHIC_ATTRIBUTE, EntityType.BUILDING_NUMBER):
        assert action_for(entity_type, PrivacyLevel.DIRECT_MASKING, audience) == "RETAIN"
        assert action_for(entity_type, PrivacyLevel.CONTEXT_GENERALIZATION, audience) == "GENERALIZE"


def test_piimb_diagnostic_breakdown_is_label_aware_without_changing_official_masking_score(tmp_path):
    text = "Passport: NO0040894 and Sex: Female"
    passport = "NO0040894"
    female = "Female"
    row = {
        "uid": "mini-v2",
        "task_name": "ai4privacy-en",
        "text": text,
        "entities": [
            {"start": text.index(passport), "end": text.index(passport) + len(passport), "label": "PASSPORTNUM"},
            {"start": text.index(female), "end": text.index(female) + len(female), "label": "SEX"},
        ],
        "language": "en",
    }
    path = tmp_path / "mini-piimb.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    result = benchmark_piimb(path, task="ai4privacy-en", limit=1)
    assert result["dataset"]["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["precision"] == 1.0
    assert result["diagnostic_by_gold_label"]["PASSPORTNUM"]["recall"] == 1.0
    assert result["diagnostic_by_gold_label"]["SEX"]["recall"] == 1.0


def test_broad_identifiers_run_through_end_to_end_fail_closed_release_gate(client):
    text = """PUBLIC RELEASE FIXTURE
Name: Anika Sharma
Passport Number: NO0040894
National ID Card Number: 6152564981451
Tax Identification Number: 11007-18052
Credit Card: 3157 5619 4311 6246
Residence: 397 Rochelle Street, Waldorf 95203
Gender Identity: Genderqueer
"""
    created = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public evidence release",
            "recipient": "Citizen information portal",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
        },
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("broad.txt", text.encode("utf-8"), "text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    detected_types = {item["entity"]["entity_type"] for item in entities}
    assert {"PASSPORT_NUMBER", "NATIONAL_ID", "TAX_IDENTIFIER", "PAYMENT_CARD_NUMBER"}.issubset(detected_types)
    for item in entities:
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                reviewed = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert reviewed.status_code == 200, reviewed.text
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["passed"] == 12 and proof["failed"] == 0 and proof["inconclusive"] == 0
    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    protected = downloaded.content.decode("utf-8")
    for original in ("NO0040894", "6152564981451", "11007-18052", "3157 5619 4311 6246"):
        assert original not in protected
