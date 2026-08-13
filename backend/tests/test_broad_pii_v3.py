from __future__ import annotations

from app.core.enums import EntityType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import processed_document_from_decoded_text


def _detect(text: str):
    return detect_all(processed_document_from_decoded_text(text))


def _values(text: str, entity_type: EntityType) -> list[str]:
    return [item.plaintext for item in _detect(text) if item.entity_type == entity_type]


def test_v3_unlabelled_compound_address_is_decomposed():
    text = "Please send the package to 221B Baker Street, London NW1 6XE."
    values = {(item.entity_type, item.plaintext) for item in _detect(text)}
    assert (EntityType.BUILDING_NUMBER, "221B") in values
    assert (EntityType.STREET_ADDRESS, "Baker Street") in values
    assert (EntityType.LOCALITY, "London") in values
    assert (EntityType.POSTCODE, "NW1 6XE") in values


def test_v3_street_suffix_is_detected_without_explicit_address_label():
    assert "Rochelle Street" in _values("Meet me near Rochelle Street tomorrow.", EntityType.STREET_ADDRESS)


def test_v3_international_postcode_labels_are_supported():
    assert _values("Postal code: K1A 0B1", EntityType.POSTCODE) == ["K1A 0B1"]


def test_v3_city_label_is_detected():
    assert _values("Birthplace: Bengaluru", EntityType.LOCALITY) == ["Bengaluru"]


def test_v3_contextual_city_candidate_is_generated_for_location_bearing_verb():
    assert "Poway" in _values("She moved to Poway last year.", EntityType.LOCALITY)


def test_v3_my_name_is_context_detects_person():
    assert _values("My name is Anika Sharma.", EntityType.PERSON_NAME) == ["Anika Sharma"]


def test_v3_prepared_by_context_detects_person():
    assert _values("Prepared by Mateo García on 10 June 2026.", EntityType.PERSON_NAME) == ["Mateo García"]


def test_v3_sentence_start_person_context_detects_name():
    assert _values("Aarav Mehta lives nearby.", EntityType.PERSON_NAME) == ["Aarav Mehta"]


def test_v3_passport_hash_label_is_supported():
    assert _values("Passport #: XH923441", EntityType.PASSPORT_NUMBER) == ["XH923441"]


def test_v3_driver_licence_abbreviation_is_supported():
    assert _values("DL No: D123-456-7890", EntityType.DRIVER_LICENSE_NUMBER) == ["D123-456-7890"]


def test_v3_identification_number_context_is_supported():
    assert _values("Identification Number: AB-9271643", EntityType.NATIONAL_ID) == ["AB-9271643"]


def test_v3_luhn_valid_unlabelled_card_is_detected():
    # Standard synthetic/test number satisfying Luhn; no real account is implied.
    assert _values("Reference payment used 4111 1111 1111 1111 for the test fixture.", EntityType.PAYMENT_CARD_NUMBER) == ["4111 1111 1111 1111"]


def test_v3_invalid_unlabelled_long_number_is_not_promoted_to_payment_card():
    assert _values("Build artifact 4111 1111 1111 1112 completed.", EntityType.PAYMENT_CARD_NUMBER) == []


def test_v3_hyphenated_year_old_age_is_detected():
    assert "42" in _values("The participant is a 42-year-old researcher.", EntityType.AGE)


def test_v3_first_person_age_is_detected():
    assert _values("I am 37 years old.", EntityType.AGE) == ["37"]


def test_v3_identifies_as_demographic_context_is_detected():
    assert _values("The respondent identifies as non-binary.", EntityType.DEMOGRAPHIC_ATTRIBUTE) == ["non-binary"]


def test_v3_first_person_demographic_context_is_detected():
    assert _values("I am female.", EntityType.DEMOGRAPHIC_ATTRIBUTE) == ["female"]


def test_v3_negative_location_and_name_controls_do_not_overmask_generic_phrases():
    detections = _detect("The office is in the company building and the Privacy Policy was reviewed.")
    values = {(item.entity_type, item.plaintext.casefold()) for item in detections}
    assert (EntityType.LOCALITY, "the") not in values
    assert (EntityType.PERSON_NAME, "privacy policy") not in values
