from __future__ import annotations

from app.core.enums import (
    DetectionSource,
    EntityType,
    FileType,
    ReviewStatus,
    SensitivityLevel,
    TestStatus as VerificationStatus,
    TransformationType,
)
from app.detection.models import DetectedMention
from app.transformation.sanitizer import ProtectionInstruction
import app.verification.red_team as red_team


def _qr(*, decoded: bool, rect=(100.0, 100.0, 200.0, 200.0)) -> DetectedMention:
    return DetectedMention(
        entity_type=EntityType.QR_CODE,
        plaintext="https://example.invalid/private" if decoded else "UNDECODED_QR_CANDIDATE_PAGE_1_0",
        page_index=1,
        page_char_start=-1,
        page_char_end=-1,
        rect=rect,
        confidence=0.98 if decoded else 0.55,
        source=DetectionSource.VISUAL,
        sensitivity=SensitivityLevel.HIGH,
        transformation=TransformationType.REMOVE_REGION,
        review_status=ReviewStatus.NOT_REQUIRED if decoded else ReviewStatus.PENDING,
    )


def _patch_qr_scan(monkeypatch, detections):
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_visual_entities", lambda _document: detections)


def test_reviewed_ignored_geometry_only_qr_is_not_a_residual_leak(monkeypatch):
    candidate = _qr(decoded=False)
    _patch_qr_scan(monkeypatch, [candidate])
    result = red_team.qr_rescan(
        b"protected",
        FileType.PDF,
        reviewed_ignored_visual_regions=[
            {
                "entity_type": "QR_CODE",
                "page_index": 1,
                "rect": [95.0, 95.0, 205.0, 205.0],
                "confidence": 0.55,
            }
        ],
    )
    assert result.status == VerificationStatus.PASS
    assert "reviewer-dismissed" in result.detail


def test_unreviewed_geometry_only_qr_remains_fail_closed(monkeypatch):
    _patch_qr_scan(monkeypatch, [_qr(decoded=False)])
    result = red_team.qr_rescan(b"protected", FileType.PDF, reviewed_ignored_visual_regions=[])
    assert result.status == VerificationStatus.FAIL
    assert "unreviewed undecoded" in result.detail


def test_decoded_qr_always_blocks_even_when_region_was_previously_ignored(monkeypatch):
    candidate = _qr(decoded=True)
    _patch_qr_scan(monkeypatch, [candidate])
    result = red_team.qr_rescan(
        b"protected",
        FileType.PDF,
        reviewed_ignored_visual_regions=[
            {
                "entity_type": "QR_CODE",
                "page_index": 1,
                "rect": [95.0, 95.0, 205.0, 205.0],
                "confidence": 0.55,
            }
        ],
    )
    assert result.status == VerificationStatus.FAIL
    assert "decodable residual" in result.detail


def test_direct_identifier_gate_does_not_duplicate_qr_gate(monkeypatch):
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [])
    monkeypatch.setattr(
        red_team,
        "detect_visual_entities",
        lambda _document: (_ for _ in ()).throw(AssertionError("visual detector must not run here")),
    )
    result = red_team.direct_identifier_rescan(b"protected", FileType.PDF)
    assert result.status == VerificationStatus.PASS



def _direct_identifier(
    *,
    entity_type: EntityType,
    plaintext: str,
    rect=(100.0, 100.0, 200.0, 125.0),
) -> DetectedMention:
    return DetectedMention(
        entity_type=entity_type,
        plaintext=plaintext,
        page_index=0,
        page_char_start=0,
        page_char_end=len(plaintext),
        rect=rect,
        confidence=0.74,
        source=DetectionSource.OCR,
        sensitivity=SensitivityLevel.HIGH,
        transformation=TransformationType.MASK,
        review_status=ReviewStatus.NOT_REQUIRED,
    )


def _aadhaar_instruction() -> ProtectionInstruction:
    return ProtectionInstruction(
        entity_id="aadhaar-entity",
        mention_id="aadhaar-mention",
        entity_type=EntityType.AADHAAR_LIKE,
        page_index=0,
        rect=(95.0, 95.0, 205.0, 130.0),
        replacement="XXXX XXXX 9012",
    )


def test_macos_ocr_aadhaar_mask_artifact_is_bound_to_approved_region(monkeypatch):
    artifact = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1111 1111 9012",
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [artifact])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.AADHAAR_LIKE, "1234 5678 9012")],
        instructions=[_aadhaar_instruction()],
    )
    assert result.status == VerificationStatus.PASS
    assert "OCR mask artefact" in result.detail


def test_exact_original_aadhaar_still_blocks_inside_mask_region(monkeypatch):
    original = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1234 5678 9012",
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [original])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.AADHAAR_LIKE, "1234 5678 9012")],
        instructions=[_aadhaar_instruction()],
    )
    assert result.status == VerificationStatus.FAIL
    assert "AADHAAR_LIKE" in result.detail


def test_unrelated_aadhaar_outside_mask_region_remains_fail_closed(monkeypatch):
    unrelated = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1111 1111 9012",
        rect=(350.0, 350.0, 470.0, 380.0),
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [unrelated])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.AADHAAR_LIKE, "1234 5678 9012")],
        instructions=[_aadhaar_instruction()],
    )
    assert result.status == VerificationStatus.FAIL


def test_reviewed_qr_geometry_with_apple_silicon_polygon_jitter_matches(monkeypatch):
    # The new candidate overlaps less than 50% of its own area, which was the
    # brittle Hotfix 1 threshold, but remains the same nearby geometry.
    candidate = _qr(decoded=False, rect=(155.0, 80.0, 245.0, 170.0))
    _patch_qr_scan(monkeypatch, [candidate])
    result = red_team.qr_rescan(
        b"protected",
        FileType.PDF,
        reviewed_ignored_visual_regions=[
            {
                "entity_type": "QR_CODE",
                "page_index": 1,
                "rect": [100.0, 100.0, 200.0, 200.0],
                "confidence": 0.55,
            }
        ],
    )
    assert result.status == VerificationStatus.PASS


def test_one_reviewed_qr_region_cannot_exempt_multiple_output_candidates(monkeypatch):
    first = _qr(decoded=False, rect=(100.0, 100.0, 200.0, 200.0))
    second = _qr(decoded=False, rect=(105.0, 105.0, 205.0, 205.0))
    _patch_qr_scan(monkeypatch, [first, second])
    result = red_team.qr_rescan(
        b"protected",
        FileType.PDF,
        reviewed_ignored_visual_regions=[
            {
                "entity_type": "QR_CODE",
                "page_index": 1,
                "rect": [95.0, 95.0, 205.0, 205.0],
                "confidence": 0.55,
            }
        ],
    )
    assert result.status == VerificationStatus.FAIL
    assert "1 unreviewed" in result.detail


def _phone_instruction() -> ProtectionInstruction:
    return ProtectionInstruction(
        entity_id="phone-entity",
        mention_id="phone-mention",
        entity_type=EntityType.PHONE,
        page_index=0,
        rect=(95.0, 95.0, 205.0, 130.0),
        replacement="XXXXXXXX3210",
    )


def test_macos_phone_mask_misclassified_as_aadhaar_is_accepted(monkeypatch):
    artifact = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1111 1111 3210",
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [artifact])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.PHONE, "9876543210")],
        instructions=[_phone_instruction()],
    )
    assert result.status == VerificationStatus.PASS
    assert "OCR mask artefact" in result.detail


def test_numeric_original_blocks_even_when_detector_class_changes(monkeypatch):
    leaked = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="0098 7654 3210",
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [leaked])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.PHONE, "9876543210")],
        instructions=[_phone_instruction()],
    )
    assert result.status == VerificationStatus.FAIL


def test_cross_class_numeric_artifact_requires_matching_visible_suffix(monkeypatch):
    unrelated = _direct_identifier(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1111 1111 9999",
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [unrelated])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.PHONE, "9876543210")],
        instructions=[_phone_instruction()],
    )
    assert result.status == VerificationStatus.FAIL


def test_text_layer_candidate_is_never_exempted_as_ocr_mask_artifact(monkeypatch):
    candidate = DetectedMention(
        entity_type=EntityType.AADHAAR_LIKE,
        plaintext="1111 1111 3210",
        page_index=0,
        page_char_start=0,
        page_char_end=14,
        rect=(100.0, 100.0, 200.0, 125.0),
        confidence=0.99,
        source=DetectionSource.TEXT_LAYER,
        sensitivity=SensitivityLevel.HIGH,
        transformation=TransformationType.MASK,
        review_status=ReviewStatus.NOT_REQUIRED,
    )
    monkeypatch.setattr(red_team, "process_document", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(red_team, "detect_direct_identifiers", lambda _document: [candidate])
    result = red_team.direct_identifier_rescan(
        b"protected",
        FileType.PDF,
        known_values=[(EntityType.PHONE, "9876543210")],
        instructions=[_phone_instruction()],
    )
    assert result.status == VerificationStatus.FAIL
