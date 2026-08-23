from __future__ import annotations

from functools import lru_cache

from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import normalize_value, replacement_for
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from generate_scanned_test_document import build_scanned_pdf, build_scanned_png
from generate_test_pdf import build_test_pdf




@lru_cache(maxsize=1)
def _scanned_pdf_document():
    return process_document(build_scanned_pdf(), FileType.PDF)


@lru_cache(maxsize=1)
def _scanned_pdf_detections():
    return tuple(detect_all(_scanned_pdf_document()))


@lru_cache(maxsize=1)
def _scanned_png_document():
    return process_document(build_scanned_png(), FileType.IMAGE)


@lru_cache(maxsize=1)
def _scanned_png_detections():
    return tuple(detect_all(_scanned_png_document()))


@lru_cache(maxsize=1)
def _digital_document():
    return process_document(build_test_pdf(), FileType.PDF)


@lru_cache(maxsize=1)
def _digital_detections():
    return tuple(detect_all(_digital_document()))


def _names(detections):
    return [item for item in detections if item.entity_type == EntityType.PERSON_NAME]


def test_scanned_pdf_detects_multimodal_entities_and_repeated_mentions():
    document = _scanned_pdf_document()
    detections = _scanned_pdf_detections()
    types = {item.entity_type for item in detections}
    assert document.page_count == 2
    assert document.scanned_pages == 2
    assert {
        EntityType.PERSON_NAME,
        EntityType.PHONE,
        EntityType.EMAIL,
        EntityType.AADHAAR_LIKE,
        EntityType.PAN_LIKE,
        EntityType.QR_CODE,
        EntityType.SIGNATURE_CANDIDATE,
    }.issubset(types)
    repeated = [
        item for item in detections
        if item.entity_type == EntityType.PHONE and normalize_value(item.entity_type, item.plaintext).endswith("9876543210")
    ]
    assert len(repeated) == 2
    assert {item.page_index for item in repeated} == {0, 1}


def test_scanned_name_field_is_a_review_required_candidate():
    document = _scanned_pdf_document()
    names = _names(_scanned_pdf_detections())
    assert len(names) == 1
    assert names[0].plaintext == "Aarav Testperson"
    assert names[0].source.value == "OCR"
    assert names[0].review_status.value == "PENDING"
    assert replacement_for(EntityType.PERSON_NAME, names[0].plaintext) == "[NAME PROTECTED]"


def test_digital_table_label_and_value_are_associated_as_a_name_candidate():
    document = _digital_document()
    names = _names(_digital_detections())
    assert len(names) == 1
    assert names[0].plaintext == "Aarav Testperson"
    assert names[0].source.value == "TEXT_LAYER"
    assert names[0].review_status.value == "PENDING"
    assert names[0].rect[0] > 200  # value column, not the Citizen label column


def test_standalone_png_uses_ocr_and_visual_detection():
    document = _scanned_png_document()
    detections = _scanned_png_detections()
    assert document.page_count == 1
    assert document.scanned_pages == 1
    assert any(item.entity_type == EntityType.PERSON_NAME for item in detections)
    assert any(item.entity_type == EntityType.QR_CODE for item in detections)
    assert any(item.entity_type == EntityType.EMAIL for item in detections)
    assert any(item.entity_type == EntityType.SIGNATURE_CANDIDATE for item in detections)


def test_digital_pdf_slice_a_regression_path_remains_intact():
    document = _digital_document()
    detections = _digital_detections()
    assert document.page_count == 2
    assert document.scanned_pages == 0
    repeated = [
        item for item in detections
        if item.entity_type == EntityType.PHONE and normalize_value(item.entity_type, item.plaintext).endswith("9876543210")
    ]
    assert len(repeated) == 2
    assert all(item.source.value == "TEXT_LAYER" for item in repeated)


def test_geometry_only_qr_detection_requires_human_review(monkeypatch):
    """An OpenCV polygon without a decoded payload must never auto-redact."""
    import numpy as np
    import app.detection.visual_detector as visual_detector

    class GeometryOnlyDetector:
        def detectAndDecodeMulti(self, _image):
            points = np.array([[[120.0, 120.0], [220.0, 120.0], [220.0, 220.0], [120.0, 220.0]]])
            return True, ("",), points, None

        def detectAndDecode(self, _image):
            return "", None, None

    document = _scanned_pdf_document()
    page_without_real_qr = document.pages[1]
    monkeypatch.setattr(visual_detector.cv2, "QRCodeDetector", lambda: GeometryOnlyDetector())

    detections = visual_detector._qr_detections(page_without_real_qr)
    assert len(detections) == 1
    assert detections[0].entity_type == EntityType.QR_CODE
    assert detections[0].plaintext.startswith("UNDECODED_QR_CANDIDATE")
    assert detections[0].review_status.value == "PENDING"
    assert detections[0].confidence <= 0.55


def test_decoded_qr_remains_automatic_protection():
    document = _scanned_png_document()
    qr = [item for item in _scanned_png_detections() if item.entity_type == EntityType.QR_CODE]
    assert qr
    assert all(item.plaintext for item in qr)
    assert all(item.review_status.value == "NOT_REQUIRED" for item in qr)
