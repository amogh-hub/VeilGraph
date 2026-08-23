from __future__ import annotations

import io

import fitz
import pytest
from PIL import Image, ImageDraw, ImageFont

from app.core.config import settings
from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import normalize_value
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.ingestion.validator import ValidationError, sanitize_filename, validate_upload
from app.transformation.sanitizer import ProtectionInstruction, sanitize_pdf


def _png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _rotated_identity_png() -> bytes:
    font = ImageFont.load_default(size=26)
    image = Image.new("RGB", (1100, 1500), "white")
    draw = ImageDraw.Draw(image)
    lines = [
        "FICTIONAL CITIZEN RECORD",
        "Citizen: Aarav Testperson",
        "Mobile: +91 98765 43210",
        "Email: aarav.test@example.org",
        "Date of birth: 11 June 2007",
        "Address: 42 Test Road Bengaluru Karnataka",
        "Employer: Example Systems Private Limited",
        "Case reference: VG-TEST-2026-001",
    ]
    y = 70
    # Repeated normal prose gives Tesseract OSD enough local evidence to make
    # a deterministic orientation decision without network/model calls.
    for repeat in range(3):
        for line in lines:
            draw.text((60, y), line, font=font, fill="black")
            y += 44
        y += 18
    return _png_bytes(image.transpose(Image.Transpose.ROTATE_270))


def _multipage_pdf(page_count: int = 12) -> bytes:
    doc = fitz.open()
    try:
        for index in range(page_count):
            page = doc.new_page(width=595, height=842)
            page.insert_text((72, 90), f"FICTIONAL PAGE {index + 1}", fontsize=12)
            page.insert_text((72, 130), "Mobile: +91 98765 43210", fontsize=12)
            page.insert_text((72, 160), "Email: stress.user@example.org", fontsize=12)
        return doc.tobytes(garbage=4, deflate=True)
    finally:
        doc.close()


def test_rotated_scan_is_auto_oriented_and_identifier_boxes_map_back():
    data = _rotated_identity_png()
    document = process_document(data, FileType.IMAGE)
    detections = detect_all(document)
    types = {item.entity_type for item in detections}
    assert {EntityType.PHONE, EntityType.EMAIL, EntityType.PERSON_NAME}.issubset(types)
    page = document.pages[0]
    for item in detections:
        x0, y0, x1, y1 = item.rect
        assert 0 <= x0 < x1 <= page.width
        assert 0 <= y0 < y1 <= page.height


def test_ocr_email_with_separator_whitespace_normalizes_to_same_identity():
    from app.detection.direct_identifiers import detect_direct_identifiers
    from app.extraction.document_processor import PageFrame, PositionedLine, PositionedToken, ProcessedDocument
    from app.core.enums import DetectionSource

    text = "Email: aarav.test @ example . org"
    token = PositionedToken(text, 10, 10, 350, 30, 0.91)
    line = PositionedLine(text, (token,), DetectionSource.OCR, 0, 0)
    image = Image.new("RGB", (500, 200), "white")
    doc = ProcessedDocument(FileType.IMAGE, (PageFrame(0, 500, 200, image, (line,), True),), 1, 1)
    detections = [item for item in detect_direct_identifiers(doc) if item.entity_type == EntityType.EMAIL]
    assert len(detections) == 1
    assert normalize_value(EntityType.EMAIL, detections[0].plaintext) == "aarav.test@example.org"


def test_password_protected_pdf_is_rejected_before_workspace_ingestion():
    document = fitz.open()
    try:
        page = document.new_page()
        page.insert_text((72, 72), "Sensitive")
        encrypted = document.tobytes(
            encryption=fitz.PDF_ENCRYPT_AES_256,
            owner_pw="owner-password",
            user_pw="user-password",
        )
    finally:
        document.close()
    with pytest.raises(ValidationError, match="Password-protected|encrypted"):
        validate_upload(encrypted, "locked.pdf")


def test_absurd_pdf_page_geometry_is_rejected_by_render_budget():
    document = fitz.open()
    try:
        document.new_page(width=10_000, height=10_000)
        data = document.tobytes()
    finally:
        document.close()
    with pytest.raises(ValidationError, match="rendering budget"):
        validate_upload(data, "oversized-page.pdf")


def test_image_decoding_budget_blocks_pixel_bomb_before_analysis(monkeypatch):
    image = Image.new("RGB", (120, 120), "white")
    data = _png_bytes(image)
    monkeypatch.setattr(settings, "max_image_pixels", 10_000)
    with pytest.raises(ValidationError, match="pixel decoding limit"):
        validate_upload(data, "large.png")


def test_page_count_limit_is_enforced_before_analysis(monkeypatch):
    monkeypatch.setattr(settings, "max_pdf_pages", 3)
    with pytest.raises(ValidationError, match="3-page limit"):
        validate_upload(_multipage_pdf(4), "too-many-pages.pdf")


def test_twelve_page_document_retains_all_cross_page_mentions():
    document = process_document(_multipage_pdf(12), FileType.PDF)
    detections = detect_all(document)
    phones = [
        item for item in detections
        if item.entity_type == EntityType.PHONE
        and normalize_value(item.entity_type, item.plaintext).endswith("9876543210")
    ]
    emails = [item for item in detections if item.entity_type == EntityType.EMAIL]
    assert document.page_count == 12
    assert document.scanned_pages == 0
    assert len(phones) == 12
    assert len(emails) == 12
    assert {item.page_index for item in phones} == set(range(12))


def test_malformed_pdf_and_magic_extension_mismatch_fail_closed():
    with pytest.raises(ValidationError, match="Invalid PDF"):
        validate_upload(b"%PDF-1.7\nthis is not a valid object graph", "broken.pdf")
    with pytest.raises(ValidationError, match="magic bytes"):
        validate_upload(_multipage_pdf(1), "looks-like-image.png")


def test_untrusted_filename_is_normalized_for_response_headers():
    safe = sanitize_filename('../../evil\r\nX-Injected: yes.pdf')
    assert safe.endswith('.pdf')
    assert '/' not in safe and '\\' not in safe
    assert '\r' not in safe and '\n' not in safe
    assert ':' not in safe
    assert len(safe) <= 120


def test_pdf_sanitizer_removes_metadata_attachment_and_hidden_identifier():
    document = fitz.open()
    try:
        page = document.new_page(width=595, height=842)
        page.insert_text((72, 100), "Mobile: +91 98765 43210", fontsize=12)
        # Hidden white-on-white identifier simulates a text-layer trick.
        page.insert_text((72, 140), "hidden.user@example.org", fontsize=12, color=(1, 1, 1))
        document.set_metadata({"author": "Sensitive Author", "subject": "hidden.user@example.org"})
        document.embfile_add("secret.txt", b"hidden.user@example.org")
        original = document.tobytes()
    finally:
        document.close()

    processed = process_document(original, FileType.PDF)
    detections = detect_all(processed)
    target = next(item for item in detections if item.entity_type == EntityType.EMAIL)
    protected, _, _, _ = sanitize_pdf(
        original,
        [
            ProtectionInstruction(
                entity_id="e1",
                mention_id="m1",
                entity_type=EntityType.EMAIL,
                page_index=target.page_index,
                rect=target.rect,
                replacement="h***@example.org",
            )
        ],
    )
    checked = fitz.open(stream=protected, filetype="pdf")
    try:
        assert checked.embfile_count() == 0
        for key in ("author", "subject", "title", "keywords", "creator", "producer", "creationDate", "modDate"):
            assert not (checked.metadata.get(key) or "")
        extracted = "\n".join(page.get_text() for page in checked)
        assert "hidden.user@example.org" not in extracted
    finally:
        checked.close()
