from __future__ import annotations

import io

import fitz
from PIL import Image, ImageDraw, ImageFont

from app.core.enums import EntityType, FileType, TestStatus as GateStatus
from app.transformation.sanitizer import ProtectionInstruction
from app.verification.red_team import (
    hidden_markup_payload_scan,
    independent_extraction,
    ocr_rescan,
    raw_object_stream_scan,
    secondary_text_parser_rescan,
)


def _instruction(replacement: str) -> ProtectionInstruction:
    return ProtectionInstruction(
        entity_id="locality-1",
        mention_id="mention-1",
        entity_type=EntityType.LOCALITY,
        page_index=0,
        rect=(72.0, 72.0, 360.0, 112.0),
        replacement=replacement,
        char_start=10,
        char_end=19,
    )


def test_exact_approved_replacement_phrase_is_not_a_global_locality_whitelist():
    known = [(EntityType.LOCALITY, "Bengaluru")]
    instruction = _instruction("Bengaluru metropolitan area")
    protected = b"Locality: Bengaluru metropolitan area\nContext: safe release.\n"

    assert independent_extraction(protected, FileType.TEXT, known, [instruction]).status == GateStatus.PASS
    assert secondary_text_parser_rescan(protected, known, [instruction]).status == GateStatus.PASS
    assert hidden_markup_payload_scan(protected, known, [instruction]).status == GateStatus.PASS
    assert raw_object_stream_scan(protected, FileType.TEXT, known, [instruction]).status == GateStatus.PASS

    leaked = protected + b"Travel note: departed from Bengaluru yesterday.\n"
    assert independent_extraction(leaked, FileType.TEXT, known, [instruction]).status == GateStatus.FAIL
    assert secondary_text_parser_rescan(leaked, known, [instruction]).status == GateStatus.FAIL
    assert hidden_markup_payload_scan(leaked, known, [instruction]).status == GateStatus.FAIL
    assert raw_object_stream_scan(leaked, FileType.TEXT, known, [instruction]).status == GateStatus.FAIL


def _pdf_with_text(lines: list[str]) -> bytes:
    document = fitz.open()
    page = document.new_page(width=595, height=842)
    y = 120
    for line in lines:
        page.insert_text((72, y), line, fontsize=16)
        y += 48
    data = document.tobytes(garbage=4, deflate=True, clean=True)
    document.close()
    return data


def test_pdf_text_and_raw_stream_scans_only_exempt_exact_signed_replacement_phrase():
    known = [(EntityType.LOCALITY, "Bengaluru")]
    instruction = _instruction("Bengaluru metropolitan area")

    protected = _pdf_with_text(["Locality: Bengaluru metropolitan area", "Context: safe release"])
    assert independent_extraction(protected, FileType.PDF, known, [instruction]).status == GateStatus.PASS
    assert raw_object_stream_scan(protected, FileType.PDF, known, [instruction]).status == GateStatus.PASS

    leaked = _pdf_with_text([
        "Locality: Bengaluru metropolitan area",
        "Travel note: departed from Bengaluru yesterday",
    ])
    assert independent_extraction(leaked, FileType.PDF, known, [instruction]).status == GateStatus.FAIL
    assert raw_object_stream_scan(leaked, FileType.PDF, known, [instruction]).status == GateStatus.FAIL


def _raster_pdf(lines: list[str]) -> bytes:
    image = Image.new("RGB", (1400, 900), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=42)
    y = 180
    for line in lines:
        draw.text((100, y), line, fill="black", font=font)
        y += 120
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    document = fitz.open()
    page = document.new_page(width=700, height=450)
    page.insert_image(page.rect, stream=buf.getvalue())
    data = document.tobytes(garbage=4, deflate=True, clean=True)
    document.close()
    return data


def test_ocr_rescan_is_replacement_aware_but_still_catches_standalone_city_leak():
    known = [(EntityType.LOCALITY, "Bengaluru")]
    instruction = _instruction("Bengaluru metropolitan area")
    protected = _raster_pdf(["Bengaluru metropolitan area", "safe release"])
    result = ocr_rescan(protected, FileType.PDF, known, [instruction])
    assert result.status == GateStatus.PASS, result.detail

    leaked = _raster_pdf(["Bengaluru metropolitan area", "departed from Bengaluru yesterday"])
    result = ocr_rescan(leaked, FileType.PDF, known, [instruction])
    assert result.status == GateStatus.FAIL, result.detail
