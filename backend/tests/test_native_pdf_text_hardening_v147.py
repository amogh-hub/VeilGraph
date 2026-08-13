from __future__ import annotations

import io

import fitz
from PIL import Image, ImageDraw, ImageFont

from app.core.enums import EntityType, FileType
from app.transformation.sanitizer import ProtectionInstruction, sanitize_pdf, sanitize_text
from app.verification.red_team import replacement_presence_attack


def _instruction(*, entity_id: str, mention_id: str, entity_type: EntityType, rect, replacement: str, start=None, end=None):
    return ProtectionInstruction(
        entity_id=entity_id,
        mention_id=mention_id,
        entity_type=entity_type,
        page_index=0,
        rect=tuple(float(v) for v in rect),
        replacement=replacement,
        char_start=start,
        char_end=end,
    )


def test_native_text_propagates_employer_legal_suffix_variant():
    source = (
        "Employer: Orion Analytics Pvt Ltd\n"
        "Context: The subject was the only Orion Analytics delegate selected for the event.\n"
    )
    start = source.index("Orion Analytics Pvt Ltd")
    end = start + len("Orion Analytics Pvt Ltd")
    protected, _, _, report = sanitize_text(
        source.encode("utf-8"),
        [
            _instruction(
                entity_id="employer-1",
                mention_id="mention-1",
                entity_type=EntityType.EMPLOYER,
                rect=(0, 0, 1, 1),
                replacement="Organisation A",
                start=start,
                end=end,
            )
        ],
        "fixture.txt",
    )
    decoded = protected.decode("utf-8")
    assert "Orion Analytics Pvt Ltd" not in decoded
    assert "Orion Analytics" not in decoded
    assert decoded.count("Organisation A") == 2
    assert report["propagated_occurrences"] == 1


def _digital_pdf_with_repeated_locality() -> tuple[bytes, fitz.Rect]:
    document = fitz.open()
    page = document.new_page(width=595, height=842)
    page.insert_text((72, 110), "Locality: Indiranagar, Bengaluru", fontsize=12)
    page.insert_text((72, 150), "Context: The subject was the only delegate from Indiranagar selected.", fontsize=12)
    target = page.search_for("Indiranagar, Bengaluru")[0]
    data = document.tobytes(garbage=4, deflate=True, clean=True)
    document.close()
    return data, target


def test_digital_pdf_propagates_contextual_locality_variant_and_renders_alias():
    original, rect = _digital_pdf_with_repeated_locality()
    instruction = _instruction(
        entity_id="locality-1",
        mention_id="mention-1",
        entity_type=EntityType.LOCALITY,
        rect=rect,
        replacement="Bengaluru metropolitan area",
    )
    protected, _, _, report = sanitize_pdf(original, [instruction])
    document = fitz.open(stream=protected, filetype="pdf")
    try:
        text = "\n".join(page.get_text("text", sort=True) for page in document)
    finally:
        document.close()
    assert "Indiranagar" not in text
    assert text.count("Bengaluru metropolitan area") >= 2
    assert report["propagated_occurrences"] >= 1
    gate = replacement_presence_attack(protected, FileType.PDF, [instruction])
    assert gate.status.value == "PASS", gate.detail


def _scanned_pdf() -> tuple[bytes, list[tuple[EntityType, fitz.Rect, str]]]:
    width, height = 1200, 1600
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=30)
    rows = [
        ("Citizen", "Aarav Menon", EntityType.PERSON_NAME, "Person A"),
        ("Email", "aarav.menon@example.org", EntityType.EMAIL, "Email alias A"),
        ("Mobile", "+91 90000 10001", EntityType.PHONE, "Contact A"),
        ("City", "Bengaluru", EntityType.LOCALITY, "Bengaluru metropolitan area"),
        ("Reference", "VG-CASE-26001", EntityType.CASE_REFERENCE, "Case A"),
        ("Aadhaar-like", "1111 2222 3333", EntityType.AADHAAR_LIKE, "Credential A"),
        ("PAN-like", "ABCDE1234F", EntityType.PAN_LIKE, "Tax credential A"),
    ]
    specs: list[tuple[EntityType, fitz.Rect, str]] = []
    y = 260
    for label, value, entity_type, replacement in rows:
        draw.text((140, y), f"{label}:", fill="black", font=font)
        draw.text((430, y), value, fill="black", font=font)
        # Image is scaled by 0.5 into PDF points. Use a conservative region
        # around the value; replacement rendering must not disappear even when
        # the replacement is longer than the source OCR box.
        specs.append((entity_type, fitz.Rect(205, (y - 8) / 2, 500, (y + 38) / 2), replacement))
        y += 105
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    document = fitz.open()
    page = document.new_page(width=600, height=800)
    page.insert_image(page.rect, stream=buffer.getvalue())
    data = document.tobytes(garbage=4, deflate=True, clean=True)
    document.close()
    return data, specs


def test_scanned_pdf_deterministically_materializes_all_promised_replacement_text():
    original, specs = _scanned_pdf()
    instructions = [
        _instruction(
            entity_id=f"entity-{index}",
            mention_id=f"mention-{index}",
            entity_type=entity_type,
            rect=rect,
            replacement=replacement,
        )
        for index, (entity_type, rect, replacement) in enumerate(specs, start=1)
    ]
    protected, _, _, _ = sanitize_pdf(original, instructions)
    document = fitz.open(stream=protected, filetype="pdf")
    try:
        text = "\n".join(page.get_text("text", sort=True) for page in document)
    finally:
        document.close()
    for _entity_type, _rect, replacement in specs:
        assert replacement in text, (replacement, text)
    gate = replacement_presence_attack(protected, FileType.PDF, instructions)
    assert gate.status.value == "PASS", gate.detail

