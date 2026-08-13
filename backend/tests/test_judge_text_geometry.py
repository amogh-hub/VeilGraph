from __future__ import annotations

import io

from PIL import Image

from app.core.enums import EntityType, FileType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.presentation.preview import _text_rects_for_char_span, annotated_preview


JUDGE_STYLE_TEXT = (
    "Retention Demo\n"
    "\n"
    "Name: Dev Malhotra\n"
    "Email: dev.malhotra@example.org\n"
    "Phone: +91 90000 10001\n"
)


def _dark_pixels_in_band(image: Image.Image, y0: int, y1: int) -> int:
    gray = image.convert("L")
    crop = gray.crop((35, max(0, y0), min(image.width, 900), min(image.height, y1)))
    hist = crop.histogram()
    return sum(hist[:160])


def test_blank_source_rows_are_preserved_in_native_text_virtual_layout():
    document = process_document(JUDGE_STYLE_TEXT.encode("utf-8"), FileType.TEXT)
    page = document.pages[0]
    assert [line.text for line in page.lines] == [
        "Retention Demo",
        "Name: Dev Malhotra",
        "Email: dev.malhotra@example.org",
        "Phone: +91 90000 10001",
    ]
    # Row 1 is intentionally blank. The next visible line must therefore be
    # two 30px rows below the title, not compacted directly underneath it.
    y_values = [min(token.y0 for token in line.tokens) for line in page.lines]
    assert y_values == [52.0, 112.0, 142.0, 172.0]
    assert page.height >= 254.0


def test_rendered_native_text_pixels_use_the_same_rows_as_evidence_tokens():
    page = process_document(JUDGE_STYLE_TEXT.encode("utf-8"), FileType.TEXT).pages[0]
    for line in page.lines:
        y0 = int(min(token.y0 for token in line.tokens))
        assert _dark_pixels_in_band(page.image, y0, y0 + 28) > 5, line.text

    # The deliberate blank row between title and Name must remain visually blank.
    assert _dark_pixels_in_band(page.image, 82, 108) == 0


def test_native_text_preview_rect_uses_exact_character_offsets_inside_a_token():
    source = "Account note\nEmail:dev@example.org\n"
    page = process_document(source.encode("utf-8"), FileType.TEXT).pages[0]
    line = next(line for line in page.lines if line.text.startswith("Email:"))
    start = source.index("dev@example.org")
    end = start + len("dev@example.org")
    rects = _text_rects_for_char_span(page, start, end)
    assert len(rects) == 1
    rect = rects[0]
    token = line.tokens[0]  # The whole `Email:dev@example.org` string is one token.
    assert rect[0] > token.x0
    assert rect[2] <= token.x1 + 0.5
    assert rect[1] == token.y0
    assert rect[3] == token.y1


def test_judge_style_txt_detects_all_three_identifiers_and_annotated_preview_is_aligned_png():
    document = process_document(JUDGE_STYLE_TEXT.encode("utf-8"), FileType.TEXT)
    detected = detect_all(document)
    by_type = {item.entity_type for item in detected}
    assert {EntityType.PERSON_NAME, EntityType.EMAIL, EntityType.PHONE} <= by_type

    wanted = [
        item for item in detected
        if item.entity_type in {EntityType.PERSON_NAME, EntityType.EMAIL, EntityType.PHONE}
    ]
    mentions = []
    counters: dict[EntityType, int] = {}
    for item in sorted(wanted, key=lambda x: (x.page_char_start, x.entity_type.value)):
        counters[item.entity_type] = counters.get(item.entity_type, 0) + 1
        mentions.append(
            {
                "entity_type": item.entity_type.value,
                "placeholder": f"{item.entity_type.value}_{counters[item.entity_type]:03d}",
                "source": item.source.value,
                "x0": item.rect[0],
                "y0": item.rect[1],
                "x1": item.rect[2],
                "y1": item.rect[3],
                "page_char_start": item.page_char_start,
                "page_char_end": item.page_char_end,
            }
        )

    payload = annotated_preview(JUDGE_STYLE_TEXT.encode("utf-8"), FileType.TEXT, 0, mentions)
    assert payload[:8] == bytes.fromhex("89504e470d0a1a0a")
    image = Image.open(io.BytesIO(payload)).convert("RGB")

    # Every exact evidence rectangle must have its colored top-left border at the
    # same row as the source text, including all rows after the blank line.
    page = document.pages[0]
    for mention in mentions:
        rect = _text_rects_for_char_span(
            page, int(mention["page_char_start"]), int(mention["page_char_end"])
        )[0]
        x = max(0, min(image.width - 1, int(round(rect[0]))))
        y = max(0, min(image.height - 1, int(round(rect[1]))))
        r, g, b = image.getpixel((x, y))
        assert max(r, g, b) - min(r, g, b) > 20


def test_markdown_blank_rows_and_multipage_offsets_remain_stable():
    source = "# Judge Record\n\n" + "\n".join(
        f"Useful non-sensitive row {i:02d}" for i in range(48)
    ) + "\n\nEmail: final.person@example.org\n"
    document = process_document(source.encode("utf-8"), FileType.TEXT)
    assert document.page_count >= 2
    detections = detect_all(document)
    email = next(item for item in detections if item.entity_type == EntityType.EMAIL)
    assert email.plaintext == "final.person@example.org"
    assert source[email.page_char_start:email.page_char_end] == "final.person@example.org"
    page = document.pages[email.page_index]
    rect = _text_rects_for_char_span(page, email.page_char_start, email.page_char_end)
    assert rect
