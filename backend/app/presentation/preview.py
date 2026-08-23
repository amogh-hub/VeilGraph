from __future__ import annotations

import io

import fitz
from PIL import Image, ImageDraw, ImageFont, ImageOps

from app.core.enums import EntityType, FileType
from app.extraction.document_processor import process_document
from app.extraction.structured_data import render_structured_record
from app.extraction.video import physical_frame


_PERSON_COLOR = (139, 121, 246)   # matches Identity Exposure Graph subject/person nodes
_DIRECT_COLOR = (224, 103, 115)   # matches Identity Exposure Graph direct identifiers
_QUASI_COLOR = (72, 189, 168)     # matches Identity Exposure Graph quasi-identifiers
_VISUAL_COLOR = (224, 103, 115)
_DEFAULT_COLOR = (139, 121, 246)

_DIRECT_TYPES = {
    EntityType.PHONE, EntityType.EMAIL, EntityType.AADHAAR_LIKE, EntityType.PAN_LIKE,
    EntityType.PERSON_NAME, EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER, EntityType.TAX_IDENTIFIER, EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER, EntityType.CASE_REFERENCE,
}
_QUASI_TYPES = {
    EntityType.DATE_OF_BIRTH, EntityType.GENERIC_DATE, EntityType.AGE, EntityType.STREET_ADDRESS,
    EntityType.BUILDING_NUMBER, EntityType.LOCALITY, EntityType.POSTCODE, EntityType.EMPLOYER,
    EntityType.JOB_TITLE, EntityType.PERSON_TITLE, EntityType.DEMOGRAPHIC_ATTRIBUTE,
}
_VISUAL_TYPES = {EntityType.QR_CODE, EntityType.FACE, EntityType.SIGNATURE_CANDIDATE}


def _color_for(entity_type: EntityType) -> tuple[int, int, int]:
    if entity_type == EntityType.PERSON_NAME:
        return _PERSON_COLOR
    if entity_type in _DIRECT_TYPES:
        return _DIRECT_COLOR
    if entity_type in _QUASI_TYPES:
        return _QUASI_COLOR
    if entity_type in _VISUAL_TYPES:
        return _VISUAL_COLOR
    return _DEFAULT_COLOR



def _docx_token_char_spans(line) -> list[tuple[int, int, object]]:
    """Map DOCX preview tokens back to their exact line-text offsets.

    DOCX presentation can wrap one logical Word line across multiple visual
    rows.  Generic detector rectangles intentionally remain a single bounding
    box for storage, but the judge-facing preview must not draw that union
    rectangle across unrelated text.
    """
    spans: list[tuple[int, int, object]] = []
    cursor = 0
    folded = line.text.casefold()
    for token in line.tokens:
        needle = token.text.casefold()
        start = folded.find(needle, cursor)
        if start < 0:
            start = cursor
        end = start + len(token.text)
        spans.append((start, end, token))
        cursor = end
    return spans


def _docx_rects_for_char_span(page, char_start: int, char_end: int) -> list[tuple[float, float, float, float]]:
    """Return one evidence rectangle per *visual row* for a DOCX span.

    A phone/e-mail can legitimately wrap in the virtual DOCX preview even
    though it is one logical XML/text span.  Grouping overlapping tokens by
    rendered y-position prevents a multi-row span from producing one giant
    rectangle that visually claims the intervening footer/header prose.
    """
    grouped: dict[int, list[object]] = {}
    for line in page.lines:
        line_start = int(line.page_char_start)
        line_end = line_start + len(line.text)
        if char_start >= line_end or char_end <= line_start:
            continue
        local_start = max(0, char_start - line_start)
        local_end = min(len(line.text), char_end - line_start)
        for token_start, token_end, token in _docx_token_char_spans(line):
            if token_start < local_end and token_end > local_start:
                # Token y values are deterministic integer-ish layout values;
                # rounding absorbs harmless floating-point representation noise.
                grouped.setdefault(int(round(float(token.y0))), []).append(token)

    rects: list[tuple[float, float, float, float]] = []
    for row_y in sorted(grouped):
        tokens = grouped[row_y]
        rects.append((
            min(float(token.x0) for token in tokens),
            min(float(token.y0) for token in tokens),
            max(float(token.x1) for token in tokens),
            max(float(token.y1) for token in tokens),
        ))
    return rects


def _text_rects_for_char_span(page, char_start: int, char_end: int) -> list[tuple[float, float, float, float]]:
    """Reconstruct exact native-text preview rectangles from source offsets.

    Native TXT/MD/RTF detection stores character offsets as the authoritative
    identity span. Detector rectangles can intentionally be token-granular; the
    judge-facing preview should be character-accurate even when an identifier is
    embedded inside a larger token such as ``Email:dev@example.org``.
    """
    if char_end <= char_start:
        return []
    from app.extraction.document_processor import _text_font

    font = _text_font(20)
    margin_x = 52.0
    rects: list[tuple[float, float, float, float]] = []
    for line in page.lines:
        line_start = int(line.page_char_start)
        line_end = line_start + len(line.text)
        if char_start >= line_end or char_end <= line_start:
            continue
        local_start = max(0, char_start - line_start)
        local_end = min(len(line.text), char_end - line_start)
        if local_end <= local_start or not line.tokens:
            continue
        x0 = margin_x + float(font.getlength(line.text[:local_start]))
        x1 = margin_x + float(font.getlength(line.text[:local_end]))
        y0 = min(float(token.y0) for token in line.tokens)
        y1 = max(float(token.y1) for token in line.tokens)
        rects.append((x0, y0, max(x0 + 2.0, x1), y1))
    return rects


def _docx_mention_sort_key(mention: dict[str, object]) -> tuple[int, float, float, str]:
    """Return deterministic source-order placement for DOCX evidence labels.

    The API does not promise mention iteration order.  Sorting by the original
    page character offset keeps the right-side evidence rail in the same order
    a judge reads the document, which is especially important when two
    identifiers share one rendered row (for example an e-mail followed by a
    wrapped phone number in a footer).
    """
    try:
        char_start = int(mention.get("page_char_start", 10**9))
    except (TypeError, ValueError):
        char_start = 10**9
    try:
        y0 = float(mention.get("y0", 0.0))
    except (TypeError, ValueError):
        y0 = 0.0
    try:
        x0 = float(mention.get("x0", 0.0))
    except (TypeError, ValueError):
        x0 = 0.0
    return char_start, y0, x0, str(mention.get("placeholder", ""))


def _docx_connector_lines(
    rects: list[tuple[float, float, float, float]],
    *,
    lane_x: float,
    label_x: float,
    target_y: float,
) -> list[tuple[float, float, float, float]]:
    """Route every visual fragment of one DOCX entity to one label.

    A logical identifier may wrap into multiple preview rectangles.  Each
    fragment gets its own lead-in line, but all lead-ins converge on the same
    coloured evidence chip.  This makes the association explicit without
    duplicating labels or implying that neighbouring text belongs to the entity.
    """
    lines: list[tuple[float, float, float, float]] = []
    for x0, y0, x1, y1 in rects:
        source_x = float(x1) + 4.0
        source_y = (float(y0) + float(y1)) / 2.0
        lines.append((source_x, source_y, lane_x, target_y))
    lines.append((lane_x, target_y, label_x - 4.0, target_y))
    return lines


def _font(size: int = 18) -> ImageFont.ImageFont:
    for path in (
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_page(data: bytes, file_type: FileType, page_index: int) -> tuple[Image.Image, float, float]:
    if file_type == FileType.VIDEO:
        image, _info, _source_frame = physical_frame(data, page_index)
        return image, 1.0, 1.0
    if file_type in {FileType.TEXT, FileType.DOCX}:
        document = process_document(data, file_type)
        if page_index < 0 or page_index >= len(document.pages):
            raise ValueError("Document page index is out of range")
        return document.pages[page_index].image.copy(), 1.0, 1.0

    if file_type == FileType.DATASET:
        image = render_structured_record(data, page_index)
        return image, image.width / 1200.0, 1.0

    if file_type == FileType.IMAGE:
        if page_index != 0:
            raise ValueError("Standalone image has only page 1")
        image = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")
        return image, 1.0, 1.0

    document = fitz.open(stream=data, filetype="pdf")
    try:
        if page_index < 0 or page_index >= len(document):
            raise ValueError("Page index is out of range")
        page = document[page_index]
        zoom = 1.8
        pixmap = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        image = Image.open(io.BytesIO(pixmap.tobytes("png"))).convert("RGB")
        return image, image.width / float(page.rect.width), image.height / float(page.rect.height)
    finally:
        document.close()


def annotated_preview(
    data: bytes,
    file_type: FileType,
    page_index: int,
    mentions: list[dict[str, object]],
) -> bytes:
    image, scale_x, scale_y = render_page(data, file_type, page_index)
    draw = ImageDraw.Draw(image)
    font = _font(max(14, min(22, image.width // 65)))
    docx_label_rows: dict[int, int] = {}
    docx_page = None
    text_page = None
    if file_type == FileType.DOCX:
        document = process_document(data, FileType.DOCX)
        if 0 <= page_index < len(document.pages):
            docx_page = document.pages[page_index]
    elif file_type == FileType.TEXT:
        document = process_document(data, FileType.TEXT)
        if 0 <= page_index < len(document.pages):
            text_page = document.pages[page_index]
    render_mentions = mentions
    if file_type == FileType.DOCX:
        render_mentions = sorted(mentions, key=_docx_mention_sort_key)

    for mention in render_mentions:
        entity_type = EntityType(str(mention["entity_type"]))
        color = _color_for(entity_type)
        stored_rect = (
            float(mention["x0"]) * scale_x,
            float(mention["y0"]) * scale_y,
            float(mention["x1"]) * scale_x,
            float(mention["y1"]) * scale_y,
        )
        rects = [stored_rect]
        if docx_page is not None:
            try:
                segmented = _docx_rects_for_char_span(
                    docx_page, int(mention["page_char_start"]), int(mention["page_char_end"])
                )
            except (KeyError, TypeError, ValueError):
                segmented = []
            if segmented:
                rects = [
                    (x0 * scale_x, y0 * scale_y, x1 * scale_x, y1 * scale_y)
                    for x0, y0, x1, y1 in segmented
                ]
        elif text_page is not None:
            try:
                exact_text_rects = _text_rects_for_char_span(
                    text_page, int(mention["page_char_start"]), int(mention["page_char_end"])
                )
            except (KeyError, TypeError, ValueError):
                exact_text_rects = []
            if exact_text_rects:
                rects = exact_text_rects
        for rect in rects:
            draw.rectangle(rect, outline=color, width=max(3, image.width // 500))
        rect = rects[0]
        label = f'{mention["placeholder"]} · {mention["source"]}'
        if file_type == FileType.DOCX:
            # DOCX preview reserves a dedicated right-side evidence rail. This
            # guarantees chips cannot obscure narrative text, even when a
            # detected name appears mid-sentence. Multiple findings on one row
            # are stacked deterministically inside the rail.
            row_key = int(rect[1] // 8)
            row_slot = docx_label_rows.get(row_key, 0)
            docx_label_rows[row_key] = row_slot + 1
            label_x = 820
            label_y = min(image.height - 24, rect[1] + 1 + row_slot * 22)
            label_box = draw.textbbox((label_x, label_y), label, font=font)
            if label_box[2] > image.width - 8:
                label_x = max(0, image.width - (label_box[2] - label_box[0]) - 8)
                label_box = draw.textbbox((label_x, label_y), label, font=font)

            # Use a dedicated routing lane for each chip sharing the same visual
            # row.  Every rectangle belonging to this logical entity connects
            # to the same chip, so a wrapped phone number has one PHONE label
            # while both visual fragments remain visibly associated with it.
            target_y = label_y + 8
            lane_x = min(label_x - 9, 790 + row_slot * 7)
            for connector in _docx_connector_lines(
                rects, lane_x=lane_x, label_x=label_x, target_y=target_y
            ):
                draw.line(connector, fill=color, width=1)
        elif file_type in {FileType.DATASET, FileType.TEXT}:
            # Native text is dense. Placing evidence chips above each rectangle
            # obscures the previous source line and makes a correct rectangle
            # look shifted. Prefer the whitespace immediately to the right; only
            # fall back above the span when the chip would leave the page.
            label_x = rects[-1][2] + 8
            label_y = rect[1] + 1
            label_box = draw.textbbox((label_x, label_y), label, font=font)
            if label_box[2] > image.width - 8:
                label_x = max(0, rect[0])
                label_y = max(0, rect[1] - 22)
                label_box = draw.textbbox((label_x, label_y), label, font=font)
        else:
            label_box = draw.textbbox((rect[0], max(0, rect[1] - 26)), label, font=font)
        draw.rectangle(label_box, fill=color)
        draw.text((label_box[0], label_box[1]), label, fill="white", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def plain_preview(data: bytes, file_type: FileType, page_index: int) -> bytes:
    image, _, _ = render_page(data, file_type, page_index)
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _docx_protected_rects_for_annotation(page, item: dict[str, object]) -> list[tuple[float, float, float, float]]:
    """Re-locate a protected DOCX replacement in the protected preview.

    Annotation manifests intentionally carry the *source* evidence rectangle so
    auditors can understand where the transformation originated.  A replacement
    can be shorter/longer and can wrap differently, so reusing that source box
    in the derived protected preview can visually claim neighbouring text.
    Re-find the non-secret replacement text in the protected virtual page and
    choose the occurrence closest to the original evidence row.
    """
    replacement = str(item.get("replacement_preview", "")).strip()
    if not replacement:
        return []
    raw_rect = item.get("rect")
    try:
        target_y = float(raw_rect[1]) if isinstance(raw_rect, list) and len(raw_rect) == 4 else 0.0
    except (TypeError, ValueError):
        target_y = 0.0

    candidates: list[tuple[float, list[tuple[float, float, float, float]]]] = []
    needle = replacement.casefold()
    for line in page.lines:
        folded = line.text.casefold()
        cursor = 0
        while True:
            local_start = folded.find(needle, cursor)
            if local_start < 0:
                break
            char_start = int(line.page_char_start) + local_start
            char_end = char_start + len(replacement)
            rects = _docx_rects_for_char_span(page, char_start, char_end)
            if rects:
                candidates.append((abs(float(rects[0][1]) - target_y), rects))
            cursor = local_start + max(1, len(replacement))
    if not candidates:
        return []
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def annotated_protected_preview(
    data: bytes,
    file_type: FileType,
    page_index: int,
    annotations: list[dict[str, object]],
) -> bytes:
    """Render the protected artifact with non-secret transformation evidence.

    The clean release artifact is never modified. This is a derived judge/audit
    view whose labels come from the cryptographically bound annotation manifest.
    DOCX replacements are re-located in the protected artifact so the evidence
    boxes describe the released text rather than stale source geometry.
    """
    image, scale_x, scale_y = render_page(data, file_type, page_index)
    draw = ImageDraw.Draw(image)
    font = _font(max(13, min(20, image.width // 70)))

    docx_page = None
    if file_type == FileType.DOCX:
        document = process_document(data, FileType.DOCX)
        if 0 <= page_index < len(document.pages):
            docx_page = document.pages[page_index]

    prepared: list[tuple[dict[str, object], list[tuple[float, float, float, float]]]] = []
    for item in annotations:
        raw_rect = item.get("rect")
        if not isinstance(raw_rect, list) or len(raw_rect) != 4:
            continue
        rects: list[tuple[float, float, float, float]] = []
        if docx_page is not None:
            rects = _docx_protected_rects_for_annotation(docx_page, item)
        if not rects:
            rects = [(float(raw_rect[0]), float(raw_rect[1]), float(raw_rect[2]), float(raw_rect[3]))]
        scaled = [(x0 * scale_x, y0 * scale_y, x1 * scale_x, y1 * scale_y) for x0, y0, x1, y1 in rects]
        prepared.append((item, scaled))

    if file_type == FileType.DOCX:
        prepared.sort(key=lambda pair: (pair[1][0][1], pair[1][0][0], str(pair[0].get("placeholder", ""))))

    label_rows: dict[int, int] = {}
    for item, rects in prepared:
        entity_type = EntityType(str(item["entity_type"]))
        color = _color_for(entity_type)
        for rect in rects:
            draw.rectangle(rect, outline=color, width=max(3, image.width // 520))

        confidence = int(round(float(item.get("confidence", 0.0)) * 100))
        action = str(item.get("action", "PROTECT"))
        placeholder = str(item.get("placeholder", entity_type.value))
        label = f"{placeholder} · {action} · {confidence}%"
        first = rects[0]

        if file_type == FileType.DOCX:
            row_key = int(first[1] // 8)
            row_slot = label_rows.get(row_key, 0)
            label_rows[row_key] = row_slot + 1
            label_x = 820
            label_y = min(image.height - 24, first[1] + 1 + row_slot * 22)
            label_box = draw.textbbox((label_x, label_y), label, font=font)
            if label_box[2] > image.width - 8:
                label_x = max(0, image.width - (label_box[2] - label_box[0]) - 8)
                label_box = draw.textbbox((label_x, label_y), label, font=font)
            target_y = label_y + 8
            lane_x = min(label_x - 9, 790 + row_slot * 7)
            for connector in _docx_connector_lines(rects, lane_x=lane_x, label_x=label_x, target_y=target_y):
                draw.line(connector, fill=color, width=1)
        else:
            label_x = first[2] + 8
            label_y = first[1] + 1
            label_box = draw.textbbox((label_x, label_y), label, font=font)
            if label_box[2] > image.width - 8:
                label_x = max(0, first[0])
                label_y = max(0, first[1] - 22)
                label_box = draw.textbbox((label_x, label_y), label, font=font)

        draw.rectangle(label_box, fill=color)
        draw.text((label_box[0], label_box[1]), label, fill="white", font=font)

    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()
