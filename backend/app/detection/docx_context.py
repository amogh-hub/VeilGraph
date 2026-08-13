from __future__ import annotations

import re

from app.core.enums import DetectionSource, EntityType, FileType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument

# DOCX-specific structural hints. These are deliberately separate from the
# frozen Broad PII v3 detector/holdout path: Word field labels provide extra
# document structure that plain-text benchmark corpora do not expose.
_PERSON_FIELD = re.compile(
    r"(?:^|[|;])\s*(?P<label>primary\s+subject|data\s+subject|record\s+subject|case\s+owner|record\s+owner|subject)\s*[:\-]\s*(?P<value>[^|;]+?)(?=\s*(?:[|;]|$))",
    re.IGNORECASE,
)
_LOCALITY_FIELD = re.compile(
    r"(?:^|[|;])\s*(?P<label>location|service\s+location|case\s+location|place|region)\s*[:\-]\s*(?P<value>[^|;]+?)(?=\s*(?:[|;]|$))",
    re.IGNORECASE,
)
_NAME_TOKEN = re.compile(r"^[^\W\d_](?:[^\W\d_.'’\-]*[.'’\-]?)*$", re.UNICODE)


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("|,;:"))


def _plausible_person(value: str) -> bool:
    cleaned = _clean(value)
    words = cleaned.split()
    if not 2 <= len(cleaned) <= 80 or not 1 <= len(words) <= 6 or any(char.isdigit() for char in cleaned):
        return False
    if any(marker in cleaned for marker in ("@", "/", "\\", "=", "[", "]", "{", "}")):
        return False
    return all(_NAME_TOKEN.fullmatch(word.strip("(),")) for word in words)


def _plausible_locality(value: str) -> bool:
    cleaned = _clean(value)
    if not 2 <= len(cleaned) <= 120 or "@" in cleaned or any(char.isdigit() for char in cleaned):
        return False
    return bool(re.search(r"[A-Za-z]", cleaned))


def _token_spans(line: PositionedLine) -> list[tuple[int, int, PositionedToken]]:
    """Map positioned tokens back onto the actual line text, including tabs.

    Existing generic detectors historically reconstruct token offsets with
    single spaces. DOCX tables can contain tabs, so this adapter uses the real
    source string to keep structural-context rectangles exact.
    """
    spans: list[tuple[int, int, PositionedToken]] = []
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


def _rect_for_span(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    tokens = [token for a, b, token in _token_spans(line) if a < end and b > start]
    if not tokens:
        return None
    return (
        min(token.x0 for token in tokens),
        min(token.y0 for token in tokens),
        max(token.x1 for token in tokens),
        max(token.y1 for token in tokens),
    )


def _candidate(
    *,
    line: PositionedLine,
    entity_type: EntityType,
    value: str,
    start: int,
    end: int,
    context: str,
    pending: bool,
    confidence: float,
) -> DetectedMention | None:
    rect = _rect_for_span(line, start, end)
    if rect is None:
        return None
    if entity_type == EntityType.PERSON_NAME:
        sensitivity = SensitivityLevel.HIGH
        transformation = TransformationType.PSEUDONYMIZE
    else:
        sensitivity = SensitivityLevel.MEDIUM
        transformation = TransformationType.GENERALIZE
    return DetectedMention(
        entity_type=entity_type,
        plaintext=_clean(value),
        page_index=line.page_index,
        page_char_start=line.page_char_start + start,
        page_char_end=line.page_char_start + end,
        rect=rect,
        confidence=confidence,
        source=DetectionSource.TEXT_LAYER,
        sensitivity=sensitivity,
        transformation=transformation,
        review_status=ReviewStatus.PENDING if pending else ReviewStatus.NOT_REQUIRED,
        context_label=context,
    )


def _repeat_pattern(value: str) -> re.Pattern[str]:
    pieces = [re.escape(piece) for piece in value.split()]
    return re.compile(r"(?<!\w)" + r"\s+".join(pieces) + r"(?!\w)", re.IGNORECASE)


def detect_docx_structural_context(document: ProcessedDocument) -> list[DetectedMention]:
    if document.file_type != FileType.DOCX:
        return []

    detections: list[DetectedMention] = []
    anchors: list[tuple[EntityType, str, int, int, int]] = []

    for page in document.pages:
        for line in page.lines:
            person = _PERSON_FIELD.search(line.text)
            if person and _plausible_person(person.group("value")):
                start, end = person.span("value")
                candidate = _candidate(
                    line=line,
                    entity_type=EntityType.PERSON_NAME,
                    value=person.group("value"),
                    start=start,
                    end=end,
                    context=f"docx-structural:{re.sub(r'\s+', '-', person.group('label').strip().casefold())}",
                    pending=True,
                    confidence=0.99,
                )
                if candidate:
                    detections.append(candidate)
                    anchors.append((EntityType.PERSON_NAME, candidate.plaintext, page.page_index, start, end))

            locality = _LOCALITY_FIELD.search(line.text)
            if locality and _plausible_locality(locality.group("value")):
                start, end = locality.span("value")
                candidate = _candidate(
                    line=line,
                    entity_type=EntityType.LOCALITY,
                    value=locality.group("value"),
                    start=start,
                    end=end,
                    context=f"docx-structural:{re.sub(r'\s+', '-', locality.group('label').strip().casefold())}",
                    pending=False,
                    confidence=0.99,
                )
                if candidate:
                    detections.append(candidate)
                    anchors.append((EntityType.LOCALITY, candidate.plaintext, page.page_index, start, end))

    # Once a DOCX field has established a high-confidence identity value, find
    # exact repetitions elsewhere in the Word text so narrative references do
    # not survive transformation. Repeats inherit the validated anchor and do
    # not add redundant human-review clicks.
    for entity_type, value, anchor_page, anchor_start, anchor_end in anchors:
        pattern = _repeat_pattern(value)
        for page in document.pages:
            for line in page.lines:
                for match in pattern.finditer(line.text):
                    start, end = match.span()
                    if page.page_index == anchor_page and start == anchor_start and end == anchor_end:
                        continue
                    candidate = _candidate(
                        line=line,
                        entity_type=entity_type,
                        value=match.group(0),
                        start=start,
                        end=end,
                        context=f"docx-structural:repeat-{entity_type.value.casefold().replace('_', '-')}",
                        pending=False,
                        confidence=0.98,
                    )
                    if candidate:
                        detections.append(candidate)

    return detections
