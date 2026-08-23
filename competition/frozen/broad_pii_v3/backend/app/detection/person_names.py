from __future__ import annotations

import re

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument

_LABEL_ALTERNATIVES = (
    r"full\s+name", r"applicant(?:\s+name)?", r"citizen(?:\s+name)?",
    r"patient(?:\s+name)?", r"employee(?:\s+name)?", r"customer(?:\s+name)?",
    r"beneficiary(?:\s+name)?", r"student(?:\s+name)?", r"account\s+holder(?:\s+name)?",
    r"contact\s+person(?:\s+name)?", r"emergency\s+contact(?:\s+name)?",
    r"guardian(?:'s)?\s+name", r"father(?:'s)?\s+name", r"mother(?:'s)?\s+name",
    r"spouse(?:'s)?\s+name", r"nominee(?:'s)?\s+name", r"witness(?:'s)?\s+name", r"name",
)
_LABEL_BODY = "(?:" + "|".join(_LABEL_ALTERNATIVES) + ")"
_SAME_LINE = re.compile(rf"^\s*(?P<label>{_LABEL_BODY})\s*[:\-]\s*(?P<value>.+?)\s*$", re.IGNORECASE)
_LABEL_ONLY = re.compile(rf"^\s*(?P<label>{_LABEL_BODY})\s*:?\s*$", re.IGNORECASE)
_NAME_TOKEN = re.compile(r"^[^\W\d_](?:[^\W\d_.'’\-]*[.'’\-]?)*$", re.UNICODE)
_REJECT_EXACT = {"synthetic value", "not available", "not applicable", "unknown", "none", "nil", "name protected", "protected", "confidential", "test data"}
_REJECT_WORDS = {"mobile", "phone", "email", "address", "contact", "aadhaar", "pan", "signature", "citizen", "applicant", "patient", "employee", "customer", "beneficiary", "student", "field", "value"}


def _token_spans(tokens: tuple[PositionedToken, ...]) -> list[tuple[int, int, PositionedToken]]:
    spans = []
    offset = 0
    for index, token in enumerate(tokens):
        start = offset; end = start + len(token.text)
        spans.append((start, end, token))
        offset = end + (1 if index < len(tokens) - 1 else 0)
    return spans


def _rect_for_span(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    overlapping = [token for token_start, token_end, token in _token_spans(line.tokens) if token_start < end and token_end > start]
    if not overlapping:
        return None
    return (min(t.x0 for t in overlapping), min(t.y0 for t in overlapping), max(t.x1 for t in overlapping), max(t.y1 for t in overlapping))


def _line_rect(line: PositionedLine) -> tuple[float, float, float, float] | None:
    if not line.tokens:
        return None
    return (min(t.x0 for t in line.tokens), min(t.y0 for t in line.tokens), max(t.x1 for t in line.tokens), max(t.y1 for t in line.tokens))


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("|,;:"))


def _plausible(value: str) -> bool:
    cleaned = _clean(value); lowered = cleaned.casefold()
    if not 2 <= len(cleaned) <= 80 or lowered in _REJECT_EXACT or any(c.isdigit() for c in cleaned):
        return False
    if any(marker in cleaned for marker in ("@", "/", "\\", "=", "[", "]", "{", "}")):
        return False
    words = cleaned.split()
    if not 1 <= len(words) <= 6:
        return False
    if {word.casefold().strip(".'’-") for word in words} & _REJECT_WORDS:
        return False
    if not all(_NAME_TOKEN.fullmatch(word.strip("(),")) for word in words):
        return False
    return not (len(words) == 1 and len(words[0].strip(".'’-")) < 2)


def _confidence(line: PositionedLine, start: int, end: int) -> float:
    values = [token.confidence for token_start, token_end, token in _token_spans(line.tokens) if token_start < end and token_end > start]
    base = min(values) if values else 0.75
    return max(0.55, min(0.99 if line.source == DetectionSource.TEXT_LAYER else 0.95, base))


def _same_row(label_line: PositionedLine, value_line: PositionedLine) -> bool:
    left = _line_rect(label_line); right = _line_rect(value_line)
    if left is None or right is None:
        return False
    lx0, ly0, lx1, ly1 = left; vx0, vy0, _vx1, vy1 = right
    overlap = max(0.0, min(ly1, vy1) - max(ly0, vy0))
    return overlap >= min(ly1 - ly0, vy1 - vy0) * 0.45 and vx0 > lx1 - 3.0


def _near_below(label_line: PositionedLine, value_line: PositionedLine) -> bool:
    label = _line_rect(label_line); value = _line_rect(value_line)
    if label is None or value is None:
        return False
    lx0, _ly0, _lx1, ly1 = label; vx0, vy0, _vx1, _vy1 = value
    return 0.0 <= vy0 - ly1 <= 32.0 and vx0 >= lx0 - 4.0


def _candidate(line: PositionedLine, value: str, start: int, end: int, label: str) -> DetectedMention | None:
    cleaned = _clean(value)
    if not _plausible(cleaned):
        return None
    rect = _rect_for_span(line, start, end)
    if rect is None:
        return None
    return DetectedMention(
        entity_type=EntityType.PERSON_NAME,
        plaintext=cleaned,
        page_index=line.page_index,
        page_char_start=line.page_char_start + start,
        page_char_end=line.page_char_start + end,
        rect=rect,
        confidence=_confidence(line, start, end),
        source=line.source,
        sensitivity=SensitivityLevel.HIGH,
        transformation=TransformationType.PSEUDONYMIZE,
        review_status=ReviewStatus.PENDING,
        context_label=re.sub(r"\s+", " ", label.strip()).casefold(),
    )


def detect_person_name_candidates(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    occupied: set[tuple[int, int, int]] = set()
    for page in document.pages:
        lines = list(page.lines)
        for index, line in enumerate(lines):
            same = _SAME_LINE.match(line.text)
            if same:
                start, end = same.span("value")
                candidate = _candidate(line, same.group("value"), start, end, same.group("label"))
                if candidate:
                    key = (candidate.page_index, candidate.page_char_start, candidate.page_char_end)
                    if key not in occupied:
                        occupied.add(key); detections.append(candidate)
                continue
            label_match = _LABEL_ONLY.match(line.text)
            if not label_match:
                continue
            for value_line in lines[index + 1:index + 4]:
                if _LABEL_ONLY.match(value_line.text):
                    break
                # Do not walk past another labelled field after a rejected value
                # (for example an emergency-contact phone followed by Locality).
                if re.match(r"^\s*[A-Za-z][A-Za-z '’\-]{1,50}\s*:\s*$", value_line.text):
                    break
                if not (_same_row(line, value_line) or _near_below(line, value_line)):
                    continue
                candidate = _candidate(value_line, value_line.text, 0, len(value_line.text), label_match.group("label"))
                if candidate:
                    key = (candidate.page_index, candidate.page_char_start, candidate.page_char_end)
                    if key not in occupied:
                        occupied.add(key); detections.append(candidate)
                    break
    return detections
