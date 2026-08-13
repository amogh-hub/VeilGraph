from __future__ import annotations

import re

from app.core.enums import (
    DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType,
)
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, ProcessedDocument


_LABELS = (
    (re.compile(r"^\s*(?:subject|primary subject|name|person|case owner)\s*:\s*(.+?)\s*$", re.I), EntityType.PERSON_NAME, TransformationType.PSEUDONYMIZE, True, "person"),
    (re.compile(r"^\s*(?:location|city|locality)\s*:\s*(.+?)\s*$", re.I), EntityType.LOCALITY, TransformationType.GENERALIZE, False, "location"),
    (re.compile(r"^\s*(?:case|case reference|reference)\s*:\s*([A-Za-z0-9][A-Za-z0-9._/-]{4,})\s*$", re.I), EntityType.CASE_REFERENCE, TransformationType.PSEUDONYMIZE, False, "case-reference"),
)


def _token_spans(line: PositionedLine) -> list[tuple[int, int, object]]:
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


def _rect_for_span(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    tokens = [token for left, right, token in _token_spans(line) if left < end and right > start]
    if not tokens:
        return None
    return (
        min(float(token.x0) for token in tokens),
        min(float(token.y0) for token in tokens),
        max(float(token.x1) for token in tokens),
        max(float(token.y1) for token in tokens),
    )


def detect_video_structural_context(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    for page in document.pages:
        for line in page.lines:
            for pattern, entity_type, transformation, needs_review, label in _LABELS:
                match = pattern.match(line.text)
                if not match:
                    continue
                value = match.group(1).strip().rstrip(".,;|")
                if len(value) < 2:
                    continue
                start = line.text.find(match.group(1))
                end = start + len(match.group(1))
                rect = _rect_for_span(line, start, end)
                if rect is None:
                    continue
                detections.append(DetectedMention(
                    entity_type=entity_type,
                    plaintext=value,
                    page_index=page.page_index,
                    page_char_start=line.page_char_start + start,
                    page_char_end=line.page_char_start + end,
                    rect=rect,
                    confidence=0.98 if needs_review else 0.97,
                    source=DetectionSource.OCR,
                    sensitivity=SensitivityLevel.HIGH if entity_type in {EntityType.PERSON_NAME, EntityType.CASE_REFERENCE} else SensitivityLevel.MEDIUM,
                    transformation=transformation,
                    review_status=ReviewStatus.PENDING if needs_review else ReviewStatus.NOT_REQUIRED,
                    context_label=f"video-structural:{label}",
                ))
                break
    return detections
