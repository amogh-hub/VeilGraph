from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


Validator = Callable[[str], bool]


@dataclass(frozen=True)
class LabelSpec:
    entity_type: EntityType
    labels: tuple[str, ...]
    sensitivity: SensitivityLevel
    transformation: TransformationType
    validator: Validator


def _date_valid(value: str) -> bool:
    cleaned = re.sub(r"\s+", " ", value.strip().strip(".,;"))
    formats = (
        "%d %B %Y", "%d %b %Y", "%B %d %Y", "%b %d %Y",
        "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(cleaned.replace(",", ""), fmt)
            return 1900 <= parsed.year <= datetime.now().year
        except ValueError:
            continue
    return False


def _age_valid(value: str) -> bool:
    match = re.fullmatch(r"\s*(\d{1,3})(?:\s*(?:years?|yrs?|y/o))?\s*", value, re.IGNORECASE)
    return bool(match and 0 <= int(match.group(1)) <= 120)


def _postcode_valid(value: str) -> bool:
    return bool(re.fullmatch(r"\s*\d{6}\s*", value))


def _text_value(min_len: int, max_len: int) -> Validator:
    def validate(value: str) -> bool:
        cleaned = re.sub(r"\s+", " ", value.strip().strip("|,;:"))
        return min_len <= len(cleaned) <= max_len and cleaned.casefold() not in {
            "none", "nil", "unknown", "not available", "n/a",
        }
    return validate


def _case_ref_valid(value: str) -> bool:
    cleaned = value.strip()
    return bool(re.fullmatch(r"[A-Z0-9][A-Z0-9/_-]{4,39}", cleaned, re.IGNORECASE))


_SPECS = (
    LabelSpec(
        EntityType.DATE_OF_BIRTH,
        (r"date\s+of\s+birth", r"d\.?o\.?b\.?") ,
        SensitivityLevel.HIGH,
        TransformationType.GENERALIZE,
        _date_valid,
    ),
    LabelSpec(
        EntityType.AGE,
        (r"age",),
        SensitivityLevel.MEDIUM,
        TransformationType.GENERALIZE,
        _age_valid,
    ),
    LabelSpec(
        EntityType.STREET_ADDRESS,
        (r"residential\s+address", r"home\s+address", r"address"),
        SensitivityLevel.HIGH,
        TransformationType.GENERALIZE,
        _text_value(5, 180),
    ),
    LabelSpec(
        EntityType.LOCALITY,
        (r"locality", r"city", r"district"),
        SensitivityLevel.MEDIUM,
        TransformationType.GENERALIZE,
        _text_value(2, 100),
    ),
    LabelSpec(
        EntityType.POSTCODE,
        (r"pin\s*code", r"pincode", r"postal\s+code", r"pin"),
        SensitivityLevel.HIGH,
        TransformationType.GENERALIZE,
        _postcode_valid,
    ),
    LabelSpec(
        EntityType.EMPLOYER,
        (r"employer", r"organisation", r"organization", r"company"),
        SensitivityLevel.MEDIUM,
        TransformationType.PSEUDONYMIZE,
        _text_value(2, 120),
    ),
    LabelSpec(
        EntityType.JOB_TITLE,
        (r"job\s+title", r"designation", r"occupation", r"role"),
        SensitivityLevel.MEDIUM,
        TransformationType.GENERALIZE,
        _text_value(2, 100),
    ),
    LabelSpec(
        EntityType.CASE_REFERENCE,
        (r"case\s+reference", r"case\s+ref", r"reference\s+id", r"application\s+id"),
        SensitivityLevel.HIGH,
        TransformationType.PSEUDONYMIZE,
        _case_ref_valid,
    ),
)


def _token_spans(tokens: tuple[PositionedToken, ...]) -> list[tuple[int, int, PositionedToken]]:
    spans: list[tuple[int, int, PositionedToken]] = []
    offset = 0
    for index, token in enumerate(tokens):
        start = offset
        end = start + len(token.text)
        spans.append((start, end, token))
        offset = end + (1 if index < len(tokens) - 1 else 0)
    return spans


def _rect_for_span(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    tokens = [
        token for token_start, token_end, token in _token_spans(line.tokens)
        if token_start < end and token_end > start
    ]
    if not tokens:
        return None
    return (
        min(token.x0 for token in tokens), min(token.y0 for token in tokens),
        max(token.x1 for token in tokens), max(token.y1 for token in tokens),
    )


def _line_rect(line: PositionedLine) -> tuple[float, float, float, float] | None:
    if not line.tokens:
        return None
    return (
        min(token.x0 for token in line.tokens), min(token.y0 for token in line.tokens),
        max(token.x1 for token in line.tokens), max(token.y1 for token in line.tokens),
    )


def _same_row(label_line: PositionedLine, value_line: PositionedLine) -> bool:
    left = _line_rect(label_line)
    right = _line_rect(value_line)
    if left is None or right is None:
        return False
    _lx0, ly0, lx1, ly1 = left
    vx0, vy0, _vx1, vy1 = right
    overlap = max(0.0, min(ly1, vy1) - max(ly0, vy0))
    return overlap >= min(ly1 - ly0, vy1 - vy0) * 0.45 and vx0 > lx1 - 3.0


def _near_below(label_line: PositionedLine, value_line: PositionedLine) -> bool:
    label = _line_rect(label_line)
    value = _line_rect(value_line)
    if label is None or value is None:
        return False
    lx0, _ly0, _lx1, ly1 = label
    vx0, vy0, _vx1, _vy1 = value
    return 0.0 <= vy0 - ly1 <= 34.0 and vx0 >= lx0 - 4.0


def _confidence(line: PositionedLine, start: int, end: int) -> float:
    relevant = [
        token.confidence for token_start, token_end, token in _token_spans(line.tokens)
        if token_start < end and token_end > start
    ]
    base = min(relevant) if relevant else 0.75
    if line.source == DetectionSource.TEXT_LAYER:
        return 0.99
    return max(0.55, min(0.95, base))


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("|,;:"))


def _compile_patterns(spec: LabelSpec) -> tuple[re.Pattern[str], re.Pattern[str]]:
    body = "(?:" + "|".join(spec.labels) + ")"
    same_line = re.compile(rf"^\s*(?P<label>{body})\s*[:\-]\s*(?P<value>.+?)\s*$", re.IGNORECASE)
    label_only = re.compile(rf"^\s*(?P<label>{body})\s*:?\s*$", re.IGNORECASE)
    return same_line, label_only


def _candidate(
    spec: LabelSpec,
    line: PositionedLine,
    value: str,
    start: int,
    end: int,
    label: str,
) -> DetectedMention | None:
    cleaned = _clean(value)
    if not spec.validator(cleaned):
        return None
    rect = _rect_for_span(line, start, end)
    if rect is None:
        return None
    return DetectedMention(
        entity_type=spec.entity_type,
        plaintext=cleaned,
        page_index=line.page_index,
        page_char_start=line.page_char_start + start,
        page_char_end=line.page_char_start + end,
        rect=rect,
        confidence=_confidence(line, start, end),
        source=line.source,
        sensitivity=spec.sensitivity,
        transformation=spec.transformation,
        review_status=ReviewStatus.NOT_REQUIRED,
        context_label=re.sub(r"\s+", " ", label.strip()).casefold(),
    )


def detect_quasi_identifiers(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    occupied: set[tuple[int, int, int, EntityType]] = set()
    for page in document.pages:
        lines = list(page.lines)
        for spec in _SPECS:
            same_line_pattern, label_only_pattern = _compile_patterns(spec)
            for index, line in enumerate(lines):
                same = same_line_pattern.match(line.text)
                if same:
                    start, end = same.span("value")
                    candidate = _candidate(spec, line, same.group("value"), start, end, same.group("label"))
                    if candidate:
                        key = (candidate.page_index, candidate.page_char_start, candidate.page_char_end, candidate.entity_type)
                        if key not in occupied:
                            occupied.add(key)
                            detections.append(candidate)
                    continue
                label_match = label_only_pattern.match(line.text)
                if not label_match:
                    continue
                for value_line in lines[index + 1:index + 4]:
                    if any(_compile_patterns(other)[1].match(value_line.text) for other in _SPECS):
                        break
                    if not (_same_row(line, value_line) or _near_below(line, value_line)):
                        continue
                    candidate = _candidate(
                        spec,
                        value_line,
                        value_line.text,
                        0,
                        len(value_line.text),
                        label_match.group("label"),
                    )
                    if candidate:
                        key = (candidate.page_index, candidate.page_char_start, candidate.page_char_end, candidate.entity_type)
                        if key not in occupied:
                            occupied.add(key)
                            detections.append(candidate)
                        break
    return detections
