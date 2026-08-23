from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


@dataclass(frozen=True)
class _PatternSpec:
    entity_type: EntityType
    pattern: re.Pattern[str]
    sensitivity: SensitivityLevel


_PATTERN_SPECS = (
    _PatternSpec(
        EntityType.EMAIL,
        re.compile(
            r"(?<![\w.+-])[A-Z0-9._%+-]+\s*@\s*[A-Z0-9-]+(?:\s*\.\s*[A-Z0-9-]+)*\s*\.\s*[A-Z]{2,}(?![\w.-])",
            re.IGNORECASE,
        ),
        SensitivityLevel.HIGH,
    ),
    _PatternSpec(
        EntityType.PAN_LIKE,
        re.compile(r"(?<![A-Z0-9])[A-Z]{5}\s*\d{4}\s*[A-Z](?![A-Z0-9])", re.IGNORECASE),
        SensitivityLevel.HIGH,
    ),
    _PatternSpec(
        EntityType.AADHAAR_LIKE,
        re.compile(r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"),
        SensitivityLevel.HIGH,
    ),
    _PatternSpec(
        EntityType.PHONE,
        re.compile(
            r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,5}\)?[\s.-]?)?"
            r"\d{3,5}[\s.-]?\d{3,5}(?:[\s.-]?\d{2,5})?(?!\d)"
        ),
        SensitivityLevel.HIGH,
    ),
)


_TEXTUAL_TYPES = {
    EntityType.EMAIL,
    EntityType.PAN_LIKE,
    EntityType.PERSON_NAME,
    EntityType.DATE_OF_BIRTH,
    EntityType.AGE,
    EntityType.STREET_ADDRESS,
    EntityType.LOCALITY,
    EntityType.EMPLOYER,
    EntityType.JOB_TITLE,
    EntityType.CASE_REFERENCE,
    EntityType.PERSON_TITLE,
    EntityType.GENERIC_DATE,
    EntityType.DEMOGRAPHIC_ATTRIBUTE,
}

_ALNUM_IDENTIFIER_TYPES = {
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
}


def normalize_value(entity_type: EntityType, value: str) -> str:
    value = value.strip()
    if entity_type == EntityType.EMAIL:
        return re.sub(r"\s+", "", value).casefold()
    if entity_type == EntityType.PAN_LIKE:
        return re.sub(r"\s+", "", value).upper()
    if entity_type in _TEXTUAL_TYPES:
        return re.sub(r"\s+", " ", value).strip().casefold()
    if entity_type in _ALNUM_IDENTIFIER_TYPES:
        return re.sub(r"[^A-Z0-9]", "", value.upper())
    return re.sub(r"\D", "", value)


def replacement_for(entity_type: EntityType, value: str) -> str:
    normalized = normalize_value(entity_type, value)
    if entity_type == EntityType.PHONE:
        return "X" * max(0, len(normalized) - 4) + normalized[-4:]
    if entity_type == EntityType.AADHAAR_LIKE:
        return f"XXXX XXXX {normalized[-4:]}"
    if entity_type == EntityType.PAN_LIKE:
        return f"XXXXXX{normalized[-4:]}"
    if entity_type == EntityType.EMAIL:
        local, _, domain = normalized.partition("@")
        first = local[:1] or "x"
        return f"{first}***@{domain}"
    if entity_type == EntityType.PERSON_NAME:
        return "[NAME PROTECTED]"
    if entity_type == EntityType.CASE_REFERENCE:
        return "[REFERENCE PROTECTED]"
    if entity_type == EntityType.PAYMENT_CARD_NUMBER:
        return "XXXX XXXX XXXX " + (normalized[-4:] if normalized else "XXXX")
    if entity_type in _ALNUM_IDENTIFIER_TYPES:
        suffix = normalized[-4:] if len(normalized) >= 4 else normalized
        return f"[CREDENTIAL MASKED {suffix}]" if suffix else "[CREDENTIAL MASKED]"
    return "[PROTECTED]"


def _token_char_spans(tokens: tuple[PositionedToken, ...]) -> list[tuple[int, int, PositionedToken]]:
    spans: list[tuple[int, int, PositionedToken]] = []
    offset = 0
    for index, token in enumerate(tokens):
        start = offset
        end = start + len(token.text)
        spans.append((start, end, token))
        offset = end + (1 if index < len(tokens) - 1 else 0)
    return spans


def _rect_for_match(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    overlapping = [
        token for token_start, token_end, token in _token_char_spans(line.tokens)
        if token_start < end and token_end > start
    ]
    if not overlapping:
        return None
    return (
        min(token.x0 for token in overlapping),
        min(token.y0 for token in overlapping),
        max(token.x1 for token in overlapping),
        max(token.y1 for token in overlapping),
    )


def _valid_aadhaar_like(value: str, line_text: str, start: int, end: int) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12:
        return False
    lowered = line_text.casefold()
    # Reject 12-digit groups that are visibly embedded in version/build identifiers
    # or explicitly negated as Aadhaar. This remains "AADHAAR_LIKE" detection;
    # it intentionally does not claim UIDAI authenticity.
    if any(marker in lowered for marker in (
        "not an aadhaar", "not aadhaar", "software version", "build version",
        "version string", "release version", "credit card", "debit card", "payment card",
    )):
        return False
    if start > 0 and line_text[start - 1] in "-_/." and start > 1 and line_text[start - 2].isalnum():
        return False
    if end < len(line_text) and line_text[end] in "-_/." and end + 1 < len(line_text) and line_text[end + 1].isalnum():
        return False
    return True


def _valid_phone(value: str, line_text: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15 or len(set(digits)) == 1:
        return False
    lowered = line_text.casefold()
    # Avoid interpreting dates and reference numbers as phones. Shorter phone
    # candidates require a phone/contact label; 10+ digit values remain valid.
    if "/" in value or re.fullmatch(r"\d{1,4}-\d{1,4}-\d{1,4}", value.strip()):
        return False
    if any(label in lowered for label in ("case reference", "case ref", "reference id", "application id", "date of birth", "dob")):
        return False
    if len(digits) < 10 and not any(label in lowered for label in ("phone", "mobile", "contact", "telephone", "tel")):
        return False
    return True


def detect_direct_identifiers(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    for page in document.pages:
        for line in page.lines:
            occupied: list[tuple[int, int]] = []
            for spec in _PATTERN_SPECS:
                for match in spec.pattern.finditer(line.text):
                    start, end = match.span()
                    if any(start < other_end and end > other_start for other_start, other_end in occupied):
                        continue
                    value = match.group(0).strip()
                    normalized = normalize_value(spec.entity_type, value)
                    if spec.entity_type == EntityType.PHONE and not _valid_phone(value, line.text):
                        continue
                    if spec.entity_type == EntityType.AADHAAR_LIKE and not _valid_aadhaar_like(value, line.text, start, end):
                        continue
                    if spec.entity_type == EntityType.PAN_LIKE and len(normalized) != 10:
                        continue
                    rect = _rect_for_match(line, start, end)
                    if rect is None:
                        continue
                    confidence = min(token.confidence for token in line.tokens) if line.tokens else 0.8
                    if line.source == DetectionSource.TEXT_LAYER:
                        confidence = max(confidence, 0.99)
                    detections.append(
                        DetectedMention(
                            entity_type=spec.entity_type,
                            plaintext=value,
                            page_index=page.page_index,
                            page_char_start=line.page_char_start + start,
                            page_char_end=line.page_char_start + end,
                            rect=rect,
                            confidence=max(0.55, min(1.0, confidence)),
                            source=line.source,
                            sensitivity=spec.sensitivity,
                            transformation=TransformationType.MASK,
                            review_status=ReviewStatus.NOT_REQUIRED,
                            context_label=None,
                        )
                    )
                    occupied.append((start, end))
    return detections
