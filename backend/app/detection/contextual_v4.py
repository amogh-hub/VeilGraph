from __future__ import annotations

"""Broad PII v4 context/schema detector.

This layer fills the high-value gap between strict validators and the local
semantic span classifier.  It is deliberately format-agnostic: native text,
DOCX, PDF text layers and structured-data adapters all expose PositionedLine
objects, so the same field/context semantics can be applied without hard-coding
specific judge fixture values.
"""

import re
import unicodedata
from dataclasses import dataclass

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


_FIELD_WRAPPER = r"(?:\*{0,2}|_{0,2}|`?)"
_FIELD_SEP = r"(?:\s*[:=]\s*|\s+[-–—]\s+)"

# Labels intentionally cover common document and table vocabulary rather than
# one dataset's exact headings.  Header normalization makes spaces, underscores
# and slashes equivalent.
_LABELS: dict[EntityType, tuple[str, ...]] = {
    EntityType.PERSON_NAME: (
        "name", "full name", "person name", "subject", "participant", "reviewer",
        "owner", "citizen", "patient", "customer", "applicant", "employee",
        "case owner", "record owner", "related person", "emergency contact",
    ),
    EntityType.EMAIL: ("email", "e-mail", "mail", "email address", "contact email"),
    EntityType.PHONE: ("phone", "mobile", "telephone", "tel", "contact number", "mobile number"),
    EntityType.AGE: ("age", "age exact", "exact age"),
    EntityType.LOCALITY: ("city", "locality", "location", "town", "place", "city / locality", "follow-up city"),
    EntityType.EMPLOYER: (
        "employer", "organisation", "organization", "institution", "company", "agency",
        "department", "workplace",
    ),
    EntityType.CASE_REFERENCE: (
        "case", "case ref", "case reference", "reference", "ref", "record reference",
        "application reference", "ticket reference", "case id",
    ),
    EntityType.POSTCODE: ("postcode", "postal", "postal code", "pin code", "pincode", "zip", "zip code"),
    EntityType.GENERIC_DATE: ("event date", "date", "record date", "filing date"),
}

# Nested JSON often produces paths such as participants.employer.name.  Use the
# complete header path, not only the terminal token, to disambiguate `name`.
_HEADER_PATH_HINTS: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    (EntityType.EMPLOYER, re.compile(r"(?:^|\.)(?:employer|organisation|organization|company)(?:\.|$)", re.I)),
    (EntityType.LOCALITY, re.compile(r"(?:^|\.)(?:places?|locations?|cities|city|locality)(?:\.|$)", re.I)),
    (EntityType.PERSON_NAME, re.compile(r"(?:^|\.)(?:participants?|people|persons?|subjects?|owners?)(?:\.|.*\.)name$", re.I)),
    (EntityType.EMAIL, re.compile(r"(?:^|\.)(?:email|emails)(?:\.|$)", re.I)),
    (EntityType.PHONE, re.compile(r"(?:^|\.)(?:phone|phones|mobile|telephone)(?:\.|$)", re.I)),
    (EntityType.CASE_REFERENCE, re.compile(r"(?:^|\.)(?:case|case_ref|case_reference|reference|ref)(?:\.|$)", re.I)),
    (EntityType.POSTCODE, re.compile(r"(?:^|\.)(?:postcode|postal_code|pincode|zip)(?:\.|$)", re.I)),
)

_CASE_TOKEN = re.compile(
    r"(?<![\w])(?P<value>(?=[A-Z0-9][A-Z0-9._/-]{4,39}(?![\w.-]))(?=[A-Z0-9._/-]*\d)[A-Z][A-Z0-9]*(?:[-_/][A-Z0-9]+){1,6})(?![\w.-])",
    re.I,
)
_POSTCODE_IN = re.compile(r"(?<!\d)(?P<value>[1-9]\d{5})(?!\d)")
_AGE_VALUE = re.compile(r"(?<!\d)(?P<value>\d{1,3}(?:\s*(?:years?|yrs?|y/o))?)(?!\d)", re.I)
_DATE_VALUE = re.compile(r"(?P<value>(?:19|20)\d{2}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-](?:19|20)?\d{2})")
_EMAIL_VALUE = re.compile(r"(?P<value>[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63})", re.I)
_PHONE_VALUE = re.compile(r"(?P<value>\+?\d[\d ().-]{6,22}\d)")

# Strong prose context for case/reference identifiers, independent of the VG
# prefix used by the fictional development data.
_CASE_CONTEXT = re.compile(r"\b(?:case|reference|ref(?:erence)?|ticket|application|record)\s*(?:number|no\.?|id)?\s*(?:is|=|:|#|-)?\s*", re.I)

# Context for organisations and people in prose.  Local semantic NER remains a
# second independent channel; these patterns are intentionally high precision.
_ORG_CONTEXT = re.compile(r"\b(?:works?|worked|employed|affiliated)\s+(?:at|by|with)\s+(?P<value>[\w&.'’\-/]+(?:\s+[\w&.'’\-/]+){1,8}?)(?=\s+(?:as|in|on|for)\b|[.,;]|$)", re.I | re.UNICODE)
_PERSON_CONTEXT = re.compile(r"\b(?i:participant|subject|applicant|owner|reviewer|citizen|patient|alias\s+note\s*:|emergency\s+contact\s+is|contact\s+is)\s*(?P<value>[A-Z][\w'’.-]+(?:\s+[A-Z][\w'’.-]+){1,3})(?=\s+(?i:appears|attended|submitted|requested|reported|filed|works|was|is|has|who|reachable)\b|[.,;]|$)", re.UNICODE)
_LOCALITY_CONTEXT = re.compile(r"\b(?:from|in|at)\s+(?P<value>[A-Z][\w'’.-]+(?:\s+[A-Z][\w'’.-]+){0,2})(?=\s+(?:to|for|after|before|during|under|and|who|where)\b|[.,;)]|$)", re.UNICODE)

_GENERIC_VALUE_BLOCK = {"", "n/a", "na", "none", "nil", "unknown", "not available", "end", "sample", "value", "field", "key", "-", "--", "test data", "demo data", "sample data", "service record", "case report", "research note", "identity card", "privacy demo"}


@dataclass(frozen=True)
class _Candidate:
    entity_type: EntityType
    line: PositionedLine
    start: int
    end: int
    value: str
    confidence: float
    context: str
    review: ReviewStatus


def _token_spans(tokens: tuple[PositionedToken, ...]) -> list[tuple[int, int, PositionedToken]]:
    spans: list[tuple[int, int, PositionedToken]] = []
    offset = 0
    for index, token in enumerate(tokens):
        start = offset
        end = start + len(token.text)
        spans.append((start, end, token))
        offset = end + (1 if index < len(tokens) - 1 else 0)
    return spans


def _rect(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    tokens = [token for a, b, token in _token_spans(line.tokens) if a < end and b > start]
    if not tokens:
        return None
    return (
        min(t.x0 for t in tokens), min(t.y0 for t in tokens),
        max(t.x1 for t in tokens), max(t.y1 for t in tokens),
    )


def _header_key(value: str) -> str:
    value = value.replace("_", " ").replace("/", " ").replace("-", " ")
    value = re.sub(r"[\*`#:]+", " ", value)
    return re.sub(r"\s+", " ", value).strip().casefold()


def _looks_person(value: str) -> bool:
    value = value.strip(" \t|,;:—–-")
    if not (2 <= len(value) <= 100) or value.casefold() in _GENERIC_VALUE_BLOCK:
        return False
    # Permit Unicode scripts and all-uppercase table values. Require at least two
    # lexical chunks and reject mostly numeric/identifier-like values.
    chunks = [p for p in re.split(r"\s+", value) if p]
    if not 2 <= len(chunks) <= 5:
        return False
    if any(any(ch.isdigit() for ch in p) for p in chunks):
        return False
    meaningful = sum(ch.isalpha() or unicodedata.category(ch) in {"Mn", "Mc"} for ch in value)
    nonspace = sum(not ch.isspace() for ch in value)
    return meaningful >= 4 and meaningful / max(1, nonspace) >= 0.58


def _looks_org(value: str) -> bool:
    value = value.strip(" \t|,;:—–-")
    if not (2 <= len(value) <= 140) or value.casefold() in _GENERIC_VALUE_BLOCK:
        return False
    return sum(ch.isalpha() for ch in value) >= 3 and "@" not in value


def _looks_locality(value: str) -> bool:
    value = value.strip(" \t|,;:—–-")
    if not (2 <= len(value) <= 90) or value.casefold() in _GENERIC_VALUE_BLOCK:
        return False
    return sum(ch.isalpha() for ch in value) >= 2 and "@" not in value


def _validated_value(entity_type: EntityType, raw: str) -> str | None:
    value = raw.strip().strip("`*_ \t|,;:—–")
    if value.casefold() in _GENERIC_VALUE_BLOCK:
        return None
    if entity_type == EntityType.PERSON_NAME:
        return value if _looks_person(value) else None
    if entity_type == EntityType.EMAIL:
        match = _EMAIL_VALUE.search(value)
        return match.group("value") if match else None
    if entity_type == EntityType.PHONE:
        match = _PHONE_VALUE.search(value)
        if not match:
            return None
        candidate = match.group("value").strip()
        digits = re.sub(r"\D", "", candidate)
        return candidate if 7 <= len(digits) <= 15 and len(set(digits)) > 1 else None
    if entity_type == EntityType.AGE:
        match = _AGE_VALUE.search(value)
        if not match:
            return None
        candidate = match.group("value").strip()
        numeric = re.match(r"\d{1,3}", candidate)
        age = int(numeric.group(0)) if numeric else 999
        return candidate if 0 <= age <= 120 else None
    if entity_type == EntityType.LOCALITY:
        # Parenthetical transliterations/context are separate evidence; the primary
        # locality span should stay exact (e.g. Mysuru in "Mysuru (ಮೈಸೂರು)").
        primary = value.split("(", 1)[0].strip() if "(" in value else value
        return primary if _looks_locality(primary) else None
    if entity_type == EntityType.EMPLOYER:
        return value if _looks_org(value) else None
    if entity_type == EntityType.CASE_REFERENCE:
        match = _CASE_TOKEN.search(value)
        return match.group("value") if match else None
    if entity_type == EntityType.POSTCODE:
        match = _POSTCODE_IN.search(value)
        return match.group("value") if match else None
    if entity_type == EntityType.GENERIC_DATE:
        match = _DATE_VALUE.search(value)
        return match.group("value") if match else None
    return None


def _split_label_value(text: str) -> tuple[str, str, int] | None:
    # Markdown wrappers around the label/value are removed only for matching; the
    # returned offset always refers to the original line so evidence geometry is exact.
    match = re.match(r"^\s*(?:[-*+]\s+)?(?P<label>(?:\*{0,2}|_{0,2}|`?)[^:=|]{1,50}?(?:\*{0,2}|_{0,2}|`?))\s*(?P<sep>[:=])\s*(?P<value>.+?)\s*$", text)
    if not match:
        return None
    label = match.group("label").strip().strip("*_` ")
    return label, match.group("value"), match.start("value")


def _entity_for_header(label: str) -> EntityType | None:
    raw = label.strip()
    normalized = _header_key(raw)
    # Path hints outrank terminal `name`, fixing nested employer.name JSON.
    for entity_type, pattern in _HEADER_PATH_HINTS:
        if pattern.search(raw.replace("_", " ")) or pattern.search(raw):
            return entity_type
    for entity_type, labels in _LABELS.items():
        if normalized in {_header_key(item) for item in labels}:
            return entity_type
    # Structured nested paths often end with a known semantic key.
    terminal = _header_key(re.split(r"[.]", raw)[-1])
    for entity_type, labels in _LABELS.items():
        if terminal in {_header_key(item) for item in labels}:
            return entity_type
    return None


def _field_candidates(line: PositionedLine) -> list[_Candidate]:
    parsed = _split_label_value(line.text)
    if not parsed:
        return []
    label, raw_value, value_offset = parsed
    entity_type = _entity_for_header(label)
    if entity_type is None:
        return []

    # A locality field may intentionally contain a hierarchy such as
    # "Indiranagar, Bengaluru". Emit exact components in addition to the full
    # value only when comma-separated; downstream graph fusion keeps them distinct.
    values: list[tuple[str, int, int]] = []
    if entity_type == EntityType.LOCALITY and "," in raw_value:
        cursor = 0
        for part in raw_value.split(","):
            leading = len(part) - len(part.lstrip())
            cleaned = part.strip().strip("`*_")
            if cleaned:
                local = raw_value.find(part, cursor) + leading
                values.append((cleaned, value_offset + local, value_offset + local + len(cleaned)))
            cursor += len(part) + 1
    elif entity_type == EntityType.PERSON_NAME and re.search(r"\s+[—–]\s+", raw_value):
        # Multilingual aliases/transliterations may be supplied side by side.
        # Each script form is a separate exact evidence span.
        for match in re.finditer(r"(?:^|\s+[—–]\s+)(?P<value>[^—–]+?)(?=\s+[—–]\s+|$)", raw_value):
            cleaned = match.group("value").strip().strip("`*_")
            if _looks_person(cleaned):
                local = match.start("value") + (len(match.group("value")) - len(match.group("value").lstrip()))
                values.append((cleaned, value_offset + local, value_offset + local + len(cleaned)))
    else:
        checked = _validated_value(entity_type, raw_value)
        if checked:
            local = raw_value.find(checked)
            values.append((checked, value_offset + local, value_offset + local + len(checked)))

    result: list[_Candidate] = []
    for value, start, end in values:
        checked = _validated_value(entity_type, value)
        if checked is None:
            continue
        # Ensure exact span if validator selected a substring (email/phone/case/date).
        if checked != value:
            delta = value.find(checked)
            start += delta
            end = start + len(checked)
            value = checked
        review = ReviewStatus.PENDING if entity_type == EntityType.PERSON_NAME else ReviewStatus.NOT_REQUIRED
        result.append(_Candidate(entity_type, line, start, end, value, 0.985, f"broad-pii-v4:field:{_header_key(label)}", review))
    return result


def _inline_field_candidates(line: PositionedLine) -> list[_Candidate]:
    """Handle dense log/RTF forms: owner=Rohan Das|mail=a@b|city=Pune."""
    result: list[_Candidate] = []
    text = line.text
    # Delimited mini-fields.  Value ends at |, semicolon, or another key=value.
    pattern = re.compile(r"(?P<label>[A-Za-z][A-Za-z _/-]{0,30})\s*=\s*(?P<value>[^|;]+)")
    for match in pattern.finditer(text):
        entity_type = _entity_for_header(match.group("label"))
        if entity_type is None:
            continue
        raw = match.group("value").strip()
        checked = _validated_value(entity_type, raw)
        if checked is None:
            continue
        local = match.group("value").find(checked)
        start = match.start("value") + local
        end = start + len(checked)
        result.append(_Candidate(
            entity_type, line, start, end, checked, 0.975,
            f"broad-pii-v4:inline-field:{_header_key(match.group('label'))}",
            ReviewStatus.PENDING if entity_type == EntityType.PERSON_NAME else ReviewStatus.NOT_REQUIRED,
        ))
    return result


def _prose_candidates(line: PositionedLine) -> list[_Candidate]:
    result: list[_Candidate] = []
    text = line.text
    for context in _CASE_CONTEXT.finditer(text):
        match = _CASE_TOKEN.search(text, context.end())
        if match and match.start("value") - context.end() <= 24:
            result.append(_Candidate(EntityType.CASE_REFERENCE, line, *match.span("value"), match.group("value"), 0.97, "broad-pii-v4:case-context", ReviewStatus.NOT_REQUIRED))
            break
    for match in _PERSON_CONTEXT.finditer(text):
        value = match.group("value").strip()
        if _looks_person(value):
            result.append(_Candidate(EntityType.PERSON_NAME, line, *match.span("value"), value, 0.90, "broad-pii-v4:person-context", ReviewStatus.PENDING))
    for match in _ORG_CONTEXT.finditer(text):
        raw = match.group("value")
        value = raw.strip().rstrip(".,;:")
        start = match.start("value") + (len(raw) - len(raw.lstrip()))
        result.append(_Candidate(EntityType.EMPLOYER, line, start, start + len(value), value, 0.91, "broad-pii-v4:employer-context", ReviewStatus.PENDING))
    for match in _LOCALITY_CONTEXT.finditer(text):
        raw = match.group("value")
        value = raw.strip().rstrip(".,;:")
        start = match.start("value") + (len(raw) - len(raw.lstrip()))
        # Avoid swallowing organisational/common connective phrases.
        if _looks_locality(value) and value.casefold() not in {"the file", "the report", "the system", "the dataset"}:
            result.append(_Candidate(EntityType.LOCALITY, line, start, start + len(value), value, 0.82, "broad-pii-v4:locality-context", ReviewStatus.PENDING))
    return result


def _sensitivity(entity_type: EntityType) -> tuple[SensitivityLevel, TransformationType]:
    if entity_type in {EntityType.PERSON_NAME, EntityType.EMAIL, EntityType.PHONE, EntityType.CASE_REFERENCE, EntityType.POSTCODE}:
        return SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE if entity_type in {EntityType.PERSON_NAME, EntityType.CASE_REFERENCE} else (TransformationType.GENERALIZE if entity_type == EntityType.POSTCODE else TransformationType.MASK)
    if entity_type == EntityType.EMPLOYER:
        return SensitivityLevel.MEDIUM, TransformationType.PSEUDONYMIZE
    return SensitivityLevel.MEDIUM, TransformationType.GENERALIZE


def _mention(candidate: _Candidate) -> DetectedMention | None:
    rect = _rect(candidate.line, candidate.start, candidate.end)
    if rect is None:
        return None
    sensitivity, transformation = _sensitivity(candidate.entity_type)
    confidence = candidate.confidence
    if candidate.line.source == DetectionSource.TEXT_LAYER:
        confidence = max(confidence, 0.97 if ":field:" in candidate.context or ":inline-field:" in candidate.context else confidence)
    return DetectedMention(
        entity_type=candidate.entity_type,
        plaintext=candidate.value,
        page_index=candidate.line.page_index,
        page_char_start=candidate.line.page_char_start + candidate.start,
        page_char_end=candidate.line.page_char_start + candidate.end,
        rect=rect,
        confidence=max(0.55, min(0.995, confidence)),
        source=candidate.line.source,
        sensitivity=sensitivity,
        transformation=transformation,
        review_status=candidate.review,
        context_label=candidate.context,
    )



def _line_value_after_label(line: PositionedLine) -> tuple[str, int] | None:
    text = line.text.strip()
    if not text:
        return None
    leading = len(line.text) - len(line.text.lstrip())
    return text.strip("`*_ "), leading


def _adjacent_field_candidates(page_lines: tuple[PositionedLine, ...]) -> list[_Candidate]:
    """Recognise two-line/table layouts where a label and value are separate lines."""
    result: list[_Candidate] = []
    lines = list(page_lines)
    for index, line in enumerate(lines[:-1]):
        label = line.text.strip().strip("`*_: ")
        entity_type = _entity_for_header(label)
        if entity_type is None:
            continue
        # Avoid generic headers such as a table column named simply Value/Field.
        if _header_key(label) in {"value", "field", "key", "privacy note", "note"}:
            continue
        value_line = lines[index + 1]
        raw = value_line.text.strip()
        if _split_label_value(value_line.text) is not None or _entity_for_header(raw.strip("`*_: ")) is not None:
            continue
        checked = _validated_value(entity_type, raw)
        if checked is None:
            continue
        start = value_line.text.find(checked)
        result.append(_Candidate(
            entity_type, value_line, start, start + len(checked), checked, 0.965,
            f"broad-pii-v4:adjacent-field:{_header_key(label)}",
            ReviewStatus.PENDING if entity_type == EntityType.PERSON_NAME else ReviewStatus.NOT_REQUIRED,
        ))
    return result


def _key_value_record_candidates(page_lines: tuple[PositionedLine, ...]) -> list[_Candidate]:
    """Handle normalized key/value records (common in two-column XLSX exports)."""
    key_line = value_line = None
    for line in page_lines:
        parsed = _split_label_value(line.text)
        if not parsed:
            continue
        label, raw, offset = parsed
        if _header_key(label) == "key":
            key_line = (raw.strip(), line)
        elif _header_key(label) == "value":
            value_line = (raw.strip(), line, offset)
    if not key_line or not value_line:
        return []
    semantic_key = key_line[0]
    entity_type = _entity_for_header(semantic_key)
    if entity_type is None:
        return []
    raw, line, offset = value_line
    checked = _validated_value(entity_type, raw)
    if checked is None:
        return []
    local = raw.find(checked)
    start = offset + local
    return [_Candidate(
        entity_type, line, start, start + len(checked), checked, 0.98,
        f"broad-pii-v4:key-value:{_header_key(semantic_key)}",
        ReviewStatus.PENDING if entity_type == EntityType.PERSON_NAME else ReviewStatus.NOT_REQUIRED,
    )]

def detect_contextual_v4(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    seen: set[tuple[int, int, int, EntityType]] = set()
    for page in document.pages:
        page_candidates = _adjacent_field_candidates(page.lines) + _key_value_record_candidates(page.lines)
        for line in page.lines:
            line_candidates = _field_candidates(line) + _inline_field_candidates(line) + _prose_candidates(line)
            if "|" in line.text:
                for match in _CASE_TOKEN.finditer(line.text):
                    token = match.group("value")
                    # Unlabelled record IDs are kept pending unless the token itself
                    # contains a case/ref cue. This improves long-line records without
                    # turning every hyphenated model/version string into a hard mask.
                    if token.count("-") >= 2:
                        line_candidates.append(_Candidate(EntityType.CASE_REFERENCE, line, *match.span("value"), token, 0.80, "broad-pii-v4:record-id", ReviewStatus.PENDING))
            page_candidates.extend(line_candidates)
        for candidate in page_candidates:
                key = (candidate.line.page_index, candidate.line.page_char_start + candidate.start, candidate.line.page_char_start + candidate.end, candidate.entity_type)
                if key in seen:
                    continue
                seen.add(key)
                mention = _mention(candidate)
                if mention is not None:
                    detections.append(mention)
    return detections
