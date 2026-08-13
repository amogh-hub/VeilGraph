from __future__ import annotations

"""Broad PII v5 deterministic generalization coverage.

High-confidence, label/context anchored coverage for identifiers that commonly
appear in unseen prose and forms.  This layer supplements the local ML semantic
NER; release authorization remains deterministic in the existing Red Team.
"""

import re
from dataclasses import dataclass

from app.core.enums import DetectionSource, EntityType, FileType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


@dataclass(frozen=True)
class _Candidate:
    entity_type: EntityType
    line: PositionedLine
    start: int
    end: int
    value: str
    confidence: float
    context: str
    review: ReviewStatus = ReviewStatus.NOT_REQUIRED


_DATE = r"(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{2,4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:,)?\s+\d{2,4})"
_TOKEN_ID = r"(?=[A-Z0-9._/\- ]{4,40})(?=[A-Z0-9._/\- ]*\d)[A-Z0-9]{1,16}(?:(?:[-/_ ][A-Z0-9]{1,16})|(?:\.[A-Z0-9]{2,16})){0,4}"
_POSTAL = r"(?:\d{5}(?:-\d{4})?|\d{6}|[A-Z]\d[A-Z][ -]?\d[A-Z]\d|[A-Z]{1,2}\d[A-Z\d]?[ ]?\d[A-Z]{2})"
_CARD = r"(?:\d[ -]?){12,18}\d"

_PERSON_LABEL_RE = re.compile(
    r"(?i:\b(?:full\s+name|person\s+name|customer\s+name|client\s+name|employee\s+name|applicant\s+name|claimant\s+name|patient\s+name|member\s+name|policyholder\s+name|account\s+holder|holder\s+name|owner\s+name|beneficiary\s+name|contact\s+name|first\s+name|given\s+name|surname|last\s+name|family\s+name|name)\s*[:=#-]\s*)"
    r"(?P<value>[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}){0,4})"
)

_PERSON_SELF_INTRO_RE = re.compile(
    r"\b(?:my\s+name\s+is|i\s+am|i['’]m|this\s+is)\s+(?P<value>[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}){1,3}?)(?=[,;:.]|\s+(?:and\s+i|from|at|with|calling|writing|regarding)\b|$)",
    re.IGNORECASE,
)
_PERSON_SIGNOFF_RE = re.compile(
    r"(?i:(?:^|[.!?]\s+)(?:regards|best(?:\s+regards)?|sincerely|thanks),?\s+)(?P<value>[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}(?:\s+[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}){1,3})(?=[,;:.]|$)"
)

_LABEL_SPECS: tuple[tuple[EntityType, str, re.Pattern[str], float], ...] = (
    (EntityType.DATE_OF_BIRTH, "dob", re.compile(rf"(?i:\b(?:date\s+of\s+birth|dob|birth\s+date|born\s+on|date\s+de\s+naissance|fecha\s+de\s+nacimiento)\s*[:=#-]?\s*)(?P<value>{_DATE})"), 0.995),
    (EntityType.PASSPORT_NUMBER, "passport", re.compile(rf"(?i:\b(?:passport|passaporte|passaporto|pasaporte)(?:\s+(?:number|no\.?|id|num(?:ber)?|n[uú]mero))?\s*[:=#-]?\s*)(?P<value>{_TOKEN_ID})"), 0.99),
    (EntityType.DRIVER_LICENSE_NUMBER, "driver-license", re.compile(rf"(?i:\b(?:driver(?:'s)?\s+licen[cs]e|driving\s+licen[cs]e|driving\s+licence|licence\s+number|license\s+number|permis\s+de\s+conduire)(?:\s+(?:number|no\.?|id|num(?:ber)?))?\s*[:=#-]?\s*)(?P<value>{_TOKEN_ID})"), 0.99),
    (EntityType.TAX_IDENTIFIER, "tax-id", re.compile(rf"(?i:\b(?:tax(?:payer)?\s+(?:identifier|identification|id|number)|tax\s+file\s+number|tfn|tin|utr|pan(?:\s+(?:number|no\.?))?|codice\s+fiscale|fiscal\s+code)\s*[:=#-]?\s*)(?P<value>{_TOKEN_ID})"), 0.985),
    (EntityType.SOCIAL_IDENTIFIER, "social-id", re.compile(rf"(?i:\b(?:social\s+security(?:\s+(?:number|no\.?|id))?|ssn|social\s+insurance(?:\s+(?:number|no\.?))?|national\s+insurance(?:\s+(?:number|no\.?))?|nino|nhs\s+number)\s*[:=#-]?\s*)(?P<value>{_TOKEN_ID})"), 0.99),
    (EntityType.NATIONAL_ID, "national-id", re.compile(rf"(?i:\b(?:national\s+(?:id|identity|identification)(?:\s+(?:number|no\.?))?|identity\s+(?:number|no\.?|id)|citizen\s+(?:id|number)|personal\s+(?:id|number)|unique\s+id|id\s+card(?:\s+(?:number|no\.?))?|aadhaar(?:\s+(?:number|no\.?))?|aadhar(?:\s+(?:number|no\.?))?|dni|bsn|personalausweis(?:\s+id)?)\s*[:=#-]?\s*)(?P<value>{_TOKEN_ID})"), 0.985),
    (EntityType.CASE_REFERENCE, "account-ref", re.compile(rf"(?i:\b(?:(?:account|acct|policy|insurance|contract|claim|case|application|(?<!tax\s)file|customer|client|member)\s+(?:reference|ref\.?|number|no\.?|id)\s*[:=#-]?|(?:account|acct|policy|insurance|contract|case)\s*[:=#])\s*[`*_]{{0,2}})(?P<value>{_TOKEN_ID})"), 0.98),
    (EntityType.POSTCODE, "postal", re.compile(rf"(?i:\b(?:postal\s+code|post\s+code|postcode|zip(?:\s+code)?|pin(?:\s+code)?)\s*[:=#-]?\s*)(?P<value>{_POSTAL})\b"), 0.99),
    (EntityType.PAYMENT_CARD_NUMBER, "payment-card", re.compile(rf"(?i:\b(?:credit|debit|payment|bank)\s+card(?:\s+(?:number|no\.?))?\s*[:=#-]?\s*)(?P<value>{_CARD})"), 0.995),
)

# Strong labels for generic fields in table-like prose. The value is deliberately
# bounded; a label should not consume the rest of a sentence/document.
_GENERIC_FIELD = re.compile(
    rf"(?i:\b(?P<label>passport|driver(?:'s)?\s+licen[cs]e|national\s+id|identity\s+number|id\s+card|aadhaar|aadhar|tax\s+id|tax\s+file\s+number|tfn|tin|utr|ssn|nino|nhs\s+number|(?:account|acct)(?:\s+(?:ref|reference|number))?|policy(?:\s+(?:ref|reference|number))?|insurance(?:\s+(?:ref|reference|number))?|contract(?:\s+(?:ref|reference|number))?|case(?:\s+(?:ref|reference|number))?)\s*[:=#]\s*)(?P<value>{_TOKEN_ID})"
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


def _rect(line: PositionedLine, start: int, end: int) -> tuple[float, float, float, float] | None:
    tokens = [token for a, b, token in _token_spans(line.tokens) if a < end and b > start]
    if not tokens:
        return None
    return min(t.x0 for t in tokens), min(t.y0 for t in tokens), max(t.x1 for t in tokens), max(t.y1 for t in tokens)


def _clean_identifier(value: str) -> str:
    return value.strip(" \t,;:.()[]{}")


def _candidate_from_match(line: PositionedLine, entity_type: EntityType, match: re.Match[str], confidence: float, context: str) -> _Candidate | None:
    value = _clean_identifier(match.group("value"))
    raw = match.group("value")
    start = match.start("value") + (len(raw) - len(raw.lstrip()))
    if not value:
        return None
    end = start + len(value)
    # Identifier values must contain enough non-space signal. For card numbers,
    # numeric length is validated separately by the pattern.
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4:
        return None
    return _Candidate(entity_type, line, start, end, value, confidence, f"broad-pii-v5:{context}")


def _sensitivity(entity_type: EntityType) -> tuple[SensitivityLevel, TransformationType]:
    if entity_type == EntityType.DATE_OF_BIRTH:
        return SensitivityLevel.HIGH, TransformationType.GENERALIZE
    if entity_type == EntityType.POSTCODE:
        return SensitivityLevel.MEDIUM, TransformationType.GENERALIZE
    if entity_type == EntityType.CASE_REFERENCE:
        return SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE
    if entity_type == EntityType.PAYMENT_CARD_NUMBER:
        return SensitivityLevel.HIGH, TransformationType.MASK
    return SensitivityLevel.HIGH, TransformationType.MASK


def _mention(candidate: _Candidate) -> DetectedMention | None:
    rect = _rect(candidate.line, candidate.start, candidate.end)
    if rect is None:
        return None
    sensitivity, transformation = _sensitivity(candidate.entity_type)
    return DetectedMention(
        entity_type=candidate.entity_type,
        plaintext=candidate.value,
        page_index=candidate.line.page_index,
        page_char_start=candidate.line.page_char_start + candidate.start,
        page_char_end=candidate.line.page_char_start + candidate.end,
        rect=rect,
        confidence=candidate.confidence,
        source=candidate.line.source,
        sensitivity=sensitivity,
        transformation=transformation,
        review_status=candidate.review,
        context_label=candidate.context,
    )


def detect_generalization_v5(document: ProcessedDocument) -> list[DetectedMention]:
    # Earlier adapters already provide authoritative schema/frame context for these
    # formats. v5 focuses on unseen narrative text, PDF text layers and OCR images.
    if document.file_type in {FileType.DATASET, FileType.DOCX, FileType.VIDEO}:
        return []
    result: list[DetectedMention] = []
    seen: set[tuple[int, int, int, EntityType]] = set()
    for page in document.pages:
        for line in page.lines:
            candidates: list[_Candidate] = []
            for match in _PERSON_LABEL_RE.finditer(line.text):
                raw = match.group("value")
                value = raw.strip(" \t,;:.()[]{}")
                if value and value.casefold() not in {"unknown", "none", "n/a", "not available"}:
                    start = match.start("value") + (len(raw) - len(raw.lstrip()))
                    candidates.append(_Candidate(
                        EntityType.PERSON_NAME, line, start, start + len(value), value, 0.99,
                        "broad-pii-v5:person-field", ReviewStatus.PENDING,
                    ))
            for person_pattern, context in ((_PERSON_SELF_INTRO_RE, "self-intro"), (_PERSON_SIGNOFF_RE, "signoff")):
                for match in person_pattern.finditer(line.text):
                    raw = match.group("value")
                    value = raw.strip(" \t,;:.()[]{}")
                    if value:
                        start = match.start("value") + (len(raw) - len(raw.lstrip()))
                        candidates.append(_Candidate(
                            EntityType.PERSON_NAME, line, start, start + len(value), value, 0.975,
                            f"broad-pii-v5:{context}", ReviewStatus.PENDING,
                        ))
            for entity_type, label, pattern, confidence in _LABEL_SPECS:
                for match in pattern.finditer(line.text):
                    candidate = _candidate_from_match(line, entity_type, match, confidence, label)
                    if candidate:
                        candidates.append(candidate)
            for match in _GENERIC_FIELD.finditer(line.text):
                label = match.group("label").casefold()
                entity_type = (
                    EntityType.PASSPORT_NUMBER if "passport" in label else
                    EntityType.DRIVER_LICENSE_NUMBER if "licen" in label else
                    EntityType.TAX_IDENTIFIER if ("tax" in label or label in {"tfn", "tin", "utr"}) else
                    EntityType.SOCIAL_IDENTIFIER if label in {"ssn", "nino", "nhs number"} else
                    EntityType.NATIONAL_ID if any(term in label for term in ("national", "identity", "id card", "aadhaar", "aadhar")) else
                    EntityType.CASE_REFERENCE
                )
                candidate = _candidate_from_match(line, entity_type, match, 0.975, "generic-field")
                if candidate:
                    candidates.append(candidate)
            for candidate in candidates:
                key = (candidate.line.page_index, candidate.line.page_char_start + candidate.start, candidate.line.page_char_start + candidate.end, candidate.entity_type)
                if key in seen:
                    continue
                seen.add(key)
                mention = _mention(candidate)
                if mention is not None:
                    result.append(mention)
    return result
