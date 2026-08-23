from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


# Broad-coverage layer for common international PII classes. This complements
# (rather than replaces) VeilGraph's precise India-specific validators and local
# semantic NER. It is deliberately context-aware so that broad benchmark
# coverage does not turn into "mask every number" behaviour in production.

_TITLE_RE = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Mister|Dr|Doctor|Prof|Professor|Mx|Sir|Madam)\.?\b", re.IGNORECASE)
_MONTH = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
_DATE_PATTERNS = (
    re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?\b"),
    re.compile(r"\b\d{1,2}[./-]\d{1,2}[./-](?:19|20)?\d{2}\b"),
    re.compile(rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH}\s+(?:19|20)\d{{2}}\b", re.IGNORECASE),
    re.compile(rf"\b{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,)?\s+(?:19|20)\d{{2}}\b", re.IGNORECASE),
    re.compile(rf"\b{_MONTH}/\d{{2,4}}\b", re.IGNORECASE),
)

_AGE_RE = re.compile(r"(?<!\d)(?P<age>\d{1,3})(?=\s*(?:years?\s+old\b|years?\b|yrs?\b|y/o\b))", re.IGNORECASE)
_AGE_LABEL_RE = re.compile(r"\bage\s*:\s*[_\s-]*(?P<age>\d{1,3})\b", re.IGNORECASE)
_PHONE_CONTEXT_RE = re.compile(r"\b(?:phone|mobile|telephone|tel\.?|sms|contact)\b", re.IGNORECASE)
_PHONE_VALUE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d().\s-]{5,22}\d)(?!\w)")

_STREET_SUFFIX = r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Lane|Ln\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Way|Court|Ct\.?|Terrace|Place|Pl\.?|Highway|Hwy\.?|Circle|Crescent|Parkway|Pkwy\.?)"
_STREET_RE = re.compile(
    rf"(?<!\w)(?P<building>\d{{1,6}}[A-Za-z]?)\s+(?P<street>[A-Z][^,;\n]{{1,60}}?\s+{_STREET_SUFFIX})(?=\s*[,;.]|\s+[A-Z]|$)",
    re.IGNORECASE,
)
_STREET_ONLY_RE = re.compile(
    rf"\b(?P<street>[A-Z][A-Za-z'’\-]*(?:\s+(?:de|la|le|du|of|the|[A-Z][A-Za-z'’\-]*)){{0,5}}\s+{_STREET_SUFFIX})\b",
    re.IGNORECASE,
)
_US_ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
_POSTAL_LABEL_RE = re.compile(r"\b(?:zip(?:\s*code)?|postal\s*code|postcode|pin\s*code|pincode)\b", re.IGNORECASE)

_GREETING_RE = re.compile(r"\b(?:Dear|Hello|Hi)\s+(?P<value>[^,;:]{2,90})(?=[,;:]|$)", re.IGNORECASE)
_NAME_LABEL_RE = re.compile(r"\b(?:full\s+name|name)\s*:\s*[_\s-]*(?P<value>[^,;]{2,90})", re.IGNORECASE)
_NAME_START_RE = re.compile(r"^(?P<value>[^,]{2,80}),\s+(?:the|a|an|our|your|who)\b", re.IGNORECASE)
_NAME_END_RE = re.compile(r",\s*(?P<value>[^,.;:]{2,80})[.!]?$")
_WORD_RE = re.compile(r"[^\W\d_][^\W\d_.'’\-]*", re.UNICODE)

_DEMOGRAPHIC_LABEL_RE = re.compile(r"\b(?:sex|gender(?:\s+identity)?|biological\s+sex)\b", re.IGNORECASE)
_DEMOGRAPHIC_VALUES = {
    "male", "female", "m", "f", "nonbinary", "non-binary", "genderqueer", "bigender",
    "agender", "two-spirit", "transgender", "intersex", "other", "prefer not to say",
}

_ID_CONTEXTS: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    (EntityType.PASSPORT_NUMBER, re.compile(r"\bpassport(?:\s*(?:number|no\.?))?\b", re.IGNORECASE)),
    (EntityType.DRIVER_LICENSE_NUMBER, re.compile(r"\b(?:driver'?s?\s+licen[cs]e|driving\s+licen[cs]e)(?:\s*(?:number|no\.?))?\b", re.IGNORECASE)),
    (EntityType.NATIONAL_ID, re.compile(r"\b(?:national\s+id(?:\s+card)?|government\s+id|identity\s+card)(?:\s*(?:number|no\.?))?\b", re.IGNORECASE)),
    (EntityType.TAX_IDENTIFIER, re.compile(r"\b(?:tax\s+(?:identification|identifier)(?:\s+number)?|tax\s+id|TIN)\b", re.IGNORECASE)),
    (EntityType.SOCIAL_IDENTIFIER, re.compile(r"\b(?:social\s+security(?:\s+number)?|SSN|social\s+number)\b", re.IGNORECASE)),
)
_CARD_CONTEXT_RE = re.compile(r"\b(?:credit|debit|payment)\s+card\b", re.IGNORECASE)
_LONG_DIGITS_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){11,18}(?!\d)")
_ALNUM_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9-]{5,24}(?![A-Za-z0-9-]))(?=[A-Za-z0-9-]*\d)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?![A-Za-z0-9-])")
_GROUPED_NUMERIC_ID_RE = re.compile(r"(?<!\d)\d{3,10}(?:[ -]\d{2,10}){1,3}(?!\d)")

_LOCALITY_PATTERNS = (
    re.compile(r"\b(?:based|located|resident|resides?|living)\s+in\s+(?P<value>[A-Z][\w'’\-]{1,}(?:\s+[A-Z][\w'’\-]{1,}){0,2})\b", re.UNICODE),
    re.compile(r"\b(?:audiences?|participants?|employees?|customers?)\s+in\s+(?P<value>[A-Z][\w'’\-]{1,}(?:\s+[A-Z][\w'’\-]{1,}){0,2})\b", re.UNICODE),
    re.compile(r"\b(?:city|locality|town)\s*:\s*[_\s-]*(?P<value>[A-Z][\w'’\-]{1,}(?:\s+[A-Z][\w'’\-]{1,}){0,2})\b", re.IGNORECASE | re.UNICODE),
)


@dataclass(frozen=True)
class _Span:
    entity_type: EntityType
    line: PositionedLine
    start: int
    end: int
    value: str
    confidence: float
    sensitivity: SensitivityLevel
    transformation: TransformationType
    review: ReviewStatus = ReviewStatus.NOT_REQUIRED
    context: str | None = None


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
    tokens = [token for token_start, token_end, token in _token_spans(line.tokens) if token_start < end and token_end > start]
    if not tokens:
        return None
    return (
        min(token.x0 for token in tokens), min(token.y0 for token in tokens),
        max(token.x1 for token in tokens), max(token.y1 for token in tokens),
    )


def _mention(span: _Span) -> DetectedMention | None:
    rect = _rect(span.line, span.start, span.end)
    if rect is None:
        return None
    confidence = span.confidence
    if span.line.source == DetectionSource.TEXT_LAYER:
        confidence = max(confidence, 0.94)
    return DetectedMention(
        entity_type=span.entity_type,
        plaintext=span.value,
        page_index=span.line.page_index,
        page_char_start=span.line.page_char_start + span.start,
        page_char_end=span.line.page_char_start + span.end,
        rect=rect,
        confidence=max(0.55, min(0.99, confidence)),
        source=span.line.source,
        sensitivity=span.sensitivity,
        transformation=span.transformation,
        review_status=span.review,
        context_label=span.context,
    )


def _name_words(value: str) -> list[tuple[int, int, str]]:
    result = []
    for match in _WORD_RE.finditer(value):
        word = match.group(0)
        if word.casefold().rstrip(".") in {"mr", "mrs", "ms", "miss", "mister", "dr", "doctor", "prof", "professor", "mx", "sir", "madam"}:
            continue
        if word[:1].isupper():
            result.append((match.start(), match.end(), word))
    return result


def _name_span_from_fragment(line: PositionedLine, fragment_start: int, fragment_end: int) -> _Span | None:
    fragment = line.text[fragment_start:fragment_end]
    words = _name_words(fragment)
    if not words:
        return None
    # Keep up to four consecutive capitalised tokens. A single token is allowed
    # only in strong greeting/title contexts; callers provide such contexts.
    start = fragment_start + words[0][0]
    end = fragment_start + words[min(3, len(words) - 1)][1]
    value = line.text[start:end].strip()
    if not value or len(value) > 90:
        return None
    return _Span(
        EntityType.PERSON_NAME, line, start, end, value, 0.88,
        SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE,
        ReviewStatus.PENDING, "broad-pii:person-name",
    )


def _contextual_identifier_spans(line: PositionedLine) -> list[_Span]:
    spans: list[_Span] = []
    text = line.text
    for entity_type, context_re in _ID_CONTEXTS:
        for context in context_re.finditer(text):
            candidates: list[tuple[int, int, str]] = []
            for candidate in _GROUPED_NUMERIC_ID_RE.finditer(text):
                value = candidate.group(0)
                alnum = re.sub(r"[^A-Za-z0-9]", "", value)
                if 5 <= len(alnum) <= 24 and any(ch.isdigit() for ch in alnum):
                    candidates.append((candidate.start(), candidate.end(), value))
            for candidate in _ALNUM_TOKEN_RE.finditer(text):
                value = candidate.group(0)
                alnum = re.sub(r"[^A-Za-z0-9]", "", value)
                if 5 <= len(alnum) <= 24 and any(ch.isdigit() for ch in alnum):
                    candidates.append((candidate.start(), candidate.end(), value))
            # Prefer the first plausible identifier after this exact label. This
            # prevents a line with both government-ID and passport values from
            # assigning both values to both classes. A short look-behind handles
            # constructions such as "12345 (passport)" without scanning the line.
            after = [item for item in candidates if item[0] >= context.end() and item[0] - context.end() <= 100]
            before = [item for item in candidates if item[1] <= context.start() and context.start() - item[1] <= 36]
            chosen = min(after, key=lambda item: item[0]) if after else (max(before, key=lambda item: item[1]) if before else None)
            if chosen is None:
                continue
            c0, c1, value = chosen
            spans.append(_Span(
                entity_type, line, c0, c1, value, 0.96,
                SensitivityLevel.HIGH, TransformationType.MASK,
                ReviewStatus.NOT_REQUIRED, f"broad-pii:{entity_type.value.casefold()}",
            ))
    return spans


def _card_spans(line: PositionedLine) -> list[_Span]:
    if not _CARD_CONTEXT_RE.search(line.text):
        return []
    result = []
    for match in _LONG_DIGITS_RE.finditer(line.text):
        digits = re.sub(r"\D", "", match.group(0))
        if 12 <= len(digits) <= 19 and len(set(digits)) > 1:
            result.append(_Span(
                EntityType.PAYMENT_CARD_NUMBER, line, match.start(), match.end(), match.group(0), 0.97,
                SensitivityLevel.HIGH, TransformationType.MASK,
                ReviewStatus.NOT_REQUIRED, "broad-pii:payment-card-number",
            ))
    return result


def _address_spans(line: PositionedLine) -> list[_Span]:
    result: list[_Span] = []
    # Existing label/semantic detectors already cover these forms with a larger,
    # more useful address span. Avoid fragmenting them into overlapping building
    # and street detections, which would also create conflicting transforms.
    if re.search(r"^\s*(?:home\s+|residential\s+)?address\s*:", line.text, re.IGNORECASE):
        return result
    if re.search(r"\b(?:delivered|sent|mailed|couriered|posted|addressed)\s+to\b", line.text, re.IGNORECASE):
        return result
    address_context = bool(re.search(r"\b(?:residence|resident|lives?\s+at)\b", line.text, re.IGNORECASE))
    if address_context:
        street_matches = list(_STREET_RE.finditer(line.text))
    else:
        street_matches = []
    for match in street_matches:
        b0, b1 = match.span("building")
        s0, s1 = match.span("street")
        result.append(_Span(
            EntityType.BUILDING_NUMBER, line, b0, b1, match.group("building"), 0.94,
            SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
            ReviewStatus.NOT_REQUIRED, "broad-pii:building-number",
        ))
        result.append(_Span(
            EntityType.STREET_ADDRESS, line, s0, s1, match.group("street"), 0.94,
            SensitivityLevel.HIGH, TransformationType.GENERALIZE,
            ReviewStatus.NOT_REQUIRED, "broad-pii:street",
        ))
        # City after comma and before a ZIP/postcode.
        tail = line.text[s1:]
        city_match = re.match(r"\s*,\s*(?P<city>[A-Z][\w'’\-]{1,}(?:\s+[A-Z][\w'’\-]{1,}){0,2})(?=\s+\d{4,6}\b|\s*[,.;]|$)", tail, re.UNICODE)
        if city_match:
            c0, c1 = city_match.span("city")
            result.append(_Span(
                EntityType.LOCALITY, line, s1 + c0, s1 + c1, city_match.group("city"), 0.93,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:locality",
            ))
    if address_context and not any(item.entity_type == EntityType.STREET_ADDRESS for item in result):
        for match in _STREET_ONLY_RE.finditer(line.text):
            s0, s1 = match.span("street")
            result.append(_Span(
                EntityType.STREET_ADDRESS, line, s0, s1, match.group("street"), 0.88,
                SensitivityLevel.HIGH, TransformationType.GENERALIZE,
                ReviewStatus.PENDING, "broad-pii:street",
            ))
    # ZIP/postal numbers are accepted without a label only in an address line.
    if address_context or result or _POSTAL_LABEL_RE.search(line.text):
        for match in _US_ZIP_RE.finditer(line.text):
            result.append(_Span(
                EntityType.POSTCODE, line, match.start(), match.end(), match.group(0), 0.92,
                SensitivityLevel.HIGH, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:postcode",
            ))
    return result


def _demographic_spans(line: PositionedLine) -> list[_Span]:
    context = _DEMOGRAPHIC_LABEL_RE.search(line.text)
    lowered = line.text.casefold().strip()
    if not context:
        standalone = lowered.rstrip(".")
        if standalone in _DEMOGRAPHIC_VALUES and len(line.text.strip()) <= 24:
            start = len(line.text) - len(line.text.lstrip())
            end = start + len(line.text.strip().rstrip("."))
            return [_Span(
                EntityType.DEMOGRAPHIC_ATTRIBUTE, line, start, end, line.text[start:end], 0.82,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.PENDING, "broad-pii:demographic-standalone",
            )]
        return []
    lowered = line.text.casefold()
    result = []
    for value in sorted(_DEMOGRAPHIC_VALUES, key=len, reverse=True):
        for match in re.finditer(rf"(?<![\w-]){re.escape(value)}(?![\w-])", lowered):
            if match.start() < context.start():
                continue
            result.append(_Span(
                EntityType.DEMOGRAPHIC_ATTRIBUTE, line, match.start(), match.end(), line.text[match.start():match.end()], 0.94,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:demographic",
            ))
            return result
    return result


def _name_spans(line: PositionedLine) -> list[_Span]:
    result: list[_Span] = []
    text = line.text
    greeting = _GREETING_RE.search(text)
    if greeting:
        span = _name_span_from_fragment(line, *greeting.span("value"))
        if span:
            result.append(span)
    for title in _TITLE_RE.finditer(text):
        after_start = title.end()
        tail = text[after_start:]
        # Stop at first verb/comma boundary and collect capitalised name words.
        boundary = re.search(r"[,;:]|\b(?:prefers|works|submitted|requested|reviewed|completed|outlines|will|is|was|has|had)\b", tail, re.IGNORECASE)
        after_end = after_start + (boundary.start() if boundary else min(len(tail), 90))
        span = _name_span_from_fragment(line, after_start, after_end)
        if span:
            result.append(span)
    label = _NAME_LABEL_RE.search(text)
    if label:
        span = _name_span_from_fragment(line, *label.span("value"))
        if span:
            result.append(span)
    start = _NAME_START_RE.match(text)
    if start and not re.match(r"^\s*(?:Dear|Hello|Hi)\b", text, re.IGNORECASE):
        span = _name_span_from_fragment(line, *start.span("value"))
        if span:
            result.append(span)
    end = _NAME_END_RE.search(text)
    if end and re.search(r"\b(?:questionnaire|screening|form|profile|applicant|patient|participant|respondent)\b", text, re.IGNORECASE):
        span = _name_span_from_fragment(line, *end.span("value"))
        if span:
            result.append(span)
    return result


# ---------------------------------------------------------------------------
# Broad-Coverage PII Engine v3
# ---------------------------------------------------------------------------
# v3 is a precision-controlled expansion driven by the frozen PIIMB v2
# diagnostic profile. It concentrates on address decomposition, person-name
# context, international credential formats, payment-card validation and
# contextual age/demographic clues. The rules nominate spans only; VeilGraph's
# existing candidate fusion, review semantics, Identity Exposure Graph and
# fail-closed release verification remain authoritative.

_V3_STREET_SUFFIX = r"(?i:(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Lane|Ln\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Way|Court|Ct\.?|Terrace|Ter\.?|Place|Pl\.?|Highway|Hwy\.?|Circle|Cir\.?|Crescent|Parkway|Pkwy\.?|Square|Sq\.?|Grove|Gardens?|Close|Route|Rue|Calle|Avenida|Rua|Via|Viale|Corso|Piazza|Chemin|Strasse|Straße|Weg|Allee|Platz))"
_V3_STREET_WORD = r"(?:[A-Z][A-Za-zÀ-ÖØ-öø-ÿ0-9'’.-]*|(?i:de|del|della|di|da|dos|das|du|des|la|le|el|los|las|van|von|der|den|the|of))"
_V3_COMPOUND_ADDRESS_RE = re.compile(
    rf"(?<!\w)(?P<building>\d{{1,6}}[A-Za-z]?(?:[-/]\d{{1,6}}[A-Za-z]?)?)\s+"
    rf"(?P<street>{_V3_STREET_WORD}(?:\s+{_V3_STREET_WORD}){{0,7}}\s+{_V3_STREET_SUFFIX})\b"
)
_V3_STREET_ONLY_RE = re.compile(
    rf"\b(?P<street>{_V3_STREET_WORD}(?:\s+{_V3_STREET_WORD}){{0,7}}\s+{_V3_STREET_SUFFIX})\b"
)
_V3_ADDRESS_LABEL_RE = re.compile(
    r"\b(?:address|residence|residential\s+address|mailing\s+address|postal\s+address|home\s+address|shipping\s+address|delivery\s+address)\b",
    re.IGNORECASE,
)
_V3_LOCATION_PREP_RE = re.compile(
    r"\b(?:based|located|living|resident|resides?|born|raised|staying|moved|moving|travell?ed|travel(?:s|ing)?|visiting|visit|arrived|departed)\s+(?:at|in|near|around|within|to|from)\s+",
    re.IGNORECASE,
)
_V3_CITY_LABEL_RE = re.compile(r"\b(?:city|town|municipality|locality|place\s+of\s+birth|birthplace)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)
_V3_CAP_PLACE_RE = re.compile(r"(?P<value>[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*(?:\s+(?:[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*|(?i:de|del|la|las|los|le|du|of|the)\b)){0,3})")
_V3_PLACE_STOP = {
    "the", "a", "an", "this", "that", "our", "your", "their", "my", "his", "her",
    "office", "company", "university", "college", "hospital", "school", "department", "team", "institute", "technology", "technologies", "corporation", "bank",
    "january", "february", "march", "april", "may", "june", "july", "august", "september",
    "october", "november", "december",
}

_V3_POSTAL_CONTEXT_RE = re.compile(r"\b(?:zip(?:\s*code)?|postal\s*code|postcode|pin(?:\s*code)?|pincode)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)
_V3_POSTAL_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])(?P<value>(?:[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}|[A-Z]\d[A-Z]\s*\d[A-Z]\d|\d{4,6}(?:-\d{3,4})?))(?![A-Za-z0-9])", re.IGNORECASE)

_V3_PERSON_WORD = r"[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*"
_V3_PERSON_PART = rf"(?:{_V3_PERSON_WORD}|(?i:de|del|della|di|da|dos|das|du|des|la|le|van|von|der|den|bin|binti)\b)"
_V3_PERSON_PHRASE = rf"{_V3_PERSON_WORD}(?:\s+{_V3_PERSON_PART}){{0,4}}"
_V3_NAME_CONTEXT_PATTERNS = (
    re.compile(rf"\b(?i:my\s+name\s+is|full\s+name\s+is|this\s+is|I\s+am\s+called|I'?m\s+called)\s+(?P<value>{_V3_PERSON_PHRASE})(?=[,.;:]|\s+(?i:and|who|from|at|with|living|working|calling|writing)\b|$)", re.UNICODE),
    re.compile(rf"\b(?i:applicant|patient|customer|client|employee|participant|respondent|recipient|sender|beneficiary|policyholder|cardholder|account\s+holder|student|teacher|author|owner|contact\s+person)\s*(?i:name)?\s*(?:(?i:is)|=|:|-)?\s*(?P<value>{_V3_PERSON_PHRASE})(?=[,.;:]|$)", re.UNICODE),
    re.compile(rf"\b(?i:prepared|signed|submitted|reviewed|approved|written|reported|filed|completed)\s+(?i:by)\s+(?P<value>{_V3_PERSON_PHRASE})(?=[,.;:]|\s+(?i:on|at|for|from|who|and)\b|$)", re.UNICODE),
    re.compile(rf"\b(?i:contact|call|email|message|reach|notify|ask\s+for|attn\.?|attention)\s+(?P<value>{_V3_PERSON_PHRASE})(?=\s+(?i:at|on|via|by)\b|[,.;:]|$)", re.UNICODE),
)
_V3_NAME_SENTENCE_START_RE = re.compile(
    rf"^\s*(?P<value>{_V3_PERSON_WORD}(?:\s+{_V3_PERSON_PART}){{1,3}})\s+"
    r"(?=(?:is|was|has|had|will|can|should|said|asked|works|worked|lives|resides|prefers)\b)",
    re.UNICODE,
)
_V3_NAME_BLOCK = {
    "public release", "smart city", "new york", "united states", "united kingdom", "data protection",
    "privacy policy", "artificial intelligence", "machine learning", "software engineering",
}

_V3_ID_CONTEXTS: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    (EntityType.PASSPORT_NUMBER, re.compile(r"\b(?:passport(?:\s*(?:number|no\.?|#|id))?|travel\s+document(?:\s*(?:number|no\.?|#))?)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)),
    (EntityType.DRIVER_LICENSE_NUMBER, re.compile(r"\b(?:driver'?s?\s+licen[cs]e|driving\s+licen[cs]e|driver\s+licen[cs]e|DLN|DL\s*(?:number|no\.?|#))\s*(?:number|no\.?|#|id)?\s*(?:is|=|:|-)?\s*", re.IGNORECASE)),
    (EntityType.NATIONAL_ID, re.compile(r"\b(?:national\s+id(?:\s+card)?|government\s+id|identity\s+card|identity\s+number|id\s+card|personal\s+id|citizen\s+id|identification\s+number)\s*(?:number|no\.?|#|id)?\s*(?:is|=|:|-)?\s*", re.IGNORECASE)),
    (EntityType.TAX_IDENTIFIER, re.compile(r"\b(?:tax\s+(?:identification|identifier)(?:\s+number)?|tax\s+id|TIN|VAT\s*(?:number|no\.?|#)?)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)),
    (EntityType.SOCIAL_IDENTIFIER, re.compile(r"\b(?:social\s+security(?:\s+number)?|SSN|social\s+number|social\s+insurance(?:\s+number)?|SIN)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)),
)
_V3_ID_VALUE_RE = re.compile(r"(?<![A-Za-z0-9])(?P<value>(?=[A-Za-z0-9 /-]{5,28}(?![A-Za-z0-9]))(?=[A-Za-z0-9 /-]*\d)(?:\d{2,10}(?:[ -]\d{2,10}){1,3}|[A-Za-z0-9]{2,12}(?:[-/][A-Za-z0-9]{2,12}){0,3}))(?![A-Za-z0-9])")
_V3_CARD_CONTEXT_RE = re.compile(r"\b(?:credit\s+card|debit\s+card|payment\s+card|card\s+(?:number|no\.?|#)|cc\s+(?:number|no\.?|#)|cardholder\s+number)\s*(?:is|=|:|-)?\s*", re.IGNORECASE)
_V3_CARD_NUMBER_RE = re.compile(r"(?<!\d)(?P<value>\d(?:[ -]?\d){12,18})(?!\d)")

_V3_AGE_PATTERNS = (
    re.compile(r"\b(?:aged|age\s+of|age\s+is|age\s*=|age\s*:|currently\s+aged)\s*(?P<age>\d{1,3})\b", re.IGNORECASE),
    re.compile(r"\b(?P<age>\d{1,3})\s*[- ]?years?[- ]?old\b", re.IGNORECASE),
    re.compile(r"\b(?P<age>\d{1,3})\s*[- ]?y/o\b", re.IGNORECASE),
    re.compile(r"\bI\s*(?:am|'m)\s+(?P<age>\d{1,3})(?=\s*(?:years?\s+old\b|years?\b|[,.]|$))", re.IGNORECASE),
    re.compile(r"\b(?:turned|turning)\s+(?P<age>\d{1,3})\b", re.IGNORECASE),
)
_V3_DEMO_CONTEXT_RE = re.compile(r"\b(?:I\s*(?:am|'m)|identif(?:y|ies)\s+as|sex\s*(?:is|=|:)|gender(?:\s+identity)?\s*(?:is|=|:)|biological\s+sex\s*(?:is|=|:))\s*", re.IGNORECASE)
_V3_DEMO_VALUES = {
    "male", "female", "man", "woman", "nonbinary", "non-binary", "genderqueer", "agender",
    "bigender", "transgender", "intersex", "two-spirit", "other",
}


def _v3_luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) <= 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _v3_clean_place(value: str) -> str | None:
    cleaned = value.strip(" \t,.;:-")
    if len(cleaned) < 2 or len(cleaned) > 70:
        return None
    words = [part.casefold().strip(".'’-\"") for part in cleaned.split()]
    if not words or words[0] in _V3_PLACE_STOP:
        return None
    if any(word in {"company", "university", "college", "hospital", "school", "department", "team", "institute", "technology", "technologies", "corporation", "bank"} for word in words):
        return None
    return cleaned


def _v3_address_spans(line: PositionedLine) -> list[_Span]:
    text = line.text
    # Do not fragment a line that the established v1/v2 address detector already
    # owns. This preserves transformation compatibility while v3 only fills true
    # coverage gaps on previously unrecognised address structures.
    if _address_spans(line):
        return []
    if re.search(r"^\s*(?:home\s+|residential\s+)?address\s*:", text, re.IGNORECASE):
        return []
    if re.search(r"\b(?:delivered|sent|mailed|couriered|posted|addressed)\s+to\b", text, re.IGNORECASE):
        return []
    result: list[_Span] = []
    compound = list(_V3_COMPOUND_ADDRESS_RE.finditer(text))
    for match in compound:
        b0, b1 = match.span("building")
        s0, s1 = match.span("street")
        result.extend((
            _Span(EntityType.BUILDING_NUMBER, line, b0, b1, match.group("building"), 0.95,
                  SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:building-number"),
            _Span(EntityType.STREET_ADDRESS, line, s0, s1, match.group("street"), 0.95,
                  SensitivityLevel.HIGH, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:street"),
        ))
        # A comma-separated title-cased locality directly after a recognised
        # street is strong structural evidence, even when no explicit address
        # label is present.
        tail = text[s1:]
        city = re.match(r"\s*,\s*(?P<city>[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*(?:\s+[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’.-]*){0,2}?)(?=\s+(?:[A-Z]{1,2}\d|\d{4,6})|\s*[,.;]|$)", tail)
        if city:
            value = _v3_clean_place(city.group("city"))
            if value:
                c0, c1 = city.span("city")
                result.append(_Span(EntityType.LOCALITY, line, s1 + c0, s1 + c1, value, 0.92,
                                    SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:locality-address"))

    # Street names with a recognisable suffix are useful even if the building
    # number was omitted (for example "Rochelle Street, Waldorf"). Keep them
    # pending review unless supported by an address label/preposition.
    strong_address_context = bool(_V3_ADDRESS_LABEL_RE.search(text) or re.search(r"\b(?:lives?\s+at|resides?\s+at|located\s+at|send\s+to|ship(?:ped)?\s+to|deliver(?:ed)?\s+to|mail(?:ed)?\s+to)\b", text, re.IGNORECASE))
    existing_streets = {(s.start, s.end) for s in result if s.entity_type == EntityType.STREET_ADDRESS}
    for match in _V3_STREET_ONLY_RE.finditer(text):
        s0, s1 = match.span("street")
        if any(s0 >= a and s1 <= b for a, b in existing_streets):
            continue
        result.append(_Span(EntityType.STREET_ADDRESS, line, s0, s1, match.group("street"), 0.91 if strong_address_context else 0.80,
                            SensitivityLevel.HIGH, TransformationType.GENERALIZE,
                            ReviewStatus.NOT_REQUIRED if strong_address_context else ReviewStatus.PENDING,
                            "broad-pii-v3:street-only"))

    # Labelled and structurally adjacent postal codes, including common UK/CA
    # alphanumeric forms. Unlabelled codes are only considered when a street or
    # locality signal already exists on the line.
    postal_context = _V3_POSTAL_CONTEXT_RE.search(text)
    if postal_context:
        for match in _V3_POSTAL_TOKEN_RE.finditer(text, postal_context.end()):
            result.append(_Span(EntityType.POSTCODE, line, *match.span("value"), match.group("value"), 0.96,
                                SensitivityLevel.HIGH, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:postcode-label"))
            break
    if result or strong_address_context:
        for match in _V3_POSTAL_TOKEN_RE.finditer(text):
            value = match.group("value")
            if any(span.start == match.start("value") and span.end == match.end("value") and span.entity_type == EntityType.POSTCODE for span in result):
                continue
            # Bare 4-6 digit sequences require adjacency to an address signal;
            # alphanumeric postal tokens are already distinctive.
            result.append(_Span(EntityType.POSTCODE, line, *match.span("value"), value, 0.88,
                                SensitivityLevel.HIGH, TransformationType.GENERALIZE, ReviewStatus.PENDING, "broad-pii-v3:postcode-structural"))

    # City/locality labels are strong evidence.
    for context in _V3_CITY_LABEL_RE.finditer(text):
        match = _V3_CAP_PLACE_RE.match(text, context.end())
        if match:
            value = _v3_clean_place(match.group("value"))
            if value:
                result.append(_Span(EntityType.LOCALITY, line, *match.span("value"), value, 0.94,
                                    SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:locality-label"))

    # Location-bearing verbs produce a lower-confidence candidate that must pass
    # human review unless another address cue supports it.
    for context in _V3_LOCATION_PREP_RE.finditer(text):
        match = _V3_CAP_PLACE_RE.match(text, context.end())
        if not match:
            continue
        value = _v3_clean_place(match.group("value"))
        if value:
            result.append(_Span(EntityType.LOCALITY, line, *match.span("value"), value, 0.84,
                                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.PENDING, "broad-pii-v3:locality-context"))
    return result


def _v3_name_spans(line: PositionedLine) -> list[_Span]:
    result: list[_Span] = []
    text = line.text
    for pattern in _V3_NAME_CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group("value")
            left_trim = len(raw) - len(raw.lstrip())
            cleaned = raw.strip().rstrip(".,;:")
            if not cleaned:
                continue
            start = match.start("value") + left_trim
            end = start + len(cleaned)
            value = text[start:end]
            if value.casefold() in _V3_NAME_BLOCK:
                continue
            result.append(_Span(EntityType.PERSON_NAME, line, start, end, value, 0.90,
                                SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE, ReviewStatus.PENDING, "broad-pii-v3:person-context"))
    start_match = _V3_NAME_SENTENCE_START_RE.search(text)
    if start_match:
        raw = start_match.group("value")
        cleaned = raw.strip().rstrip(".,;:")
        start = start_match.start("value") + (len(raw) - len(raw.lstrip()))
        end = start + len(cleaned)
        value = text[start:end]
        if value.casefold() not in _V3_NAME_BLOCK:
            result.append(_Span(EntityType.PERSON_NAME, line, start, end, value, 0.83,
                                SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE, ReviewStatus.PENDING, "broad-pii-v3:person-sentence-start"))
    return result


def _v3_identifier_spans(line: PositionedLine) -> list[_Span]:
    result: list[_Span] = []
    text = line.text
    for entity_type, context_re in _V3_ID_CONTEXTS:
        for context in context_re.finditer(text):
            if entity_type == EntityType.NATIONAL_ID and re.search(
                r"(?:tax|passport|driver|driving|social)\s+$", text[max(0, context.start() - 16):context.start()], re.IGNORECASE
            ):
                continue
            match = _V3_ID_VALUE_RE.match(text, context.end())
            if not match:
                continue
            value = match.group("value").strip(" .")
            end = match.start("value") + len(value)
            compact = re.sub(r"[^A-Za-z0-9]", "", value)
            if not (5 <= len(compact) <= 24 and any(ch.isdigit() for ch in compact)):
                continue
            result.append(_Span(entity_type, line, match.start("value"), end, value, 0.97,
                                SensitivityLevel.HIGH, TransformationType.MASK, ReviewStatus.NOT_REQUIRED,
                                f"broad-pii-v3:{entity_type.value.casefold()}"))

    card_context = _V3_CARD_CONTEXT_RE.search(text)
    if card_context and re.search(r"\b(?:national|government|identity|id)\s+(?:id\s+)?card\s+(?:number|no\.?|#)", text, re.IGNORECASE):
        card_context = None
    for match in _V3_CARD_NUMBER_RE.finditer(text):
        value = match.group("value")
        if card_context and match.start() >= card_context.end() and match.start() - card_context.end() <= 40:
            confidence, review = 0.98, ReviewStatus.NOT_REQUIRED
        elif _v3_luhn_valid(value) and not any(context_re.search(text) for _, context_re in _V3_ID_CONTEXTS):
            confidence, review = 0.97, ReviewStatus.NOT_REQUIRED
        else:
            continue
        result.append(_Span(EntityType.PAYMENT_CARD_NUMBER, line, *match.span("value"), value, confidence,
                            SensitivityLevel.HIGH, TransformationType.MASK, review, "broad-pii-v3:payment-card"))
    return result


def _v3_age_demographic_spans(line: PositionedLine) -> list[_Span]:
    result: list[_Span] = []
    text = line.text
    for pattern in _V3_AGE_PATTERNS:
        for match in pattern.finditer(text):
            age = int(match.group("age"))
            # Preserve the established v1/v2 span owner for labelled forms such
            # as "Age: 19 years", where the existing quasi detector intentionally
            # protects the complete value including the unit.
            tail = text[match.end("age"):]
            prefix = text[:match.start("age")]
            if re.search(r"\bage\s*(?:is|=|:)\s*$", prefix, re.IGNORECASE) and re.match(r"\s*(?:years?|yrs?|y/o)\b", tail, re.IGNORECASE):
                continue
            if 0 <= age <= 120:
                result.append(_Span(EntityType.AGE, line, *match.span("age"), match.group("age"), 0.94,
                                    SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:age"))
    for context in _V3_DEMO_CONTEXT_RE.finditer(text):
        tail = text[context.end():context.end() + 32]
        for value in sorted(_V3_DEMO_VALUES, key=len, reverse=True):
            match = re.match(rf"\s*(?P<value>{re.escape(value)})(?![\w-])", tail, re.IGNORECASE)
            if not match:
                continue
            start = context.end() + match.start("value")
            end = context.end() + match.end("value")
            result.append(_Span(EntityType.DEMOGRAPHIC_ATTRIBUTE, line, start, end, text[start:end], 0.93,
                                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED, "broad-pii-v3:demographic-context"))
            break
    return result


def _v3_spans(line: PositionedLine) -> list[_Span]:
    spans = (
        _v3_address_spans(line)
        + _v3_name_spans(line)
        + _v3_identifier_spans(line)
        + _v3_age_demographic_spans(line)
    )
    unique: dict[tuple[EntityType, int, int], _Span] = {}
    for span in spans:
        key = (span.entity_type, span.start, span.end)
        if key not in unique or span.confidence > unique[key].confidence:
            unique[key] = span
    return list(unique.values())

def _line_spans(line: PositionedLine) -> list[_Span]:
    spans: list[_Span] = []
    text = line.text

    for title in _TITLE_RE.finditer(text):
        spans.append(_Span(
            EntityType.PERSON_TITLE, line, title.start(), title.end(), title.group(0), 0.97,
            SensitivityLevel.LOW, TransformationType.GENERALIZE,
            ReviewStatus.NOT_REQUIRED, "broad-pii:person-title",
        ))

    for pattern in _DATE_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(_Span(
                EntityType.GENERIC_DATE, line, match.start(), match.end(), match.group(0), 0.95,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:date",
            ))

    age_label = _AGE_LABEL_RE.search(text)
    if age_label:
        a0, a1 = age_label.span("age")
        age_value = int(age_label.group("age"))
        tail = text[a1:]
        # Label-aware quasi detection already captures forms like "Age: 19 years"
        # as the full gold span. The broad fallback is for filler-heavy/numeric-only
        # forms such as "Age: ______ 73".
        if 0 <= age_value <= 120 and not re.match(r"\s*(?:years?|yrs?|y/o)\b", tail, re.IGNORECASE):
            spans.append(_Span(
                EntityType.AGE, line, a0, a1, age_label.group("age"), 0.97,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:age",
            ))

    for match in _AGE_RE.finditer(text):
        if re.search(r"^\s*age\s*:", text, re.IGNORECASE) or re.fullmatch(r"\s*\d{1,3}\s+(?:years?|yrs?)\s*", text, re.IGNORECASE):
            break
        age = int(match.group("age"))
        if 0 <= age <= 120:
            a0, a1 = match.span("age")
            spans.append(_Span(
                EntityType.AGE, line, a0, a1, match.group("age"), 0.91,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.NOT_REQUIRED, "broad-pii:age",
            ))

    if _PHONE_CONTEXT_RE.search(text):
        for match in _PHONE_VALUE_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 7 <= len(digits) <= 15 and len(set(digits)) > 1:
                spans.append(_Span(
                    EntityType.PHONE, line, match.start(), match.end(), match.group(0), 0.93,
                    SensitivityLevel.HIGH, TransformationType.MASK,
                    ReviewStatus.NOT_REQUIRED, "broad-pii:phone",
                ))

    spans.extend(_contextual_identifier_spans(line))
    spans.extend(_card_spans(line))
    spans.extend(_address_spans(line))
    spans.extend(_demographic_spans(line))
    spans.extend(_name_spans(line))
    spans.extend(_v3_spans(line))

    for pattern in _LOCALITY_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span("value")
            value = match.group("value").strip()
            if value.casefold() in {"n/a", "na", "none", "nil", "unknown"}:
                continue
            spans.append(_Span(
                EntityType.LOCALITY, line, start, end, value, 0.88,
                SensitivityLevel.MEDIUM, TransformationType.GENERALIZE,
                ReviewStatus.PENDING, "broad-pii:locality",
            ))

    # Deduplicate exact spans/types before the global fusion stage.
    unique: dict[tuple[EntityType, int, int], _Span] = {}
    for span in spans:
        key = (span.entity_type, span.start, span.end)
        if key not in unique or span.confidence > unique[key].confidence:
            unique[key] = span
    return list(unique.values())


def detect_broad_pii(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    for page in document.pages:
        for line in page.lines:
            for span in _line_spans(line):
                mention = _mention(span)
                if mention is not None:
                    detections.append(mention)
    return detections
