from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.enums import EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument


_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "semantic_ner_v1.json"

_CAP = r"[A-Z][A-Za-z'’\-]*"
_NAME_PHRASE = rf"{_CAP}(?:\s+{_CAP}){{1,3}}"
_ORG_WORD = r"(?:[A-Z][A-Za-z0-9&.'’\-]*|of|and|the|for)"
_ORG_PHRASE = rf"[A-Z][A-Za-z0-9&.'’\-]*(?:\s+{_ORG_WORD}){{1,8}}"
_ROLE_PHRASE = rf"{_CAP}(?:\s+{_CAP}){{0,4}}"
_ADDRESS_PHRASE = r"\d{1,5}[A-Za-z]?(?:\s+[A-Z][A-Za-z0-9.'’\-]*){2,8}"

# Candidate generation is intentionally syntax-oriented and conservative. The
# learned local classifier below decides whether a candidate is accepted.
_PATTERNS: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    (
        EntityType.PERSON_NAME,
        re.compile(
            rf"^(?P<value>{_NAME_PHRASE})\s+(?:submitted|requested|reviewed|completed|attended|reported|filed|signed|presented|joined|visited|called|emailed)\b"
        ),
    ),
    (
        EntityType.PERSON_NAME,
        re.compile(
            rf"\b(?i:thanked|met|contacted|called|emailed|interviewed|reviewed\s+by|signed\s+by|prepared\s+by|submitted\s+by)\s+(?P<value>{_NAME_PHRASE})(?=\s+(?i:for|after|before|during|regarding|who|and|to|at|in)\b|[.,;]|$)",
        ),
    ),
    (
        EntityType.STREET_ADDRESS,
        re.compile(
            rf"\b(?i:delivered|sent|mailed|couriered|posted|addressed)\s+(?i:to)\s+(?P<value>{_ADDRESS_PHRASE})(?=\s+(?i:before|after|on|by|where|which)\b|[.,;]|$)",
        ),
    ),
    (
        EntityType.EMPLOYER,
        re.compile(
            rf"\b(?i:works?|worked|employed)\s+(?i:at|by|with)\s+(?P<value>{_ORG_PHRASE})(?=\s+(?i:as)\b|[.,;]|$)",
        ),
    ),
    (
        EntityType.JOB_TITLE,
        re.compile(
            rf"\b(?i:as)\s+(?:(?i:an?)\s+)?(?P<value>{_ROLE_PHRASE})(?=[.,;]|$)",
        ),
    ),
)

_ROLE_TERMS = {
    "analyst", "engineer", "manager", "officer", "architect", "developer", "scientist",
    "consultant", "professor", "teacher", "director", "specialist", "researcher", "auditor",
    "administrator", "technician", "designer", "coordinator", "executive", "associate",
}
_ORG_TERMS = {
    "institute", "university", "college", "hospital", "bank", "company", "corporation",
    "technologies", "technology", "systems", "labs", "laboratories", "foundation", "agency",
    "department", "authority", "services", "solutions", "limited", "ltd", "pvt",
}
_ADDRESS_TERMS = {
    "road", "rd", "street", "st", "avenue", "ave", "lane", "ln", "layout", "cross",
    "main", "nagar", "colony", "circle", "drive", "boulevard", "block", "residency",
}
_GENERIC_NAME_BLOCKLIST = {
    "public release", "security analyst", "data analyst", "software engineer", "project manager",
    "example institute", "example avenue", "identity exposure", "privacy graph",
}


@dataclass(frozen=True)
class SemanticCandidate:
    entity_type: EntityType
    line: PositionedLine
    value: str
    start: int
    end: int
    pattern_id: int


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


def _words(value: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z'’\-]*|\d+[A-Za-z]?", value)


def semantic_features(candidate: SemanticCandidate) -> dict[str, float]:
    line_text = candidate.line.text
    value = candidate.value
    words = _words(value)
    lowered_words = [word.casefold().strip(".'’-") for word in words]
    before = line_text[max(0, candidate.start - 40):candidate.start].casefold()
    after = line_text[candidate.end:candidate.end + 40].casefold()
    title_count = sum(1 for word in words if word[:1].isupper())
    alpha_words = [word for word in words if any(ch.isalpha() for ch in word)]
    return {
        "bias": 1.0,
        "title_ratio": title_count / max(1, len(alpha_words)),
        "token_count": min(1.0, len(words) / 5.0),
        "sentence_start": 1.0 if line_text[:candidate.start].strip() == "" else 0.0,
        "starts_digit": 1.0 if value[:1].isdigit() else 0.0,
        "address_term": 1.0 if set(lowered_words) & _ADDRESS_TERMS else 0.0,
        "org_term": 1.0 if set(lowered_words) & _ORG_TERMS else 0.0,
        "role_term": 1.0 if set(lowered_words) & _ROLE_TERMS else 0.0,
        "before_action": 1.0 if re.search(r"(?:thanked|met|contacted|called|emailed|interviewed|by|to)\s*$", before) else 0.0,
        "after_action": 1.0 if re.match(r"\s*(?:submitted|requested|reviewed|completed|attended|reported|filed|signed|presented|joined|visited)\b", after) else 0.0,
        "works_context": 1.0 if re.search(r"(?:works?|worked|employed)\s+(?:at|by|with)\s*$", before) else 0.0,
        "as_context": 1.0 if re.search(r"\bas\s+(?:an?\s+)?$", before) else 0.0,
        "delivery_context": 1.0 if re.search(r"(?:delivered|sent|mailed|couriered|posted|addressed)\s+to\s*$", before) else 0.0,
        "generic_block": 1.0 if candidate.entity_type == EntityType.PERSON_NAME and value.casefold().strip(" .,") in _GENERIC_NAME_BLOCKLIST else 0.0,
    }


@lru_cache(maxsize=1)
def _model() -> dict:
    payload = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
    if payload.get("schema") != "veilgraph.semantic-ner.linear.v1":
        raise RuntimeError("Unsupported semantic NER model schema")
    return payload


def semantic_model_metadata() -> dict[str, object]:
    payload = _model()
    return {
        "schema": payload["schema"],
        "version": payload["version"],
        "training_source": payload["training_source"],
        "training_corpus_sha256": payload["training_corpus_sha256"],
        "runtime_network_required": False,
    }


def _probability(entity_type: EntityType, features: dict[str, float]) -> float:
    payload = _model()
    spec = payload["classifiers"][entity_type.value]
    score = float(spec.get("intercept", 0.0))
    for name, weight in spec.get("weights", {}).items():
        score += float(weight) * features.get(name, 0.0)
    score = max(-30.0, min(30.0, score))
    return 1.0 / (1.0 + math.exp(-score))


def _threshold(entity_type: EntityType) -> float:
    return float(_model()["classifiers"][entity_type.value].get("threshold", 0.70))


def generate_semantic_candidates(document: ProcessedDocument) -> list[SemanticCandidate]:
    candidates: list[SemanticCandidate] = []
    seen: set[tuple[int, int, int, EntityType]] = set()
    for page in document.pages:
        for line in page.lines:
            for pattern_id, (entity_type, pattern) in enumerate(_PATTERNS):
                for match in pattern.finditer(line.text):
                    start, end = match.span("value")
                    value = match.group("value").strip().strip(",;:")
                    if not value:
                        continue
                    # Keep spans exact after harmless edge punctuation cleanup.
                    raw = match.group("value")
                    left_trim = len(raw) - len(raw.lstrip())
                    right_trim = len(raw) - len(raw.rstrip(" ,;:"))
                    start += left_trim
                    end -= right_trim
                    value = line.text[start:end]
                    key = (page.page_index, line.page_char_start + start, line.page_char_start + end, entity_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(SemanticCandidate(entity_type, line, value, start, end, pattern_id))
    return candidates


def _mention(candidate: SemanticCandidate, probability: float) -> DetectedMention | None:
    rect = _rect_for_span(candidate.line, candidate.start, candidate.end)
    if rect is None:
        return None
    if candidate.entity_type == EntityType.PERSON_NAME:
        sensitivity = SensitivityLevel.HIGH
        transformation = TransformationType.PSEUDONYMIZE
        review = ReviewStatus.PENDING
    elif candidate.entity_type == EntityType.STREET_ADDRESS:
        sensitivity = SensitivityLevel.HIGH
        transformation = TransformationType.GENERALIZE
        review = ReviewStatus.NOT_REQUIRED if probability >= 0.90 else ReviewStatus.PENDING
    elif candidate.entity_type == EntityType.EMPLOYER:
        sensitivity = SensitivityLevel.MEDIUM
        transformation = TransformationType.PSEUDONYMIZE
        review = ReviewStatus.NOT_REQUIRED if probability >= 0.90 else ReviewStatus.PENDING
    else:
        sensitivity = SensitivityLevel.MEDIUM
        transformation = TransformationType.GENERALIZE
        review = ReviewStatus.NOT_REQUIRED if probability >= 0.90 else ReviewStatus.PENDING
    return DetectedMention(
        entity_type=candidate.entity_type,
        plaintext=candidate.value,
        page_index=candidate.line.page_index,
        page_char_start=candidate.line.page_char_start + candidate.start,
        page_char_end=candidate.line.page_char_start + candidate.end,
        rect=rect,
        confidence=round(max(0.55, min(0.99, probability)), 4),
        source=candidate.line.source,
        sensitivity=sensitivity,
        transformation=transformation,
        review_status=review,
        context_label=f"semantic-ner:{candidate.entity_type.value.casefold()}",
    )


def detect_semantic_entities(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    for candidate in generate_semantic_candidates(document):
        features = semantic_features(candidate)
        probability = _probability(candidate.entity_type, features)
        if probability < _threshold(candidate.entity_type):
            continue
        mention = _mention(candidate, probability)
        if mention is not None:
            detections.append(mention)
    return detections
