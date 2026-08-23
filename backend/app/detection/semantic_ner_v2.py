from __future__ import annotations

"""VeilGraph local semantic NER v2.

A bundled, runtime-offline logistic span classifier.  Candidate generation is
syntax/context based; the learned model decides whether a candidate is likely to
be a person, employer, locality, street address or job title.  No network or
third-party inference service is used.
"""

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.enums import EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument

_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "semantic_ner_v2.json"

_WORD = r"[^\W\d_][^\W\d_.'’\-]*"
_CAP = rf"(?:[A-Z][A-Za-zÀ-ÖØ-öø-ÿ'’\-]*|[A-Z]{{2,}})"
_NAME = rf"{_CAP}(?:\s+{_CAP}){{1,3}}"
_ORG = rf"{_CAP}(?:\s+(?:{_CAP}|of|and|the|for|&)){{1,8}}"
_PLACE = rf"{_CAP}(?:\s+{_CAP}){{0,2}}"
_ROLE = rf"{_CAP}(?:\s+{_CAP}){{0,4}}"
_ADDRESS = r"\d{1,6}[A-Za-z]?(?:\s+[A-Z][A-Za-z0-9.'’\-]*){2,9}"

_ROLE_TERMS = {
    "analyst", "engineer", "manager", "officer", "architect", "developer", "scientist",
    "consultant", "professor", "teacher", "director", "specialist", "researcher", "auditor",
    "administrator", "technician", "designer", "coordinator", "executive", "associate", "doctor",
}
_ORG_TERMS = {
    "institute", "university", "college", "hospital", "bank", "company", "corporation",
    "technologies", "technology", "systems", "labs", "laboratories", "foundation", "agency",
    "department", "authority", "services", "solutions", "limited", "ltd", "pvt", "research",
    "diagnostics", "works", "mobility", "analytics", "unit", "group", "centre", "center",
}
_ADDRESS_TERMS = {
    "road", "rd", "street", "st", "avenue", "ave", "lane", "ln", "layout", "cross",
    "main", "nagar", "colony", "circle", "drive", "boulevard", "block", "residency",
}
_GENERIC_BLOCK = {
    "public release", "identity exposure", "privacy graph", "machine learning", "artificial intelligence",
    "software engineering", "data protection", "security analyst", "project manager", "research partner",
    "end", "sample", "value", "field", "key",
}

_PATTERNS: tuple[tuple[EntityType, str, re.Pattern[str]], ...] = (
    (EntityType.PERSON_NAME, "sentence-person", re.compile(rf"^\s*(?P<value>{_NAME})\s+(?=(?i:is|was|has|had|will|can|said|asked|submitted|requested|reviewed|attended|reported|filed|works|lives|resides)\b)")),
    (EntityType.PERSON_NAME, "action-person", re.compile(rf"(?i:\b(?:met|called|emailed|contacted|reviewed\s+by|signed\s+by|prepared\s+by|submitted\s+by|with))\s+(?P<value>{_NAME})(?=\s+(?i:for|after|before|during|regarding|who|and|to|at|in)\b|[.,;|]|$)")),
    (EntityType.EMPLOYER, "employment-org", re.compile(rf"(?i:\b(?:works?|worked|employed|affiliated)\s+(?:at|by|with))\s+(?P<value>{_ORG}?)(?=\s+(?i:as|in|on|for)\b|[.,;|]|$)")),
    (EntityType.LOCALITY, "location-place", re.compile(rf"(?i:\b(?:in|from|near|at|located\s+in|based\s+in|resides?\s+in|city\s*[:=]|locality\s*[:=]|location\s*[:=]))\s*(?P<value>{_PLACE})(?=\s+(?i:for|to|after|before|during|under|and|who|where)\b|[.,;|)]|$)")),
    (EntityType.STREET_ADDRESS, "address", re.compile(rf"(?i:\b(?:delivered|sent|mailed|couriered|posted|addressed)\s+to)\s+(?P<value>{_ADDRESS})(?=\s+(?i:before|after|on|by|where|which)\b|[.,;|]|$)")),
    (EntityType.JOB_TITLE, "job-title", re.compile(rf"(?i:\bas\s+(?:an?\s+)?)(?P<value>{_ROLE})(?=[.,;|]|$)")),
)


@dataclass(frozen=True)
class SemanticCandidateV2:
    entity_type: EntityType
    line: PositionedLine
    value: str
    start: int
    end: int
    pattern: str


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


def semantic_v2_features(entity_type: EntityType, text: str, start: int, end: int, pattern: str) -> dict[str, float]:
    value = text[start:end]
    words = re.findall(r"[^\W\d_][^\W\d_.'’\-]*|\d+[A-Za-z]?", value, re.UNICODE)
    lower_words = [w.casefold().strip(".'’-\"") for w in words]
    before = text[max(0, start - 48):start].casefold()
    after = text[end:end + 48].casefold()
    alpha_words = [w for w in words if any(ch.isalpha() for ch in w)]
    title_like = sum(1 for w in alpha_words if w[:1].isupper() or (len(w) > 1 and w.isupper()))
    compact = value.strip(" \t|,;:—–-")
    return {
        "bias": 1.0,
        "title_ratio": title_like / max(1, len(alpha_words)),
        "token_count": min(1.0, len(words) / 6.0),
        "single_token": 1.0 if len(alpha_words) == 1 else 0.0,
        "all_caps": 1.0 if compact and compact.upper() == compact and any(ch.isalpha() for ch in compact) else 0.0,
        "starts_digit": 1.0 if compact[:1].isdigit() else 0.0,
        "org_term": 1.0 if set(lower_words) & _ORG_TERMS else 0.0,
        "role_term": 1.0 if set(lower_words) & _ROLE_TERMS else 0.0,
        "address_term": 1.0 if set(lower_words) & _ADDRESS_TERMS else 0.0,
        "person_context": 1.0 if re.search(r"(?:met|called|emailed|contacted|reviewed\s+by|signed\s+by|prepared\s+by|submitted\s+by|participant|subject|owner|reviewer|citizen)\s*[:=]?\s*$", before) else 0.0,
        "employment_context": 1.0 if re.search(r"(?:works?|worked|employed|affiliated)\s+(?:at|by|with)\s*$", before) else 0.0,
        "location_context": 1.0 if re.search(r"(?:\bin\b|\bfrom\b|\bnear\b|located\s+in\b|based\s+in\b|resides?\s+in\b|city\s*[:=]|locality\s*[:=]|location\s*[:=])\s*$", before) else 0.0,
        "role_context": 1.0 if re.search(r"\bas\s+(?:an?\s+)?$", before) else 0.0,
        "delivery_context": 1.0 if re.search(r"(?:delivered|sent|mailed|couriered|posted|addressed)\s+to\s*$", before) else 0.0,
        "sentence_start": 1.0 if text[:start].strip() == "" else 0.0,
        "next_person_verb": 1.0 if re.match(r"\s*(?:is|was|has|had|will|can|said|asked|submitted|requested|reviewed|attended|reported|filed|works|lives|resides)\b", after) else 0.0,
        "pipe_segment": 1.0 if "|" in text and (start == 0 or "|" in text[max(0, start-3):start+1]) else 0.0,
        "generic_block": 1.0 if compact.casefold() in _GENERIC_BLOCK else 0.0,
        "pattern_sentence_person": 1.0 if pattern == "sentence-person" else 0.0,
        "pattern_action_person": 1.0 if pattern == "action-person" else 0.0,
        "pattern_employment_org": 1.0 if pattern == "employment-org" else 0.0,
        "pattern_location_place": 1.0 if pattern == "location-place" else 0.0,
        "pattern_address": 1.0 if pattern == "address" else 0.0,
        "pattern_job_title": 1.0 if pattern == "job-title" else 0.0,
        "pattern_pipe": 1.0 if pattern == "pipe" else 0.0,
    }


@lru_cache(maxsize=1)
def _model() -> dict:
    payload = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
    if payload.get("schema") != "veilgraph.semantic-ner.linear.v2":
        raise RuntimeError("Unsupported semantic NER v2 model schema")
    return payload


def semantic_model_v2_metadata() -> dict[str, object]:
    payload = _model()
    return {
        "schema": payload["schema"],
        "version": payload["version"],
        "training_source": payload["training_source"],
        "training_corpus_sha256": payload["training_corpus_sha256"],
        "runtime_network_required": False,
        "model_family": payload["model_family"],
    }


def _probability(entity_type: EntityType, features: dict[str, float]) -> float:
    spec = _model()["classifiers"].get(entity_type.value)
    if not spec:
        return 0.0
    score = float(spec.get("intercept", 0.0))
    for name, weight in spec.get("weights", {}).items():
        score += float(weight) * features.get(name, 0.0)
    score = max(-30.0, min(30.0, score))
    return 1.0 / (1.0 + math.exp(-score))


def _threshold(entity_type: EntityType) -> float:
    return float(_model()["classifiers"][entity_type.value].get("threshold", 0.72))


def _add_candidate(result: list[SemanticCandidateV2], seen: set[tuple[int,int,int,EntityType]], line: PositionedLine, entity_type: EntityType, start: int, end: int, pattern: str) -> None:
    raw = line.text[start:end]
    left = len(raw) - len(raw.lstrip())
    cleaned = raw.strip().strip("|,;:—–")
    if not cleaned:
        return
    start += left
    end = start + len(cleaned)
    key = (line.page_index, line.page_char_start + start, line.page_char_start + end, entity_type)
    if key in seen:
        return
    seen.add(key)
    result.append(SemanticCandidateV2(entity_type, line, line.text[start:end], start, end, pattern))


def generate_semantic_candidates_v2(document: ProcessedDocument) -> list[SemanticCandidateV2]:
    result: list[SemanticCandidateV2] = []
    seen: set[tuple[int,int,int,EntityType]] = set()
    for page in document.pages:
        for line in page.lines:
            text = line.text
            for entity_type, pattern_id, pattern in _PATTERNS:
                for match in pattern.finditer(text):
                    _add_candidate(result, seen, line, entity_type, *match.span("value"), pattern_id)

            # Dense OCR/log rows often use pipe-delimited values with no repeated
            # labels.  Generate conservative semantic candidates for otherwise
            # plain segments; direct email/phone/ID validators still own their spans.
            if "|" in text:
                cursor = 0
                for segment in text.split("|"):
                    raw_start = cursor
                    cursor += len(segment) + 1
                    stripped = segment.strip()
                    if not stripped or stripped.casefold() in _GENERIC_BLOCK or "@" in stripped or re.search(r"\d{5,}", stripped) or len(stripped) > 90:
                        continue
                    local = segment.find(stripped)
                    start = raw_start + local
                    end = start + len(stripped)
                    # Remove a leading field label (e.g. Owner Tara Singh).
                    label_match = re.match(r"(?i)(?:owner|subject|participant|reviewer|citizen)\s*[:=]?\s+(.+)$", stripped)
                    if label_match:
                        value = label_match.group(1).strip()
                        vstart = start + stripped.find(value)
                        _add_candidate(result, seen, line, EntityType.PERSON_NAME, vstart, vstart + len(value), "pipe")
                        continue
                    words = stripped.split()
                    if 1 <= len(words) <= 3:
                        _add_candidate(result, seen, line, EntityType.LOCALITY, start, end, "pipe")
                    if 2 <= len(words) <= 6:
                        _add_candidate(result, seen, line, EntityType.PERSON_NAME, start, end, "pipe")
                        _add_candidate(result, seen, line, EntityType.EMPLOYER, start, end, "pipe")
    return result


def _mention(candidate: SemanticCandidateV2, probability: float) -> DetectedMention | None:
    rect = _rect(candidate.line, candidate.start, candidate.end)
    if rect is None:
        return None
    if candidate.entity_type == EntityType.PERSON_NAME:
        sensitivity, transformation, review = SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE, ReviewStatus.PENDING
    elif candidate.entity_type == EntityType.STREET_ADDRESS:
        sensitivity, transformation, review = SensitivityLevel.HIGH, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED if probability >= 0.92 else ReviewStatus.PENDING
    elif candidate.entity_type == EntityType.EMPLOYER:
        sensitivity, transformation, review = SensitivityLevel.MEDIUM, TransformationType.PSEUDONYMIZE, ReviewStatus.NOT_REQUIRED if probability >= 0.92 else ReviewStatus.PENDING
    else:
        sensitivity, transformation, review = SensitivityLevel.MEDIUM, TransformationType.GENERALIZE, ReviewStatus.NOT_REQUIRED if probability >= 0.92 else ReviewStatus.PENDING
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
        context_label=f"semantic-ner-v2:{candidate.entity_type.value.casefold()}:{candidate.pattern}",
    )


def detect_semantic_entities_v2(document: ProcessedDocument) -> list[DetectedMention]:
    # Structured datasets have explicit schema/header semantics in Broad PII v4;
    # running free-text semantic NER over their virtual rendering creates avoidable
    # class ambiguity (e.g. employer.name being mistaken for a person).
    from app.core.enums import FileType
    if document.file_type == FileType.DATASET:
        return []
    scored: list[tuple[SemanticCandidateV2, float]] = []
    for candidate in generate_semantic_candidates_v2(document):
        probability = _probability(candidate.entity_type, semantic_v2_features(candidate.entity_type, candidate.line.text, candidate.start, candidate.end, candidate.pattern))
        if probability >= _threshold(candidate.entity_type):
            scored.append((candidate, probability))

    # If the exact same span is plausible as several semantic classes, retain only
    # the most probable class.  This prevents an employer phrase from also becoming
    # a person simply because both consist of title-cased words.
    best_by_span: dict[tuple[int,int,int], tuple[SemanticCandidateV2, float]] = {}
    for candidate, probability in scored:
        key = (candidate.line.page_index, candidate.line.page_char_start + candidate.start, candidate.line.page_char_start + candidate.end)
        current = best_by_span.get(key)
        if current is None or probability > current[1]:
            best_by_span[key] = (candidate, probability)

    result: list[DetectedMention] = []
    for candidate, probability in best_by_span.values():
        mention = _mention(candidate, probability)
        if mention is not None:
            result.append(mention)
    return result
