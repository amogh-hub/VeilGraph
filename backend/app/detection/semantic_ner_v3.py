from __future__ import annotations

"""VeilGraph local semantic NER v3.

Broad PII v5 generalization layer.

This is a bundled, runtime-offline logistic span classifier. Candidate generation
is deliberately broader than v2 and focuses on long-form prose/domain shift:
legal documents, reports, correspondence, OCR-ish text and narrative forms.
The learned model scores syntax/context-generated spans for PERSON_NAME,
EMPLOYER, LOCALITY, STREET_ADDRESS and JOB_TITLE.

Runtime inference uses only the committed JSON weights and Python stdlib. No
network, hosted model or external inference API is required.
"""

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.enums import EntityType, FileType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PositionedLine, PositionedToken, ProcessedDocument

_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "semantic_ner_v3.json"

# Unicode-aware lexical primitives. The patterns intentionally avoid a built-in
# name gazetteer: the classifier should learn context/shape, not memorize people.
_CAP_TOKEN = r"(?:[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,}|[A-ZÀ-ÖØ-Þ](?:\.|\b)|[A-ZÀ-ÖØ-Þ]{2,})"
_NAME = rf"{_CAP_TOKEN}(?:\s+{_CAP_TOKEN}){{0,4}}"
_ORG_TOKEN = r"(?:[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ0-9'’&.\-]*|of|and|the|for|&|de|la|van|von)"
_ORG = rf"{_ORG_TOKEN}(?:\s+{_ORG_TOKEN}){{0,10}}"
_PLACE = rf"{_CAP_TOKEN}(?:\s+{_CAP_TOKEN}){{0,3}}"

_HONORIFICS = (
    "mr", "mrs", "ms", "miss", "dr", "doctor", "prof", "professor", "judge", "justice",
    "sir", "lady", "lord", "advocate", "attorney", "counsel", "inspector", "officer",
    "captain", "capt", "lieutenant", "lt", "sergeant", "sgt", "rev", "reverend",
)
_PERSON_ROLES = (
    "applicant", "claimant", "complainant", "petitioner", "respondent", "plaintiff", "defendant",
    "witness", "victim", "patient", "employee", "customer", "client", "participant", "subject",
    "owner", "reviewer", "citizen", "guardian", "mother", "father", "son", "daughter", "husband",
    "wife", "doctor", "physician", "lawyer", "attorney", "counsel", "judge", "prosecutor",
    "officer", "representative", "beneficiary", "insured", "policyholder", "account holder",
)
_PERSON_VERBS = (
    "is", "was", "has", "had", "said", "stated", "alleged", "claimed", "submitted", "requested",
    "reported", "filed", "signed", "attended", "worked", "works", "lived", "lives", "resided",
    "resides", "applied", "contacted", "informed", "testified", "appeared", "asked", "noted",
)
_ORG_TERMS = {
    "company", "corporation", "corp", "limited", "ltd", "llc", "plc", "inc", "bank", "hospital",
    "clinic", "university", "college", "school", "institute", "foundation", "agency", "department",
    "ministry", "authority", "council", "court", "office", "bureau", "association", "service",
    "services", "systems", "technologies", "technology", "labs", "laboratories", "group", "centre",
    "center", "research", "trust", "board", "commission", "committee", "administration", "police",
}
_ROLE_TERMS = {
    "analyst", "engineer", "manager", "officer", "architect", "developer", "scientist", "consultant",
    "professor", "teacher", "director", "specialist", "researcher", "auditor", "administrator",
    "technician", "designer", "coordinator", "executive", "associate", "doctor", "physician", "nurse",
    "lawyer", "attorney", "counsel", "judge", "prosecutor", "clerk", "supervisor", "president",
    "secretary", "accountant", "inspector", "investigator", "advisor", "adviser", "member", "partner",
}
_ADDRESS_TERMS = {
    "road", "rd", "street", "st", "avenue", "ave", "lane", "ln", "layout", "cross", "main", "nagar",
    "colony", "circle", "drive", "dr", "boulevard", "blvd", "block", "residency", "crescent", "close",
    "way", "highway", "hwy", "terrace", "court", "square", "place", "parkway", "marg", "gali",
}
_GENERIC_BLOCK = {
    "he", "she", "they", "we", "i", "it", "his", "her", "their", "our", "the", "this", "that", "these", "those",
    "public release", "identity exposure", "privacy graph", "machine learning", "artificial intelligence",
    "software engineering", "data protection", "security analyst", "project manager", "research partner",
    "privacy policy", "support case", "support video", "case brief", "case report", "document review",
    "end", "sample", "value", "field", "key", "personal information", "human review", "privacy red team",
}

_HON = "|".join(re.escape(x) for x in sorted(_HONORIFICS, key=len, reverse=True))
_PROLE = "|".join(re.escape(x) for x in sorted(_PERSON_ROLES, key=len, reverse=True))
_PVERB = "|".join(re.escape(x) for x in sorted(_PERSON_VERBS, key=len, reverse=True))

_PATTERNS: tuple[tuple[EntityType, str, re.Pattern[str]], ...] = (
    # Mr John A. Smith / Dr. Alice Brown
    (EntityType.PERSON_NAME, "honorific-person", re.compile(rf"(?i:\b(?:{_HON})\.?\s+)(?P<value>{_NAME})(?=[,;:()\[\].]|\s+(?:who|was|is|of|from|at|in|and|said|stated|filed|submitted)\b|\s+[a-z]|$)")),
    # the applicant, John Smith, ... / patient: Alice Brown
    (EntityType.PERSON_NAME, "role-person", re.compile(rf"(?i:\b(?:{_PROLE})\b\s*(?:was\s+identified\s+as\s+|was\s+named\s+|named\s+|called\s+|[:=,-]\s*)?)(?P<value>{_NAME})(?=[,;:()\[\].]|\s+(?:who|was|is|of|from|at|in|and|said|stated|filed|submitted|born)\b|$)")),
    # John Smith, the applicant / John Smith (the applicant)
    (EntityType.PERSON_NAME, "person-before-role", re.compile(rf"(?P<value>{_NAME})(?=\s*(?:,|\()\s*(?i:(?:the\s+)?(?:{_PROLE}))\b)")),
    # named John Smith / met John Smith / signed by John Smith
    (EntityType.PERSON_NAME, "action-person", re.compile(rf"(?i:\b(?:named|called|met|contacted|emailed|telephoned|interviewed|questioned|reviewed\s+by|signed\s+by|prepared\s+by|submitted\s+by|represented\s+by|treated\s+by|examined\s+by|identified\s+as)\s+)(?P<value>{_NAME})(?=[,;:()\[\].]|\s+(?:who|was|is|for|after|before|during|regarding|and|to|at|in|of)\b|$)")),
    # John Smith was born / John Smith stated ...
    (EntityType.PERSON_NAME, "sentence-person", re.compile(rf"(?:^|(?<=[.!?])\s+)(?P<value>{_NAME})\s+(?=(?i:(?:{_PVERB})\b))")),
    # employed by Example Health Trust / works at Meridian Labs
    (EntityType.EMPLOYER, "employment-org", re.compile(rf"(?i:\b(?:works?|worked|employed|employer|affiliated|appointed)\s+(?:at|by|with|for)\s+(?:the\s+)?)(?P<value>{_ORG})(?=[,;:()\[\].]|\s+(?:as|in|on|for|where|which|and)\b|$)")),
    # Ministry of Health / Meridian Research Foundation / District Court
    (EntityType.EMPLOYER, "org-suffix", re.compile(rf"(?P<value>{_ORG}\s+(?i:(?:{'|'.join(sorted(_ORG_TERMS, key=len, reverse=True))})))(?=[,;:()\[\].]|$|\s+(?:in|at|for|which|where|and)\b)")),
    # resident of London / based in New Delhi / city of Mysuru
    (EntityType.LOCALITY, "location-place", re.compile(rf"(?i:\b(?:resident\s+of|resides?\s+in|lives?\s+in|from|near|located\s+in|based\s+in|city\s+of|town\s+of|village\s+of|district\s+of|locality\s*[:=]|city\s*[:=]|location\s*[:=])\s+)(?P<value>{_PLACE})(?=[,;:()\[\].]|\s+(?:who|was|is|for|to|after|before|during|and|where|with)\b|$)")),
    # Address: 12 Park Street / mailed to 42 Main Road
    (EntityType.STREET_ADDRESS, "address-label", re.compile(r"(?i:\b(?:address|residential\s+address|home\s+address|residence|mailed\s+to|sent\s+to|delivered\s+to|couriered\s+to)\s*[:=,-]?\s*)(?P<value>\d{1,6}[A-Za-z]?(?:[\s,]+[A-Za-z0-9À-ÖØ-öø-ÿ.'’\-]+){1,10})(?=[;|]|$|\s+(?:phone|email|tel|mobile)\s*[:=])")),
    # as a Senior Analyst / occupation: Research Scientist
    (EntityType.JOB_TITLE, "job-title", re.compile(rf"(?i:\b(?:occupation|profession|position|job\s+title|role)\s*[:=]\s*|\bas\s+(?:an?\s+)?)(?P<value>{_CAP_TOKEN}(?:\s+{_CAP_TOKEN}){{0,4}})(?=[,;:()\[\].]|$|\s+(?:at|for|with|in|who|and)\b)")),
)


@dataclass(frozen=True)
class SemanticCandidateV3:
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


def _words(value: str) -> list[str]:
    return re.findall(r"[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ.'’\-]*|\d+[A-Za-z]?", value, re.UNICODE)


def semantic_v3_features(entity_type: EntityType, text: str, start: int, end: int, pattern: str) -> dict[str, float]:
    value = text[start:end]
    words = _words(value)
    lower_words = [w.casefold().strip(".'’-\"") for w in words]
    before = text[max(0, start - 96):start].casefold()
    after = text[end:end + 96].casefold()
    compact = value.strip(" \t|,;:—–-()[]")
    alpha_words = [w for w in words if any(ch.isalpha() for ch in w)]
    title_like = sum(1 for w in alpha_words if w[:1].isupper() or (len(w) > 1 and w.isupper()) or re.fullmatch(r"[A-Z]\.?", w))
    initials = sum(1 for w in alpha_words if re.fullmatch(r"[A-Z]\.?", w))
    alpha_chars = sum(ch.isalpha() for ch in compact)
    nonspace = sum(not ch.isspace() for ch in compact)
    lower_set = set(lower_words)
    return {
        "bias": 1.0,
        "title_ratio": title_like / max(1, len(alpha_words)),
        "initial_ratio": initials / max(1, len(alpha_words)),
        "token_count_1": 1.0 if len(alpha_words) == 1 else 0.0,
        "token_count_2": 1.0 if len(alpha_words) == 2 else 0.0,
        "token_count_3_5": 1.0 if 3 <= len(alpha_words) <= 5 else 0.0,
        "all_caps": 1.0 if compact and compact.upper() == compact and any(ch.isalpha() for ch in compact) else 0.0,
        "contains_digit": 1.0 if any(ch.isdigit() for ch in compact) else 0.0,
        "alpha_ratio": alpha_chars / max(1, nonspace),
        "org_term": 1.0 if lower_set & _ORG_TERMS else 0.0,
        "role_term": 1.0 if lower_set & _ROLE_TERMS else 0.0,
        "address_term": 1.0 if lower_set & _ADDRESS_TERMS else 0.0,
        "honorific_context": 1.0 if re.search(rf"(?:^|\W)(?:{_HON})\.?\s*$", before) else 0.0,
        "person_role_context": 1.0 if re.search(rf"(?:^|\W)(?:{_PROLE})\s*(?:was\s+identified\s+as\s+|was\s+named\s+|named\s+|called\s+|[:=,-]\s*)?$", before) else 0.0,
        "person_action_context": 1.0 if re.search(r"(?:named|called|met|contacted|emailed|telephoned|interviewed|questioned|reviewed\s+by|signed\s+by|prepared\s+by|submitted\s+by|represented\s+by|treated\s+by|examined\s+by|identified\s+as)\s+$", before) else 0.0,
        "next_person_verb": 1.0 if re.match(rf"\s*(?:{_PVERB})\b", after) else 0.0,
        "next_person_role": 1.0 if re.match(rf"\s*(?:,|\()\s*(?:the\s+)?(?:{_PROLE})\b", after) else 0.0,
        "employment_context": 1.0 if re.search(r"(?:works?|worked|employed|employer|affiliated|appointed)\s+(?:at|by|with|for)\s+(?:the\s+)?$", before) else 0.0,
        "location_context": 1.0 if re.search(r"(?:resident\s+of|resides?\s+in|lives?\s+in|from|near|located\s+in|based\s+in|city\s+of|town\s+of|village\s+of|district\s+of|locality\s*[:=]|city\s*[:=]|location\s*[:=])\s+$", before) else 0.0,
        "role_context": 1.0 if re.search(r"(?:occupation|profession|position|job\s+title|role)\s*[:=]\s*$|\bas\s+(?:an?\s+)?$", before) else 0.0,
        "address_context": 1.0 if re.search(r"(?:address|residential\s+address|home\s+address|residence|mailed\s+to|sent\s+to|delivered\s+to|couriered\s+to)\s*[:=,-]?\s*$", before) else 0.0,
        "legal_context": 1.0 if any(x in text.casefold() for x in ("applicant", "respondent", "claimant", "court", "witness", "complainant", "petition", "judgment", "proceedings")) else 0.0,
        "field_like": 1.0 if re.search(r"[A-Za-z][A-Za-z _/-]{0,32}\s*[:=]\s*$", before) else 0.0,
        "sentence_start": 1.0 if text[:start].strip(" \t\"'([{—–-") == "" else 0.0,
        "generic_block": 1.0 if compact.casefold() in _GENERIC_BLOCK else 0.0,
        **{f"pattern_{name.replace('-', '_')}": 1.0 if pattern == name else 0.0 for name in (
            "honorific-person", "role-person", "person-before-role", "action-person", "sentence-person",
            "employment-org", "org-suffix", "location-place", "address-label", "job-title",
        )},
    }


@lru_cache(maxsize=1)
def _model() -> dict:
    payload = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
    if payload.get("schema") != "veilgraph.semantic-ner.linear.v3":
        raise RuntimeError("Unsupported semantic NER v3 model schema")
    return payload


def semantic_model_v3_metadata() -> dict[str, object]:
    payload = _model()
    return {
        "schema": payload["schema"],
        "version": payload["version"],
        "training_source": payload["training_source"],
        "training_corpus_sha256": payload["training_corpus_sha256"],
        "runtime_network_required": False,
        "model_family": payload["model_family"],
        "training_examples": payload.get("training_examples", 0),
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
    return float(_model()["classifiers"][entity_type.value].get("threshold", 0.70))


def _clean_candidate(line: PositionedLine, entity_type: EntityType, start: int, end: int, pattern: str) -> SemanticCandidateV3 | None:
    raw = line.text[start:end]
    left = len(raw) - len(raw.lstrip())
    cleaned = raw.strip().strip("|,;:—–()[]")
    if not cleaned:
        return None
    start += left
    end = start + len(cleaned)
    if cleaned.casefold() in _GENERIC_BLOCK:
        return None
    if entity_type == EntityType.PERSON_NAME:
        ws = _words(cleaned)
        if not 1 <= len(ws) <= 5 or sum(ch.isalpha() for ch in cleaned) < 2:
            return None
        if any(term in {w.casefold().strip('.')} for w in ws for term in _ORG_TERMS):
            return None
    if entity_type == EntityType.EMPLOYER and cleaned.casefold() in {"the court", "the government", "the police"}:
        return None
    return SemanticCandidateV3(entity_type, line, line.text[start:end], start, end, pattern)


def generate_semantic_candidates_v3(document: ProcessedDocument) -> list[SemanticCandidateV3]:
    # v5's free-text semantic layer intentionally avoids structured datasets,
    # video evidence frames and DOCX structural units. Those have authoritative
    # adapter/schema context already and were frozen in earlier acceptance work.
    if document.file_type in {FileType.DATASET, FileType.VIDEO, FileType.DOCX}:
        return []
    result: list[SemanticCandidateV3] = []
    seen: set[tuple[int, int, int, EntityType]] = set()
    for page in document.pages:
        for line in page.lines:
            for entity_type, pattern_id, pattern in _PATTERNS:
                for match in pattern.finditer(line.text):
                    candidate = _clean_candidate(line, entity_type, *match.span("value"), pattern_id)
                    if candidate is None:
                        continue
                    key = (line.page_index, line.page_char_start + candidate.start, line.page_char_start + candidate.end, entity_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    result.append(candidate)
    return result


def _mention(candidate: SemanticCandidateV3, probability: float) -> DetectedMention | None:
    rect = _rect(candidate.line, candidate.start, candidate.end)
    if rect is None:
        return None
    if candidate.entity_type == EntityType.PERSON_NAME:
        sensitivity, transformation = SensitivityLevel.HIGH, TransformationType.PSEUDONYMIZE
    elif candidate.entity_type == EntityType.STREET_ADDRESS:
        sensitivity, transformation = SensitivityLevel.HIGH, TransformationType.GENERALIZE
    elif candidate.entity_type == EntityType.EMPLOYER:
        sensitivity, transformation = SensitivityLevel.MEDIUM, TransformationType.PSEUDONYMIZE
    else:
        sensitivity, transformation = SensitivityLevel.MEDIUM, TransformationType.GENERALIZE
    review = ReviewStatus.NOT_REQUIRED if probability >= 0.94 and candidate.pattern in {"honorific-person", "employment-org", "location-place", "address-label", "job-title"} else ReviewStatus.PENDING
    confidence = probability
    # Structural address decomposition from the established detector is preferred
    # when available; v5's broader labelled-address span is a fallback.
    if candidate.entity_type == EntityType.STREET_ADDRESS:
        confidence = min(confidence, 0.90)
    return DetectedMention(
        entity_type=candidate.entity_type,
        plaintext=candidate.value,
        page_index=candidate.line.page_index,
        page_char_start=candidate.line.page_char_start + candidate.start,
        page_char_end=candidate.line.page_char_start + candidate.end,
        rect=rect,
        confidence=round(max(0.55, min(0.995, confidence)), 4),
        source=candidate.line.source,
        sensitivity=sensitivity,
        transformation=transformation,
        review_status=review,
        context_label=f"semantic-ner-v3:{candidate.entity_type.value.casefold()}:{candidate.pattern}",
    )


def detect_semantic_entities_v3(document: ProcessedDocument) -> list[DetectedMention]:
    scored: list[tuple[SemanticCandidateV3, float]] = []
    for candidate in generate_semantic_candidates_v3(document):
        features = semantic_v3_features(candidate.entity_type, candidate.line.text, candidate.start, candidate.end, candidate.pattern)
        probability = _probability(candidate.entity_type, features)
        if probability >= _threshold(candidate.entity_type):
            scored.append((candidate, probability))

    # One semantic class per exact source span. Context/model confidence decides.
    best_by_span: dict[tuple[int, int, int], tuple[SemanticCandidateV3, float]] = {}
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
