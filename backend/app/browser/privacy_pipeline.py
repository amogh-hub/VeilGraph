from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
from collections import Counter
from dataclasses import dataclass, replace
from typing import Iterable
from urllib.parse import urlparse

from PIL import Image, ImageDraw

from app.browser.local_analysis import (
    BrowserAnalysisContext,
    BrowserAnalysisError,
    browser_analysis_response_from_context,
    build_browser_analysis_context,
)
from app.browser.models import (
    BrowserLocalCaptureMetadata,
    BrowserMinimizationEvidence,
    BrowserNetworkAuthorization,
    BrowserPublicElement,
    BrowserPublicPage,
    BrowserPublicVisualContext,
    BrowserReleasePayload,
    BrowserReleasePreparationResponse,
    BrowserVerificationSummary,
)
from app.browser.release_gate import authorize_network_release
from app.core.enums import DetectionSource, EntityType, PrivacyLevel
from app.detection.direct_identifiers import normalize_value
from app.detection.models import DetectedMention
from app.policy.compiler import DIRECT_TYPES, action_for, replacement_for_policy


NETWORK_PRIVACY_FLOOR = PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION
_MAX_RELEASE_ELEMENTS = 32
_STOPWORDS = {
    "a", "an", "and", "the", "to", "of", "for", "on", "in", "this", "that", "my", "me", "please",
    "current", "page", "website", "web", "do", "it", "with", "from", "at", "is", "are",
}
_ACTIONABLE_ROLES = {"button", "link", "textbox", "combobox", "checkbox", "radio", "option", "menuitem"}
_SENSITIVE_HINTS = {
    "credential", "email", "phone", "person_name", "government_identifier", "location", "financial",
    "quasi_identifier", "health",
}


class BrowserPreparationError(ValueError):
    pass


@dataclass(frozen=True)
class BrowserSanitizationEvidence:
    metadata: BrowserLocalCaptureMetadata
    context: BrowserAnalysisContext
    payload: BrowserReleasePayload
    sanitized_image_bytes: bytes
    sensitive_values: tuple[str, ...]
    direct_sensitive_values: tuple[str, ...]
    redaction_rects: tuple[tuple[int, int, int, int], ...]
    raw_element_count: int
    released_element_count: int
    relevant_anchor_count: int
    minimization: BrowserMinimizationEvidence
    overall_visual_status: str
    policy_action_count: int


@dataclass(frozen=True)
class _ElementCandidate:
    score: int
    ordinal: int
    frame_id: int
    is_top_frame: bool
    public: BrowserPublicElement
    bbox: tuple[int, int, int, int]
    task_overlap: int
    role_compatible: bool
    sensitive: bool


@dataclass(frozen=True)
class _TaskMinimizationPlan:
    task_intent: str
    candidate_count: int
    elements: tuple[BrowserPublicElement, ...]
    required_anchor_ids: tuple[str, ...]
    dependency_anchor_ids: tuple[str, ...]
    task_token_coverage_basis_points: int
    actionability_preserved: bool


def _safe_normalize(entity_type: EntityType, value: str) -> str:
    try:
        return normalize_value(entity_type, value)
    except Exception:
        return re.sub(r"\s+", " ", value.strip()).casefold()


_SITE_SECOND_LEVEL_SUFFIXES = {
    "co", "com", "org", "net", "gov", "ac", "edu",
}


def _site_identity_key(value: str) -> str:
    """Canonical comparison key for public site-brand identity only."""
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _public_site_identity_keys(
    metadata: BrowserLocalCaptureMetadata,
) -> set[str]:
    """Derive the public registrable-site brand from the clean page origin.

    Examples:
      www.google.com       -> google
      accounts.google.com  -> google
      www.example.co.in    -> example

    This is not a general allow-list. It is scoped to the exact current
    browser origin.
    """
    top_frame = next(
        (frame for frame in metadata.frames if frame.is_top_frame),
        metadata.frames[0],
    )

    try:
        hostname = (urlparse(top_frame.origin).hostname or "").strip(".").casefold()
    except Exception:
        return set()

    labels = [label for label in hostname.split(".") if label]

    # localhost, IP-like/single-label hosts and malformed origins receive no
    # site-brand exemption.
    if len(labels) < 2:
        return set()

    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in _SITE_SECOND_LEVEL_SUFFIXES
    ):
        brand = labels[-3]
    else:
        brand = labels[-2]

    key = _site_identity_key(brand)
    if len(key) < 3 or not any(char.isalpha() for char in key):
        return set()

    return {key}


def _is_public_site_identity_false_positive(
    detection: DetectedMention,
    *,
    site_identity_keys: set[str],
    protected_field_keys: set[str],
) -> bool:
    """Suppress only obvious site-brand NER false positives.

    A public brand match is never exempted when the same value occurs in an
    actual sensitive/raw browser field. Direct patterned identifiers such as
    email, phone, PAN, Aadhaar and payment cards are unaffected.
    """
    if detection.source == DetectionSource.VISUAL:
        return False

    if detection.entity_type not in {
        EntityType.EMPLOYER,
        EntityType.PERSON_NAME,
        EntityType.LOCALITY,
    }:
        return False

    key = _site_identity_key(detection.plaintext)

    return (
        len(key) >= 3
        and key in site_identity_keys
        and key not in protected_field_keys
    )


def _replacement_map(
    detections: Iterable[DetectedMention],
    level: PrivacyLevel,
    audience,
) -> tuple[dict[str, str], tuple[str, ...], tuple[str, ...], int]:
    grouped: dict[tuple[EntityType, str], str] = {}
    counters: Counter[EntityType] = Counter()
    sensitive_values: list[str] = []
    direct_values: list[str] = []
    action_count = 0

    ordered = sorted(
        detections,
        key=lambda item: (item.entity_type.value, _safe_normalize(item.entity_type, item.plaintext), item.page_index, item.rect),
    )
    for detection in ordered:
        if detection.source == DetectionSource.VISUAL:
            continue
        value = detection.plaintext.strip()
        if not value:
            continue
        action = action_for(detection.entity_type, level, audience)
        if action == "RETAIN":
            continue
        key = (detection.entity_type, _safe_normalize(detection.entity_type, value))
        if key not in grouped:
            ordinal = counters[detection.entity_type]
            counters[detection.entity_type] += 1
            grouped[key] = replacement_for_policy(detection.entity_type, value, level, audience, ordinal)
            action_count += 1
        sensitive_values.append(value)
        if detection.entity_type in DIRECT_TYPES:
            direct_values.append(value)

    # Exact source strings are the lookup key for semantic replacement. Longer
    # values are handled first later so nested identifiers do not partially mask
    # one another.
    replacements = {
        detection.plaintext: grouped[(detection.entity_type, _safe_normalize(detection.entity_type, detection.plaintext))]
        for detection in ordered
        if detection.source != DetectionSource.VISUAL
        and detection.plaintext.strip()
        and action_for(detection.entity_type, level, audience) != "RETAIN"
    }
    return replacements, tuple(dict.fromkeys(sensitive_values)), tuple(dict.fromkeys(direct_values)), action_count


_INDEPENDENT_SUBSTITUTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I), "[EMAIL PROTECTED]"),
    (re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])", re.I), "[IDENTIFIER PROTECTED]"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)"), "[IDENTIFIER PROTECTED]"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "[FINANCIAL IDENTIFIER PROTECTED]"),
    (re.compile(r"(?<!\d)(?:\+?\d[\s().-]*){10,15}(?!\d)"), "[PHONE PROTECTED]"),
)


def _sanitize_text(value: str, replacements: dict[str, str], extra_secret_values: Iterable[str] = ()) -> str:
    result = value
    pairs = list(replacements.items()) + [(secret, "[SENSITIVE VALUE PROTECTED]") for secret in extra_secret_values if secret]
    for source, replacement in sorted(pairs, key=lambda item: len(item[0]), reverse=True):
        if len(source.strip()) < 2:
            continue
        result = re.sub(re.escape(source), replacement, result, flags=re.IGNORECASE)
    for pattern, replacement in _INDEPENDENT_SUBSTITUTIONS:
        result = pattern.sub(replacement, result)
    return re.sub(r"\s+", " ", result).strip()


_TASK_VERB_STOPWORDS = {"click", "tap", "press", "open", "go", "navigate", "visit"}
_ACTION_INTENTS = {"CLICK", "TYPE", "SELECT", "NAVIGATE", "SUBMIT"}
_READ_ROLES = {"heading", "text", "div", "span", "label", "paragraph", "cell", "row", "link"}


def _task_tokens(task: str) -> set[str]:
    # Protected placeholders are compiler output, not task meaning. Letting words
    # such as EMAIL/PROTECTED influence relevance would accidentally keep the
    # very sensitive controls that minimization is supposed to remove.
    cleaned = re.sub(r"\[[^\]]*PROTECTED[^\]]*\]", " ", task, flags=re.I)
    return {
        token for token in re.findall(r"[a-z0-9]+", cleaned.casefold())
        if len(token) > 1 and token not in _STOPWORDS and token not in _TASK_VERB_STOPWORDS
    }


def _task_intent(task: str) -> str:
    lowered = task.casefold()
    words = set(re.findall(r"[a-z]+", lowered))
    if words & {"type", "enter", "fill", "write", "input"}:
        return "TYPE"
    if words & {"select", "choose", "pick", "toggle", "uncheck"}:
        return "SELECT"
    if words & {"submit", "confirm", "send", "save", "pay", "purchase"}:
        return "SUBMIT"
    if words & {"navigate", "visit", "open", "go"}:
        return "NAVIGATE"
    if words & {"click", "tap", "press", "book"}:
        return "CLICK"
    if words & {"read", "show", "find", "what", "view", "inspect", "check"}:
        return "READ"
    return "GENERAL"


def _role_compatible(intent: str, role: str) -> bool:
    role = role.casefold()
    if intent in {"CLICK", "NAVIGATE"}:
        return role in {"button", "link", "menuitem"}
    if intent == "SUBMIT":
        return role in {"button", "link"}
    if intent == "TYPE":
        return role in {"textbox", "combobox"}
    if intent == "SELECT":
        return role in {"combobox", "checkbox", "radio", "option", "menuitem"}
    if intent == "READ":
        return role in _READ_ROLES
    return role in _ACTIONABLE_ROLES or role in _READ_ROLES


def _element_score(task: str, label: str, text: str, role: str) -> int:
    tokens = _task_tokens(task)
    haystack = set(re.findall(r"[a-z0-9]+", f"{label} {text} {role}".casefold()))
    score = 12 * len(tokens & haystack)
    if role in _ACTIONABLE_ROLES:
        score += 3
    intent = _task_intent(task)
    if _role_compatible(intent, role):
        score += 8 if intent in _ACTION_INTENTS else 4
    return score


def _bbox_distance(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> int:
    dx = max(a[0] - b[2], b[0] - a[2], 0)
    dy = max(a[1] - b[3], b[1] - a[3], 0)
    return dx + dy


def _released_token_coverage(task: str, elements: Iterable[BrowserPublicElement]) -> int:
    tokens = _task_tokens(task)
    if not tokens:
        return 10_000
    released = set(
        re.findall(
            r"[a-z0-9]+",
            " ".join(f"{item.label} {item.text} {item.role}" for item in elements).casefold(),
        )
    )
    return max(0, min(10_000, round(10_000 * len(tokens & released) / len(tokens))))


def _sensitive_element_values(metadata: BrowserLocalCaptureMetadata) -> tuple[str, ...]:
    values: list[str] = []
    for frame in metadata.frames:
        for element in frame.elements:
            hints = {hint.casefold() for hint in element.privacy_hints}
            if element.raw_value and (hints & _SENSITIVE_HINTS or (element.input_type or "").casefold() == "password"):
                values.append(element.raw_value)
    return tuple(dict.fromkeys(values))


def _public_elements(
    metadata: BrowserLocalCaptureMetadata,
    task: str,
    replacements: dict[str, str],
    secret_values: tuple[str, ...],
) -> _TaskMinimizationPlan:
    intent = _task_intent(task)
    task_tokens = _task_tokens(task)
    candidates: list[_ElementCandidate] = []
    ordinal = 0

    for frame in metadata.frames:
        for element in frame.elements:
            label = _sanitize_text(element.accessible_name, replacements, secret_values)
            text = _sanitize_text(element.visible_text, replacements, secret_values)
            role = element.role[:64] or element.tag[:64]
            is_actionable = role in _ACTIONABLE_ROLES
            if not label and not text and not is_actionable:
                ordinal += 1
                continue

            haystack = set(re.findall(r"[a-z0-9]+", f"{label} {text} {role}".casefold()))
            overlap = len(task_tokens & haystack)
            compatible = _role_compatible(intent, role)
            hints = {hint.casefold() for hint in element.privacy_hints}
            sensitive = bool(hints & _SENSITIVE_HINTS or (element.input_type or "").casefold() == "password")
            score = _element_score(task, label, text, role)

            # A sensitive control is allowed to survive only when the task itself
            # names it or its role is necessary for an explicit input/select task.
            if sensitive and overlap == 0 and intent not in {"TYPE", "SELECT"}:
                score -= 24

            public = BrowserPublicElement(
                element_id=element.local_id,
                role=role,
                label=label[:256],
                text=text[:512],
                control_type=(element.input_type[:64] if element.input_type else None),
                disabled=element.disabled,
                checked=element.checked,
                selected=element.selected,
                bbox=element.bbox if frame.is_top_frame else None,
            )
            candidates.append(
                _ElementCandidate(
                    score=score,
                    ordinal=ordinal,
                    frame_id=frame.frame_id,
                    is_top_frame=frame.is_top_frame,
                    public=public,
                    bbox=element.bbox,
                    task_overlap=overlap,
                    role_compatible=compatible,
                    sensitive=sensitive,
                )
            )
            ordinal += 1

    ranked = sorted(candidates, key=lambda item: (item.score, item.task_overlap, -item.ordinal), reverse=True)
    required: list[_ElementCandidate] = []

    if intent in _ACTION_INTENTS:
        # Prefer controls that are both role-compatible and semantically tied to
        # the task. Generic buttons do not become network context just because
        # they are clickable.
        required = [item for item in ranked if item.role_compatible and item.task_overlap > 0 and item.score > 0][:_MAX_RELEASE_ELEMENTS]
        required = required[:4]
        if not required:
            fallback = [item for item in ranked if item.role_compatible and item.score > 0]
            required = fallback[:1]
    elif intent == "READ":
        required = [item for item in ranked if item.task_overlap > 0 and item.score > 0][:4]
    else:
        required = [item for item in ranked if item.task_overlap > 0 and item.score > 0][:4]
        if not required:
            required = [item for item in ranked if item.score > 0][:1]

    required_ids = {item.public.element_id for item in required}
    dependencies: list[_ElementCandidate] = []
    dependency_ids: set[str] = set()

    for anchor in required:
        nearby = []
        for item in ranked:
            if item.public.element_id in required_ids or item.public.element_id in dependency_ids:
                continue
            if item.frame_id != anchor.frame_id:
                continue
            if item.sensitive and item.task_overlap == 0:
                continue
            semantic_dependency = item.public.role.casefold() in _READ_ROLES
            if not semantic_dependency:
                continue
            distance = _bbox_distance(anchor.bbox, item.bbox)
            if item.task_overlap > 0 or distance <= 1200:
                nearby.append((item.task_overlap, -distance, item.score, -item.ordinal, item))
        nearby.sort(reverse=True, key=lambda entry: entry[:4])
        for entry in nearby[:2]:
            item = entry[4]
            dependencies.append(item)
            dependency_ids.add(item.public.element_id)

    # Small dynamic budget: enough for required controls and their explanatory
    # context, never a disguised dump of every visible control.
    budget = min(_MAX_RELEASE_ELEMENTS, max(8, len(required) * 4 + 4))
    selected: list[_ElementCandidate] = []
    selected_ids: set[str] = set()
    for item in [*required, *dependencies]:
        if item.public.element_id not in selected_ids and len(selected) < budget:
            selected.append(item)
            selected_ids.add(item.public.element_id)

    # Add only strongly task-relevant extras. A generic actionable score alone is
    # intentionally below this threshold.
    for item in ranked:
        if len(selected) >= budget:
            break
        if item.public.element_id in selected_ids:
            continue
        if item.task_overlap <= 0 or item.score < 12:
            continue
        if item.sensitive and item.task_overlap == 0:
            continue
        selected.append(item)
        selected_ids.add(item.public.element_id)

    elements = tuple(item.public for item in selected)
    coverage = _released_token_coverage(task, elements)
    if intent in _ACTION_INTENTS:
        actionability = any(_role_compatible(intent, item.role) and not item.disabled for item in elements)
    else:
        actionability = bool(elements)

    return _TaskMinimizationPlan(
        task_intent=intent,
        candidate_count=len(candidates),
        elements=elements,
        required_anchor_ids=tuple(item.public.element_id for item in required if item.public.element_id in selected_ids),
        dependency_anchor_ids=tuple(item.public.element_id for item in dependencies if item.public.element_id in selected_ids),
        task_token_coverage_basis_points=coverage,
        actionability_preserved=actionability,
    )


def _to_pixel_rect(
    rect: tuple[float, float, float, float], width: int, height: int, padding: int = 5,
) -> tuple[int, int, int, int]:
    x0, y0, x1, y1 = rect
    return (
        max(0, int(x0) - padding),
        max(0, int(y0) - padding),
        min(width, int(x1 + 0.999) + padding),
        min(height, int(y1 + 0.999) + padding),
    )


def _bp_to_pixel_rect(
    rect: tuple[int, int, int, int], width: int, height: int, padding: int = 5,
) -> tuple[int, int, int, int]:
    x0, y0, x1, y1 = rect
    return _to_pixel_rect((width * x0 / 10_000, height * y0 / 10_000, width * x1 / 10_000, height * y1 / 10_000), width, height, padding)


def _merge_rectangles(rects: list[tuple[int, int, int, int]]) -> list[tuple[int, int, int, int]]:
    merged: list[tuple[int, int, int, int]] = []
    for rect in sorted(set(rects)):
        x0, y0, x1, y1 = rect
        if x1 <= x0 or y1 <= y0:
            continue
        changed = True
        while changed:
            changed = False
            for index, existing in enumerate(merged):
                ex0, ey0, ex1, ey1 = existing
                overlap_x = min(x1, ex1) - max(x0, ex0)
                overlap_y = min(y1, ey1) - max(y0, ey0)
                near = x0 <= ex1 + 3 and ex0 <= x1 + 3 and y0 <= ey1 + 3 and ey0 <= y1 + 3
                if overlap_x > 0 and overlap_y > 0 or near:
                    x0, y0, x1, y1 = min(x0, ex0), min(y0, ey0), max(x1, ex1), max(y1, ey1)
                    merged.pop(index)
                    changed = True
                    break
        merged.append((x0, y0, x1, y1))
    return merged


def _redaction_rectangles(
    metadata: BrowserLocalCaptureMetadata,
    context: BrowserAnalysisContext,
    image: Image.Image,
) -> list[tuple[int, int, int, int]]:
    width, height = image.size
    rects: list[tuple[int, int, int, int]] = []
    for detection in context.detections:
        if detection.page_index != 0:
            continue
        if action_for(detection.entity_type, context.level, context.audience) == "RETAIN":
            continue
        rects.append(_to_pixel_rect(detection.rect, width, height))

    top_frame = next((frame for frame in metadata.frames if frame.is_top_frame), None)
    if top_frame:
        for element in top_frame.elements:
            hints = {hint.casefold() for hint in element.privacy_hints}
            if hints & _SENSITIVE_HINTS or (element.input_type or "").casefold() == "password":
                rects.append(_bp_to_pixel_rect(element.bbox, width, height, padding=6))

    for finding in metadata.visual_findings:
        if finding.type in {"FACE", "QR_CODE", "PASSWORD_FIELD", "SENSITIVE_REGION"}:
            rects.append(_bp_to_pixel_rect(finding.bbox, width, height, padding=7))
    return _merge_rectangles(rects)


def _visual_retention_rects(
    elements: Iterable[BrowserPublicElement],
    image: Image.Image,
) -> list[tuple[int, int, int, int]]:
    width, height = image.size
    rects: list[tuple[int, int, int, int]] = []
    for element in elements:
        if element.bbox is None:
            continue
        rects.append(_bp_to_pixel_rect(element.bbox, width, height, padding=24))
    return _merge_rectangles(rects)


def _sanitize_visual_context(
    screenshot: bytes,
    metadata: BrowserLocalCaptureMetadata,
    context: BrowserAnalysisContext,
    released_elements: Iterable[BrowserPublicElement],
) -> tuple[
    BrowserPublicVisualContext,
    bytes,
    tuple[tuple[int, int, int, int], ...],
    int,
    int,
]:
    try:
        image = Image.open(io.BytesIO(screenshot)).convert("RGB")
        image.load()
    except Exception as exc:
        raise BrowserPreparationError("unable to decode screenshot for local visual sanitization") from exc

    redaction_rects = _redaction_rectangles(metadata, context, image)
    protected = image.copy()
    draw = ImageDraw.Draw(protected)
    for x0, y0, x1, y1 in redaction_rects:
        draw.rectangle((x0, y0, x1, y1), fill=(18, 18, 20))

    # Preserve the original viewport coordinate system, but make every pixel not
    # needed by the selected semantic anchors opaque. This gives the remote VLM
    # spatial context without handing it the rest of the page.
    retention_rects = _visual_retention_rects(released_elements, protected)
    minimized = Image.new("RGB", protected.size, (18, 18, 20))
    for rect in retention_rects:
        minimized.paste(protected.crop(rect), rect)

    total_area = max(1, minimized.width * minimized.height)
    retained_area = sum(max(0, x1 - x0) * max(0, y1 - y0) for x0, y0, x1, y1 in retention_rects)
    visual_minimization = max(0, min(10_000, round((1.0 - min(1.0, retained_area / total_area)) * 10_000)))

    out = io.BytesIO()
    mime = "image/webp"
    try:
        # Lossless encoding prevents compression artifacts at privacy boundaries.
        minimized.save(out, format="WEBP", lossless=True, method=4, exact=True)
    except Exception:
        out = io.BytesIO()
        minimized.save(out, format="PNG", optimize=True)
        mime = "image/png"
    sanitized = out.getvalue()
    if not sanitized:
        raise BrowserPreparationError("sanitized visual context encoded to an empty image")
    encoded = base64.b64encode(sanitized).decode("ascii")
    visual = BrowserPublicVisualContext(
        mime_type=mime,
        width=minimized.width,
        height=minimized.height,
        image_base64=encoded,
        sanitized_sha256=hashlib.sha256(sanitized).hexdigest(),
        redacted_regions=len(redaction_rects),
    )
    return visual, sanitized, tuple(redaction_rects), visual_minimization, len(retention_rects)


def _semantic_size(metadata: BrowserLocalCaptureMetadata) -> int:
    total = len(metadata.task) + sum(len(frame.title) + len(frame.href) for frame in metadata.frames)
    for frame in metadata.frames:
        for element in frame.elements:
            total += len(element.accessible_name) + len(element.visible_text) + len(element.raw_value or "") + len(element.role)
    return max(1, total)


def _released_semantic_size(task: str, title: str, elements: list[BrowserPublicElement]) -> int:
    return max(1, len(task) + len(title) + sum(len(item.label) + len(item.text) + len(item.role) for item in elements))


def _task_utility_score(task: str, elements: list[BrowserPublicElement], anchors: int) -> int:
    if not elements:
        return 0
    coverage = _released_token_coverage(task, elements) / 10_000
    actionable = any(element.role in _ACTIONABLE_ROLES and not element.disabled for element in elements)
    score = round(58 * coverage + (32 if actionable else 0) + min(10, anchors * 2))
    return max(0, min(100, score))


def _overall_visual_status(metadata: BrowserLocalCaptureMetadata, context: BrowserAnalysisContext) -> str:
    return "READY" if context.companion_status == "READY" else metadata.visual_perception_status


def prepare_browser_release(metadata: BrowserLocalCaptureMetadata, screenshot: bytes) -> BrowserReleasePreparationResponse:
    if metadata.requested_privacy_level == int(PrivacyLevel.SYNTHETIC_TWIN):
        raise BrowserPreparationError("L5 Synthetic Twin is defined for structured datasets, not live browser pages")

    effective_level = PrivacyLevel(max(metadata.requested_privacy_level, int(NETWORK_PRIVACY_FLOOR)))
    context = build_browser_analysis_context(metadata, screenshot, level_override=effective_level)
    analysis = browser_analysis_response_from_context(metadata, screenshot, context)

    top_frame = next(
        (frame for frame in metadata.frames if frame.is_top_frame),
        metadata.frames[0],
    )

    secret_values = _sensitive_element_values(metadata)
    protected_field_keys = {
        _site_identity_key(value)
        for value in secret_values
        if _site_identity_key(value)
    }
    site_identity_keys = _public_site_identity_keys(metadata)

    policy_detections = tuple(
        detection
        for detection in context.detections
        if not _is_public_site_identity_false_positive(
            detection,
            site_identity_keys=site_identity_keys,
            protected_field_keys=protected_field_keys,
        )
    )

    # Keep the original analysis evidence intact, but use the independently
    # filtered detection view for the network-bound privacy compiler and raster
    # sanitizer.
    sanitization_context = replace(
        context,
        detections=policy_detections,
    )

    replacements, sensitive_values, direct_values, policy_actions = _replacement_map(
        policy_detections,
        effective_level,
        context.audience,
    )

    all_sensitive_values = tuple(dict.fromkeys((*sensitive_values, *secret_values)))
    all_direct_values = tuple(dict.fromkeys((*direct_values, *secret_values)))

    # Task relevance must be derived from the local task semantics with
    # sensitive source values removed BEFORE privacy replacements are introduced.
    # Otherwise pseudonyms such as EMAIL_* can spuriously make an unrelated Email
    # control appear relevant to the task.
    relevance_task = _sanitize_text(metadata.task, {}, all_sensitive_values)[:1000]
    sanitized_task = _sanitize_text(metadata.task, replacements, secret_values)[:1000]
    sanitized_title = _sanitize_text(top_frame.title, replacements, secret_values)[:256]

    plan = _public_elements(metadata, relevance_task, replacements, secret_values)
    elements = list(plan.elements)
    anchors = len(plan.required_anchor_ids)
    visual_context, sanitized_image, redaction_rects, visual_minimization, retained_visual_regions = _sanitize_visual_context(
        screenshot,
        metadata,
        sanitization_context,
        elements,
    )

    raw_semantic = _semantic_size(metadata)
    released_semantic = _released_semantic_size(sanitized_task, sanitized_title, elements)
    semantic_minimization = max(0, min(10_000, round((1.0 - min(1.0, released_semantic / raw_semantic)) * 10_000)))
    overall_minimization = min(semantic_minimization, visual_minimization)
    task_utility = _task_utility_score(relevance_task, elements, anchors)
    utility_sufficient = (
        task_utility >= 60
        and anchors > 0
        and plan.actionability_preserved
        and plan.task_token_coverage_basis_points >= 4_000
    )
    raw_element_count = sum(len(frame.elements) for frame in metadata.frames)
    minimization = BrowserMinimizationEvidence(
        task_intent=plan.task_intent,
        raw_element_count=raw_element_count,
        candidate_element_count=plan.candidate_count,
        released_element_count=len(elements),
        dropped_irrelevant_count=max(0, raw_element_count - len(elements)),
        required_anchor_ids=list(plan.required_anchor_ids),
        dependency_anchor_ids=list(plan.dependency_anchor_ids),
        semantic_minimization_basis_points=semantic_minimization,
        visual_minimization_basis_points=visual_minimization,
        overall_minimization_basis_points=overall_minimization,
        task_token_coverage_basis_points=plan.task_token_coverage_basis_points,
        actionability_preserved=plan.actionability_preserved,
        utility_sufficient=utility_sufficient,
        retained_visual_regions=retained_visual_regions,
    )
    risk = context.graph["risk"]

    payload = BrowserReleasePayload(
        session_id=f"session_{secrets.token_hex(12)}",
        task_id=f"task_{secrets.token_hex(12)}",
        task=sanitized_task,
        page=BrowserPublicPage(
            origin=top_frame.origin,
            page_class="web",
            title=sanitized_title,
            elements=elements,
            visual_context=visual_context,
        ),
        privacy_level=int(effective_level),
        network_privacy_floor=int(NETWORK_PRIVACY_FLOOR),
        identity_exposure_before=int(risk["before"]),
        residual_identity_exposure=int(risk["after"]),
        task_utility_score=task_utility,
        minimization_basis_points=overall_minimization,
    )

    evidence = BrowserSanitizationEvidence(
        metadata=metadata,
        context=sanitization_context,
        payload=payload,
        sanitized_image_bytes=sanitized_image,
        sensitive_values=all_sensitive_values,
        direct_sensitive_values=all_direct_values,
        redaction_rects=redaction_rects,
        raw_element_count=raw_element_count,
        released_element_count=len(elements),
        relevant_anchor_count=anchors,
        minimization=minimization,
        overall_visual_status=_overall_visual_status(metadata, context),
        policy_action_count=policy_actions + len(secret_values),
    )

    # Import locally to preserve a hard architectural boundary: protection builds
    # evidence; the independent Red Team decides whether that evidence is enough.
    from app.browser.red_team import verify_browser_release

    verification: BrowserVerificationSummary = verify_browser_release(evidence)
    authorization: BrowserNetworkAuthorization = authorize_network_release(payload, verification)
    return BrowserReleasePreparationResponse(
        analysis=analysis,
        payload=payload,
        minimization=minimization,
        verification=verification,
        authorization=authorization,
    )
