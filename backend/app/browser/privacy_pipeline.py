from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from PIL import Image, ImageDraw

from app.browser.local_analysis import (
    BrowserAnalysisContext,
    BrowserAnalysisError,
    browser_analysis_response_from_context,
    build_browser_analysis_context,
)
from app.browser.models import (
    BrowserLocalCaptureMetadata,
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
_MAX_RELEASE_ELEMENTS = 80
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
    overall_visual_status: str
    policy_action_count: int


def _safe_normalize(entity_type: EntityType, value: str) -> str:
    try:
        return normalize_value(entity_type, value)
    except Exception:
        return re.sub(r"\s+", " ", value.strip()).casefold()


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


def _task_tokens(task: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", task.casefold())
        if len(token) > 1 and token not in _STOPWORDS
    }


def _element_score(task: str, label: str, text: str, role: str) -> int:
    tokens = _task_tokens(task)
    haystack = set(re.findall(r"[a-z0-9]+", f"{label} {text} {role}".casefold()))
    score = 12 * len(tokens & haystack)
    if role in _ACTIONABLE_ROLES:
        score += 3
    lowered = task.casefold()
    if any(word in lowered for word in ("click", "open", "book", "submit", "continue", "confirm", "send")) and role in {"button", "link"}:
        score += 8
    if any(word in lowered for word in ("type", "enter", "fill", "write")) and role in {"textbox", "combobox"}:
        score += 8
    if any(word in lowered for word in ("select", "choose", "pick")) and role in {"combobox", "checkbox", "radio", "option"}:
        score += 8
    if any(word in lowered for word in ("read", "show", "find", "check", "what")) and role in {"heading", "text", "div", "span", "label"}:
        score += 4
    return score


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
) -> tuple[list[BrowserPublicElement], int]:
    candidates: list[tuple[int, int, BrowserPublicElement]] = []
    ordinal = 0
    for frame in metadata.frames:
        for element in frame.elements:
            label = _sanitize_text(element.accessible_name, replacements, secret_values)
            text = _sanitize_text(element.visible_text, replacements, secret_values)
            role = element.role[:64] or element.tag[:64]
            score = _element_score(task, label, text, role)
            is_actionable = role in _ACTIONABLE_ROLES
            if score <= 0 and not is_actionable:
                ordinal += 1
                continue
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
            # Stable tie-breaking by capture order avoids non-deterministic JSON.
            candidates.append((score, -ordinal, public))
            ordinal += 1

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    selected = [item[2] for item in candidates[:_MAX_RELEASE_ELEMENTS]]
    anchors = sum(item[0] > 3 for item in candidates[:_MAX_RELEASE_ELEMENTS])
    return selected, anchors


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


def _sanitize_visual_context(
    screenshot: bytes,
    metadata: BrowserLocalCaptureMetadata,
    context: BrowserAnalysisContext,
) -> tuple[BrowserPublicVisualContext, bytes, tuple[tuple[int, int, int, int], ...]]:
    try:
        image = Image.open(io.BytesIO(screenshot)).convert("RGB")
        image.load()
    except Exception as exc:
        raise BrowserPreparationError("unable to decode screenshot for local visual sanitization") from exc

    rects = _redaction_rectangles(metadata, context, image)
    draw = ImageDraw.Draw(image)
    for x0, y0, x1, y1 in rects:
        draw.rectangle((x0, y0, x1, y1), fill=(18, 18, 20))

    out = io.BytesIO()
    mime = "image/webp"
    try:
        image.save(out, format="WEBP", quality=86, method=4, exact=True)
    except Exception:
        out = io.BytesIO()
        image.save(out, format="PNG", optimize=True)
        mime = "image/png"
    sanitized = out.getvalue()
    if not sanitized:
        raise BrowserPreparationError("sanitized visual context encoded to an empty image")
    encoded = base64.b64encode(sanitized).decode("ascii")
    visual = BrowserPublicVisualContext(
        mime_type=mime,
        width=image.width,
        height=image.height,
        image_base64=encoded,
        sanitized_sha256=hashlib.sha256(sanitized).hexdigest(),
        redacted_regions=len(rects),
    )
    return visual, sanitized, tuple(rects)


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
    tokens = _task_tokens(task)
    released = set(re.findall(r"[a-z0-9]+", " ".join(f"{e.label} {e.text} {e.role}" for e in elements).casefold()))
    coverage = 1.0 if not tokens else len(tokens & released) / max(1, len(tokens))
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

    replacements, sensitive_values, direct_values, policy_actions = _replacement_map(context.detections, effective_level, context.audience)
    secret_values = _sensitive_element_values(metadata)
    all_sensitive_values = tuple(dict.fromkeys((*sensitive_values, *secret_values)))
    all_direct_values = tuple(dict.fromkeys((*direct_values, *secret_values)))

    sanitized_task = _sanitize_text(metadata.task, replacements, secret_values)[:1000]
    top_frame = next((frame for frame in metadata.frames if frame.is_top_frame), metadata.frames[0])
    sanitized_title = _sanitize_text(top_frame.title, replacements, secret_values)[:256]
    elements, anchors = _public_elements(metadata, sanitized_task, replacements, secret_values)
    visual_context, sanitized_image, redaction_rects = _sanitize_visual_context(screenshot, metadata, context)

    raw_semantic = _semantic_size(metadata)
    released_semantic = _released_semantic_size(sanitized_task, sanitized_title, elements)
    minimization = max(0, min(10_000, round((1.0 - min(1.0, released_semantic / raw_semantic)) * 10_000)))
    task_utility = _task_utility_score(sanitized_task, elements, anchors)
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
        minimization_basis_points=minimization,
    )

    evidence = BrowserSanitizationEvidence(
        metadata=metadata,
        context=context,
        payload=payload,
        sanitized_image_bytes=sanitized_image,
        sensitive_values=all_sensitive_values,
        direct_sensitive_values=all_direct_values,
        redaction_rects=redaction_rects,
        raw_element_count=sum(len(frame.elements) for frame in metadata.frames),
        released_element_count=len(elements),
        relevant_anchor_count=anchors,
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
        verification=verification,
        authorization=authorization,
    )
