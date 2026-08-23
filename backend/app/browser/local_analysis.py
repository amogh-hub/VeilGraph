from __future__ import annotations

import hashlib
import io
import json
import uuid
from collections import Counter, defaultdict
from typing import Any

from PIL import Image

from app.browser.models import (
    BrowserDetectionSummary,
    BrowserLocalAnalysisResponse,
    BrowserLocalCaptureMetadata,
)
from app.core.enums import AudienceProfile, DetectionSource, EntityType, FileType, PrivacyLevel, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.direct_identifiers import normalize_value
from app.detection.models import DetectedMention
from app.detection.pipeline import detect_all
from app.extraction.document_processor import PageFrame, PositionedLine, PositionedToken, ProcessedDocument
from app.graph.exposure_graph import build_exposure_graph
from app.security.signing import canonical_json_bytes


class BrowserAnalysisError(ValueError):
    pass


def _pixel_bbox(bbox: tuple[int, int, int, int], width: int, height: int) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = bbox
    return (
        width * x0 / 10_000.0,
        height * y0 / 10_000.0,
        width * x1 / 10_000.0,
        height * y1 / 10_000.0,
    )


def _tokens_for_line(text: str, rect: tuple[float, float, float, float]) -> tuple[PositionedToken, ...]:
    parts = text.split()
    if not parts:
        return ()
    x0, y0, x1, y1 = rect
    width = max(1.0, x1 - x0)
    total_units = max(1, sum(len(part) for part in parts) + max(0, len(parts) - 1))
    cursor = x0
    tokens: list[PositionedToken] = []
    for part in parts:
        fraction = max(1, len(part)) / total_units
        token_width = width * fraction
        tokens.append(PositionedToken(part, cursor, y0, min(x1, cursor + token_width), y1, 1.0))
        cursor += token_width + width / total_units
    return tuple(tokens)


def _semantic_text(element) -> str:
    values: list[str] = []
    if element.accessible_name.strip():
        values.append(element.accessible_name.strip())
    if element.visible_text.strip() and element.visible_text.strip() not in values:
        values.append(element.visible_text.strip())
    if element.raw_value is not None and element.raw_value.strip():
        label = element.accessible_name.strip() or element.role
        values.append(f"{label}: {element.raw_value.strip()}")
    return " | ".join(values)[:4096]


def _make_processed_document(metadata: BrowserLocalCaptureMetadata, screenshot: bytes) -> ProcessedDocument:
    try:
        image = Image.open(io.BytesIO(screenshot)).convert("RGB")
        image.load()
    except Exception as exc:
        raise BrowserAnalysisError("browser screenshot is not a decodable image") from exc

    pages: list[PageFrame] = []
    for page_index, frame in enumerate(metadata.frames):
        page_image = image.copy() if frame.is_top_frame else Image.new("RGB", (frame.viewport_width, frame.viewport_height), "white")
        page_width, page_height = page_image.size
        lines: list[PositionedLine] = []
        running_offset = 0
        for element in frame.elements:
            text = _semantic_text(element)
            if not text:
                continue
            rect = _pixel_bbox(element.bbox, page_width, page_height)
            tokens = _tokens_for_line(text, rect)
            lines.append(
                PositionedLine(
                    text=text,
                    tokens=tokens,
                    source=DetectionSource.TEXT_LAYER,
                    page_index=page_index,
                    page_char_start=running_offset,
                )
            )
            running_offset += len(text) + 1
        pages.append(
            PageFrame(
                page_index=page_index,
                width=float(page_width),
                height=float(page_height),
                image=page_image,
                lines=tuple(lines),
                used_ocr=False,
            )
        )
    return ProcessedDocument(
        file_type=FileType.IMAGE,
        pages=tuple(pages),
        page_count=len(pages),
        scanned_pages=0,
        metadata={"source": "browser-local-capture", "visual_perception_status": metadata.visual_perception_status},
    )


def _merge_browser_visual_findings(
    detections: list[DetectedMention],
    metadata: BrowserLocalCaptureMetadata,
    document: ProcessedDocument,
) -> list[DetectedMention]:
    if not metadata.visual_findings or not document.pages:
        return detections
    page = document.pages[0]
    result = list(detections)
    mapping = {"FACE": EntityType.FACE, "QR_CODE": EntityType.QR_CODE}
    for finding in metadata.visual_findings:
        entity_type = mapping.get(finding.type)
        if entity_type is None:
            continue
        rect = _pixel_bbox(finding.bbox, int(page.width), int(page.height))
        result.append(
            DetectedMention(
                entity_type=entity_type,
                plaintext=f"BROWSER_{finding.type}_{finding.finding_id}",
                page_index=0,
                page_char_start=0,
                page_char_end=0,
                rect=rect,
                confidence=finding.confidence_basis_points / 10_000.0,
                source=DetectionSource.VISUAL,
                sensitivity=SensitivityLevel.HIGH,
                transformation=TransformationType.REMOVE_REGION,
                review_status=ReviewStatus.NOT_REQUIRED,
                context_label="browser-local-vision",
            )
        )
    return result


def _canonical_rows(detections: list[DetectedMention]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    grouped: dict[tuple[EntityType, str], dict[str, Any]] = {}
    mentions_by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    counters: Counter[EntityType] = Counter()

    for detection in detections:
        normalized = (
            detection.plaintext
            if detection.source == DetectionSource.VISUAL
            else normalize_value(detection.entity_type, detection.plaintext)
        )
        key = (detection.entity_type, normalized)
        entity = grouped.get(key)
        if entity is None:
            counters[detection.entity_type] += 1
            entity_id = str(uuid.uuid4())
            entity = {
                "id": entity_id,
                "job_id": "browser-local",
                "file_id": "browser-capture",
                "entity_type": detection.entity_type.value,
                "placeholder": f"{detection.entity_type.value}_{counters[detection.entity_type]:03d}",
                "sensitivity": detection.sensitivity.value,
                "transformation": detection.transformation.value,
                "mention_count": 0,
            }
            grouped[key] = entity
        entity["mention_count"] += 1
        mentions_by_entity[entity["id"]].append(
            {
                "id": str(uuid.uuid4()),
                "canonical_entity_id": entity["id"],
                "page_index": detection.page_index,
                "page_char_start": detection.page_char_start,
                "page_char_end": detection.page_char_end,
                "x0": detection.rect[0],
                "y0": detection.rect[1],
                "x1": detection.rect[2],
                "y1": detection.rect[3],
                "confidence": detection.confidence,
                "source": detection.source.value,
                "review_status": detection.review_status.value,
                "context_label": detection.context_label,
            }
        )
    return list(grouped.values()), mentions_by_entity


def _credential_fields(metadata: BrowserLocalCaptureMetadata) -> int:
    total = 0
    for frame in metadata.frames:
        for element in frame.elements:
            hints = {hint.casefold() for hint in element.privacy_hints}
            input_type = (element.input_type or "").casefold()
            if input_type == "password" or "credential" in hints:
                total += 1
    return total


def analyse_browser_capture(metadata: BrowserLocalCaptureMetadata, screenshot: bytes) -> BrowserLocalAnalysisResponse:
    if not screenshot:
        raise BrowserAnalysisError("browser screenshot is empty")
    document = _make_processed_document(metadata, screenshot)
    detections = detect_all(document)
    detections = _merge_browser_visual_findings(detections, metadata, document)
    entities, mentions_by_entity = _canonical_rows(detections)

    try:
        audience = AudienceProfile(metadata.audience_profile)
        level = PrivacyLevel(metadata.requested_privacy_level)
    except ValueError as exc:
        raise BrowserAnalysisError("unsupported browser audience/privacy level") from exc

    job = {
        "id": "browser-local",
        "audience_profile": audience.value,
        "privacy_level": int(level),
    }
    top_frame = next((frame for frame in metadata.frames if frame.is_top_frame), metadata.frames[0])
    file_row = {
        "id": "browser-capture",
        "file_type": FileType.IMAGE.value,
        "original_filename": top_frame.origin,
        "page_count": document.page_count,
    }
    graph = build_exposure_graph(job, file_row, entities, mentions_by_entity, level)

    by_type: dict[EntityType, list[DetectedMention]] = defaultdict(list)
    for detection in detections:
        by_type[detection.entity_type].append(detection)
    summaries = [
        BrowserDetectionSummary(
            entity_type=entity_type.value,
            mentions=len(items),
            sources=sorted({item.source.value for item in items}),
            pending_review=any(item.review_status == ReviewStatus.PENDING for item in items),
        )
        for entity_type, items in sorted(by_type.items(), key=lambda item: item[0].value)
    ]
    pending = sum(item.review_status == ReviewStatus.PENDING for item in detections)
    credentials = _credential_fields(metadata)
    semantic_elements = sum(len(frame.elements) for frame in metadata.frames)

    # Raw capture commitment is local audit evidence only; it is never part of
    # the external release envelope.
    metadata_payload = metadata.model_dump(mode="json", by_alias=True)
    capture_sha = hashlib.sha256(canonical_json_bytes(metadata_payload)).hexdigest()
    screenshot_sha = hashlib.sha256(screenshot).hexdigest()

    if metadata.visual_perception_status != "READY":
        readiness = "VISUAL_COVERAGE_INCOMPLETE"
    elif pending:
        readiness = "NEEDS_REVIEW"
    else:
        readiness = "READY_FOR_SANITIZATION"

    risk = graph["risk"]
    return BrowserLocalAnalysisResponse(
        capture_sha256=capture_sha,
        screenshot_sha256=screenshot_sha,
        semantic_elements=semantic_elements,
        credential_fields=credentials,
        detections=summaries,
        pending_reviews=pending,
        identity_exposure_graph=graph,
        risk_before=int(risk["before"]),
        residual_risk_preview=int(risk["after"]),
        utility_preview=int(risk["utility_score"]),
        visual_perception_status=metadata.visual_perception_status,
        readiness=readiness,
        note=(
            "Local analysis only. This response does not authorize external transmission. "
            "A sanitized payload must still pass the Browser Privacy Red Team and signed Network Release Gate."
        ),
    )
