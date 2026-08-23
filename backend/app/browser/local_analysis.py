from __future__ import annotations

import hashlib
import io
import json
import shutil
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

import cv2
from PIL import Image

from app.browser.models import (
    BrowserDetectionSummary,
    BrowserLocalAnalysisResponse,
    BrowserLocalCaptureMetadata,
    BrowserVisualCapability,
)
from app.core.enums import AudienceProfile, DetectionSource, EntityType, FileType, PrivacyLevel, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.direct_identifiers import normalize_value
from app.detection.models import DetectedMention
from app.detection.pipeline import detect_all
from app.extraction.document_processor import PageFrame, PositionedLine, PositionedToken, ProcessedDocument, process_document
from app.graph.exposure_graph import build_exposure_graph
from app.security.signing import canonical_json_bytes


class BrowserAnalysisError(ValueError):
    pass


@dataclass(frozen=True)
class BrowserAnalysisContext:
    document: ProcessedDocument
    detections: tuple[DetectedMention, ...]
    entities: list[dict[str, Any]]
    mentions_by_entity: dict[str, list[dict[str, Any]]]
    audience: AudienceProfile
    level: PrivacyLevel
    graph: dict[str, Any]
    companion_status: str
    companion_capabilities: list[BrowserVisualCapability]


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
    """Fuse screenshot OCR with DOM/accessibility semantics on-device.

    The visible top-level screenshot is independently OCRed by the local
    companion. DOM/accessibility text is then added as a second semantic view.
    This deliberately preserves two independent evidence channels instead of
    treating browser DOM extraction as proof that canvas/PDF/iframe pixels are
    safe.
    """
    try:
        visual_document = process_document(screenshot, FileType.IMAGE, "browser-visible-capture.png")
    except Exception as exc:
        raise BrowserAnalysisError("browser screenshot local OCR/visual decoding failed") from exc
    if not visual_document.pages:
        raise BrowserAnalysisError("browser screenshot produced no visual page")

    visual_page = visual_document.pages[0]
    pages: list[PageFrame] = []
    for page_index, frame in enumerate(metadata.frames):
        if frame.is_top_frame:
            page_image = visual_page.image.copy()
            lines: list[PositionedLine] = list(visual_page.lines)
            used_ocr = True
        else:
            page_image = Image.new("RGB", (frame.viewport_width, frame.viewport_height), "white")
            lines = []
            used_ocr = False

        page_width, page_height = page_image.size
        running_offset = sum(len(line.text) + 1 for line in lines)
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
                used_ocr=used_ocr,
            )
        )
    return ProcessedDocument(
        file_type=FileType.IMAGE,
        pages=tuple(pages),
        page_count=len(pages),
        scanned_pages=1,
        metadata={
            "source": "browser-local-capture",
            "browser_visual_perception_status": metadata.visual_perception_status,
            "local_companion_ocr": True,
        },
    )


def _companion_visual_capabilities(document: ProcessedDocument) -> tuple[str, list[BrowserVisualCapability]]:
    capabilities: list[BrowserVisualCapability] = []
    capabilities.append(
        BrowserVisualCapability(
            name="SCREENSHOT_DECODE", status="READY", backend="local-companion-pillow", required=True,
            detail="Visible browser screenshot decoded locally in the VeilGraph companion",
        )
    )
    ocr_ready = shutil.which("tesseract") is not None and any(page.used_ocr for page in document.pages)
    capabilities.append(
        BrowserVisualCapability(
            name="OCR_TEXT_EXTRACTION", status="READY" if ocr_ready else "UNAVAILABLE", backend="local-companion-tesseract", required=True,
            detail="Independent local screenshot OCR executed" if ocr_ready else "Tesseract OCR is unavailable",
        )
    )
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(cascade_path)
    face_ready = not cascade.empty()
    capabilities.append(
        BrowserVisualCapability(
            name="FACE_DETECTION", status="READY" if face_ready else "UNAVAILABLE", backend="local-companion-opencv-haar", required=True,
            detail="OpenCV local face detector loaded" if face_ready else "OpenCV face cascade is unavailable",
        )
    )
    try:
        detector = cv2.QRCodeDetector()
        qr_ready = detector is not None
    except Exception:
        qr_ready = False
    capabilities.append(
        BrowserVisualCapability(
            name="QR_DETECTION", status="READY" if qr_ready else "UNAVAILABLE", backend="local-companion-opencv-qr", required=True,
            detail="OpenCV local QR detector loaded" if qr_ready else "OpenCV QR detector is unavailable",
        )
    )
    capabilities.append(
        BrowserVisualCapability(
            name="TEXT_REGION_DETECTION", status="READY" if ocr_ready else "UNAVAILABLE", backend="local-companion-tesseract", required=True,
            detail="OCR word geometry supplies local visual text regions" if ocr_ready else "Visual text-region geometry unavailable",
        )
    )
    capabilities.append(
        BrowserVisualCapability(
            name="DOM_SENSITIVE_PROJECTION", status="READY", backend="browser-dom-fusion", required=True,
            detail="DOM/accessibility sensitive fields are fused with screenshot geometry",
        )
    )
    required = [item for item in capabilities if item.required]
    if required and all(item.status == "READY" for item in required):
        return "READY", capabilities
    if any(item.status == "READY" for item in required):
        return "PARTIAL", capabilities
    return "UNAVAILABLE", capabilities


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
                context_label=f"browser-local-vision:{finding.provider or 'unknown'}",
            )
        )
    return result



def _rect_overlap_ratio(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
) -> float:
    lx0, ly0, lx1, ly1 = left
    rx0, ry0, rx1, ry1 = right
    ix0, iy0 = max(lx0, rx0), max(ly0, ry0)
    ix1, iy1 = min(lx1, rx1), min(ly1, ry1)
    intersection = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
    area = max(1.0, (lx1 - lx0) * (ly1 - ly0))
    return intersection / area


def _filter_browser_label_false_positives(
    detections: list[DetectedMention],
    metadata: BrowserLocalCaptureMetadata,
    document: ProcessedDocument,
) -> list[DetectedMention]:
    """Suppress detector hits that are clearly UI field labels, not values.

    Browser forms repeatedly contain words such as ``Email``, ``Location`` and
    ``Password``. Treating those labels as person/location entities inflates the
    Identity Exposure Graph and can corrupt policy replacements. A hit is only
    suppressed when it is text-layer evidence spatially bound to a control whose
    distinct raw value is captured separately and the detected plaintext equals
    the label/visible UI text rather than that value.
    """
    if not document.pages:
        return detections
    result: list[DetectedMention] = []
    for detection in detections:
        if detection.source != DetectionSource.TEXT_LAYER or detection.page_index >= len(metadata.frames):
            result.append(detection)
            continue
        frame = metadata.frames[detection.page_index]
        page = document.pages[detection.page_index]
        detected = detection.plaintext.strip().casefold()
        suppress = False
        for element in frame.elements:
            raw = (element.raw_value or "").strip()
            if not raw:
                continue
            labels = {
                element.accessible_name.strip().casefold(),
                element.visible_text.strip().casefold(),
            } - {""}
            if detected not in labels or detected == raw.casefold():
                continue
            element_rect = _pixel_bbox(element.bbox, int(page.width), int(page.height))
            if _rect_overlap_ratio(detection.rect, element_rect) >= 0.75:
                suppress = True
                break
        if not suppress:
            result.append(detection)
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


def build_browser_analysis_context(
    metadata: BrowserLocalCaptureMetadata,
    screenshot: bytes,
    *,
    level_override: PrivacyLevel | None = None,
) -> BrowserAnalysisContext:
    if not screenshot:
        raise BrowserAnalysisError("browser screenshot is empty")
    document = _make_processed_document(metadata, screenshot)
    companion_status, companion_capabilities = _companion_visual_capabilities(document)
    detections = detect_all(document)
    detections = _merge_browser_visual_findings(detections, metadata, document)
    detections = _filter_browser_label_false_positives(detections, metadata, document)
    entities, mentions_by_entity = _canonical_rows(detections)

    try:
        audience = AudienceProfile(metadata.audience_profile)
        level = level_override or PrivacyLevel(metadata.requested_privacy_level)
    except ValueError as exc:
        raise BrowserAnalysisError("unsupported browser audience/privacy level") from exc

    top_frame = next((frame for frame in metadata.frames if frame.is_top_frame), metadata.frames[0])
    job = {
        "id": "browser-local",
        "audience_profile": audience.value,
        "privacy_level": int(level),
    }
    file_row = {
        "id": "browser-capture",
        "file_type": FileType.IMAGE.value,
        "original_filename": top_frame.origin,
        "page_count": document.page_count,
    }
    graph = build_exposure_graph(job, file_row, entities, mentions_by_entity, level)
    return BrowserAnalysisContext(
        document=document,
        detections=tuple(detections),
        entities=entities,
        mentions_by_entity=mentions_by_entity,
        audience=audience,
        level=level,
        graph=graph,
        companion_status=companion_status,
        companion_capabilities=companion_capabilities,
    )


def browser_analysis_response_from_context(
    metadata: BrowserLocalCaptureMetadata,
    screenshot: bytes,
    context: BrowserAnalysisContext,
    *,
    started: float | None = None,
) -> BrowserLocalAnalysisResponse:
    started_at = started if started is not None else time.perf_counter()
    detections = list(context.detections)
    graph = context.graph

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

    browser_status = metadata.visual_perception_status
    overall_visual_status = "READY" if context.companion_status == "READY" else browser_status
    if overall_visual_status != "READY":
        readiness = "VISUAL_COVERAGE_INCOMPLETE"
    elif pending:
        readiness = "NEEDS_REVIEW"
    else:
        readiness = "READY_FOR_SANITIZATION"

    browser_capabilities = list(metadata.visual_perception_report.capabilities) if metadata.visual_perception_report else []
    visual_capabilities = browser_capabilities + context.companion_capabilities
    ocr_lines = sum(
        line.source == DetectionSource.OCR
        for page in context.document.pages
        for line in page.lines
    )
    visual_findings_count = sum(item.source == DetectionSource.VISUAL for item in detections)

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
        browser_visual_perception_status=browser_status,
        local_companion_visual_status=context.companion_status,
        visual_perception_status=overall_visual_status,
        visual_capabilities=visual_capabilities,
        ocr_lines=ocr_lines,
        visual_findings_count=visual_findings_count,
        capture_id=metadata.capture_id,
        expected_frames=metadata.expected_frame_count or len(metadata.frames),
        captured_frames=metadata.captured_frame_count or len(metadata.frames),
        failed_frames=len(set(metadata.failed_frame_ids)),
        capture_timings=metadata.capture_timings,
        browser_capture_coverage=metadata.coverage,
        readiness=readiness,
        note=(
            "Local multimodal analysis only. Browser-native perception is independently fused with localhost OCR/OpenCV coverage; "
            "viewport geometry, capture completeness and stage timings remain explicit evidence. Raw screenshot/DOM data remains on-device. "
            "This response does not authorize external transmission. A sanitized payload must still pass the Browser Privacy Red Team and signed Network Release Gate. "
            f"Analysis elapsed {int((time.perf_counter() - started_at) * 1000)} ms."
        ),
    )


def analyse_browser_capture(metadata: BrowserLocalCaptureMetadata, screenshot: bytes) -> BrowserLocalAnalysisResponse:
    started = time.perf_counter()
    context = build_browser_analysis_context(metadata, screenshot)
    return browser_analysis_response_from_context(metadata, screenshot, context, started=started)
