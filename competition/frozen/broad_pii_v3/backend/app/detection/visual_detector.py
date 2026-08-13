from __future__ import annotations

import re

import cv2

cv2.setNumThreads(1)
import numpy as np
from PIL import Image

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType
from app.detection.models import DetectedMention
from app.extraction.document_processor import PageFrame, ProcessedDocument


def _page_rect_from_pixels(page: PageFrame, rect: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = rect
    scale_x = page.width / page.image.width
    scale_y = page.height / page.image.height
    return (x0 * scale_x, y0 * scale_y, x1 * scale_x, y1 * scale_y)


def _qr_detections(page: PageFrame) -> list[DetectedMention]:
    rgb = np.array(page.image.convert("RGB"))
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    detections: list[DetectedMention] = []

    decoded_values: list[str] = []
    polygons: list[np.ndarray] = []
    try:
        ok, decoded_info, points, _ = detector.detectAndDecodeMulti(bgr)
        if ok and points is not None:
            decoded_values = list(decoded_info)
            polygons = [np.asarray(item) for item in points]
    except cv2.error:
        pass

    if not polygons:
        try:
            decoded, points, _ = detector.detectAndDecode(bgr)
            if points is not None:
                decoded_values = [decoded]
                polygons = [np.asarray(points)]
        except cv2.error:
            pass

    for index, polygon in enumerate(polygons):
        points = polygon.reshape(-1, 2)
        x0, y0 = points.min(axis=0)
        x1, y1 = points.max(axis=0)
        padding = 5.0
        rect_pixels = (
            max(0.0, float(x0) - padding),
            max(0.0, float(y0) - padding),
            min(float(page.image.width), float(x1) + padding),
            min(float(page.image.height), float(y1) + padding),
        )
        decoded = decoded_values[index].strip() if index < len(decoded_values) else ""
        # OpenCV can occasionally return a polygon even when no QR payload was
        # decoded. Treat those geometry-only detections as review candidates,
        # never as automatic redactions. This prevents an empty/false polygon
        # from destroying unrelated document content.
        review_status = ReviewStatus.NOT_REQUIRED if decoded else ReviewStatus.PENDING
        detections.append(
            DetectedMention(
                entity_type=EntityType.QR_CODE,
                plaintext=decoded or f"UNDECODED_QR_CANDIDATE_PAGE_{page.page_index}_{index}",
                page_index=page.page_index,
                page_char_start=-1,
                page_char_end=-1,
                rect=_page_rect_from_pixels(page, rect_pixels),
                confidence=0.98 if decoded else 0.55,
                source=DetectionSource.VISUAL,
                sensitivity=SensitivityLevel.HIGH,
                transformation=TransformationType.REMOVE_REGION,
                review_status=review_status,
            )
        )
    return detections


def _face_detections(page: PageFrame) -> list[DetectedMention]:
    rgb = np.array(page.image.convert("RGB"))
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(cascade_path)
    if cascade.empty():
        return []
    faces = cascade.detectMultiScale(
        gray,
        scaleFactor=1.12,
        minNeighbors=5,
        minSize=(42, 42),
        flags=cv2.CASCADE_SCALE_IMAGE,
    )
    detections: list[DetectedMention] = []
    for index, (x, y, width, height) in enumerate(faces):
        padding_x = width * 0.08
        padding_y = height * 0.08
        rect_pixels = (
            max(0.0, x - padding_x),
            max(0.0, y - padding_y),
            min(float(page.image.width), x + width + padding_x),
            min(float(page.image.height), y + height + padding_y),
        )
        page_rect = _page_rect_from_pixels(page, rect_pixels)
        px0, py0, px1, py1 = page_rect
        candidate_area = max(1.0, (px1 - px0) * (py1 - py0))
        overlaps_text = False
        for line in page.lines:
            for token in line.tokens:
                ix0, iy0 = max(px0, token.x0), max(py0, token.y0)
                ix1, iy1 = min(px1, token.x1), min(py1, token.y1)
                overlap = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
                if overlap / candidate_area >= 0.10:
                    overlaps_text = True
                    break
            if overlaps_text:
                break
        if overlaps_text:
            continue
        detections.append(
            DetectedMention(
                entity_type=EntityType.FACE,
                plaintext=f"FACE_PAGE_{page.page_index}_{index}",
                page_index=page.page_index,
                page_char_start=-1,
                page_char_end=-1,
                rect=page_rect,
                confidence=0.72,
                source=DetectionSource.VISUAL,
                sensitivity=SensitivityLevel.HIGH,
                transformation=TransformationType.REMOVE_REGION,
                review_status=ReviewStatus.PENDING,
            )
        )
    return detections


def _signature_candidates(page: PageFrame) -> list[DetectedMention]:
    keyword_lines = [
        line for line in page.lines
        if re.search(r"\b(signature|signed|signatory)\b", line.text, re.IGNORECASE)
    ]
    if not keyword_lines:
        return []

    image = np.array(page.image.convert("RGB"))
    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
    scale_x = page.image.width / page.width
    scale_y = page.image.height / page.height
    detections: list[DetectedMention] = []

    for candidate_index, line in enumerate(keyword_lines):
        if not line.tokens:
            continue
        label_x0 = min(token.x0 for token in line.tokens)
        label_y1 = max(token.y1 for token in line.tokens)
        # Label-assisted region: below the label, extending across most of the line.
        x0 = max(0, int(label_x0 * scale_x))
        y0 = max(0, int((label_y1 + 2) * scale_y))
        x1 = min(page.image.width, int((page.width - 24) * scale_x))
        y1 = min(page.image.height, int((label_y1 + 70) * scale_y))
        if x1 <= x0 or y1 <= y0:
            continue
        crop = gray[y0:y1, x0:x1]
        binary = cv2.threshold(crop, 200, 255, cv2.THRESH_BINARY_INV)[1]
        contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        useful = []
        for contour in contours:
            bx, by, bw, bh = cv2.boundingRect(contour)
            area = cv2.contourArea(contour)
            if area >= 4 and bw >= 4 and bh >= 2:
                useful.append((bx, by, bw, bh))
        if not useful:
            continue
        min_x = min(item[0] for item in useful)
        min_y = min(item[1] for item in useful)
        max_x = max(item[0] + item[2] for item in useful)
        max_y = max(item[1] + item[3] for item in useful)
        width = max_x - min_x
        height = max_y - min_y
        ink_pixels = int((binary > 0).sum())
        if width < 55 or height < 8 or ink_pixels < 120:
            continue
        rect_pixels = (
            float(x0 + min_x - 4),
            float(y0 + min_y - 4),
            float(x0 + max_x + 4),
            float(y0 + max_y + 4),
        )
        detections.append(
            DetectedMention(
                entity_type=EntityType.SIGNATURE_CANDIDATE,
                plaintext=f"SIGNATURE_CANDIDATE_PAGE_{page.page_index}_{candidate_index}",
                page_index=page.page_index,
                page_char_start=-1,
                page_char_end=-1,
                rect=_page_rect_from_pixels(page, rect_pixels),
                confidence=0.68,
                source=DetectionSource.VISUAL,
                sensitivity=SensitivityLevel.HIGH,
                transformation=TransformationType.REMOVE_REGION,
                review_status=ReviewStatus.PENDING,
            )
        )
    return detections


def detect_visual_entities(document: ProcessedDocument) -> list[DetectedMention]:
    detections: list[DetectedMention] = []
    for page in document.pages:
        detections.extend(_qr_detections(page))
        detections.extend(_face_detections(page))
        detections.extend(_signature_candidates(page))
    return detections
