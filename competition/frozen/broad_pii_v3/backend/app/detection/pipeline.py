from __future__ import annotations

from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import detect_direct_identifiers, normalize_value
from app.detection.broad_pii import detect_broad_pii
from app.detection.models import DetectedMention
from app.detection.person_names import detect_person_name_candidates
from app.detection.quasi_identifiers import detect_quasi_identifiers
from app.detection.semantic_ner import detect_semantic_entities
from app.detection.visual_detector import detect_visual_entities
from app.extraction.document_processor import ProcessedDocument


_PRIORITY = {
    EntityType.PAN_LIKE: 0,
    EntityType.AADHAAR_LIKE: 0,
    EntityType.EMAIL: 0,
    EntityType.DATE_OF_BIRTH: 0,
    EntityType.POSTCODE: 0,
    EntityType.CASE_REFERENCE: 0,
    EntityType.NATIONAL_ID: 0,
    EntityType.PASSPORT_NUMBER: 0,
    EntityType.DRIVER_LICENSE_NUMBER: 0,
    EntityType.TAX_IDENTIFIER: 0,
    EntityType.SOCIAL_IDENTIFIER: 0,
    EntityType.PAYMENT_CARD_NUMBER: 0,
    EntityType.PERSON_NAME: 1,
    EntityType.PERSON_TITLE: 1,
    EntityType.GENERIC_DATE: 1,
    EntityType.DEMOGRAPHIC_ATTRIBUTE: 1,
    EntityType.BUILDING_NUMBER: 1,
    EntityType.PHONE: 2,
}


def _containment_ratio(inner: tuple[float, float, float, float], outer: tuple[float, float, float, float]) -> float:
    ax0, ay0, ax1, ay1 = inner
    bx0, by0, bx1, by1 = outer
    ix0, iy0 = max(ax0, bx0), max(ay0, by0)
    ix1, iy1 = min(ax1, bx1), min(ay1, by1)
    intersection = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
    area_inner = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0)
    return intersection / area_inner if area_inner else 0.0


def _is_v3_candidate(item: DetectedMention) -> bool:
    return bool((item.context_label or "").startswith("broad-pii-v3:"))


def _iou(first: tuple[float, float, float, float], second: tuple[float, float, float, float]) -> float:
    ax0, ay0, ax1, ay1 = first
    bx0, by0, bx1, by1 = second
    ix0, iy0 = max(ax0, bx0), max(ay0, by0)
    ix1, iy1 = min(ax1, bx1), min(ay1, by1)
    intersection = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
    if intersection <= 0:
        return 0.0
    area_a = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0)
    area_b = max(0.0, bx1 - bx0) * max(0.0, by1 - by0)
    union = area_a + area_b - intersection
    return intersection / union if union else 0.0


def detect_all(document: ProcessedDocument) -> list[DetectedMention]:
    candidates = (
        detect_direct_identifiers(document)
        + detect_broad_pii(document)
        + detect_person_name_candidates(document)
        + detect_quasi_identifiers(document)
        + detect_semantic_entities(document)
        + ([] if document.file_type in {FileType.TEXT, FileType.DATASET} else detect_visual_entities(document))
    )
    accepted: list[DetectedMention] = []
    ordered = sorted(
        candidates,
        key=lambda item: (
            item.page_index,
            item.rect[1],
            item.rect[0],
            _PRIORITY.get(item.entity_type, 1),
            1 if _is_v3_candidate(item) else 0,
            -item.confidence,
        ),
    )
    for candidate in ordered:
        duplicate_index = None
        conflict = False
        for index, existing in enumerate(accepted):
            if existing.page_index != candidate.page_index:
                continue
            overlap = _iou(existing.rect, candidate.rect)
            if existing.entity_type == candidate.entity_type:
                same_value = normalize_value(candidate.entity_type, candidate.plaintext) == normalize_value(
                    existing.entity_type, existing.plaintext
                )
                if same_value and overlap >= 0.35:
                    duplicate_index = index
                    break
            # Broad-v3 decomposes previously unseen compound addresses into building,
            # street, locality and postcode components. When an established detector
            # already owns a larger STREET_ADDRESS span, those components are not
            # additional independent mentions: keeping both creates overlapping
            # transformations and can make the release manifest unverifiable. Prefer
            # the established full-address span and use v3 only to fill coverage gaps.
            if (
                _is_v3_candidate(candidate)
                and existing.entity_type == EntityType.STREET_ADDRESS
                and not _is_v3_candidate(existing)
                and candidate.entity_type in {
                    EntityType.BUILDING_NUMBER, EntityType.STREET_ADDRESS,
                    EntityType.LOCALITY, EntityType.POSTCODE,
                }
                and _containment_ratio(candidate.rect, existing.rect) >= 0.80
            ):
                conflict = True
                break
            # Generic-date coverage must never override the more specific birth-date detector.
            if candidate.entity_type == EntityType.GENERIC_DATE and existing.entity_type == EntityType.DATE_OF_BIRTH and overlap >= 0.45:
                conflict = True
                break
            if candidate.entity_type == EntityType.BUILDING_NUMBER and existing.entity_type == EntityType.STREET_ADDRESS and overlap >= 0.75:
                conflict = True
                break
            # Broad phone patterns must not override a label/context-anchored identifier
            # occupying the same region.
            if candidate.entity_type == EntityType.PHONE and existing.entity_type in {
                EntityType.DATE_OF_BIRTH,
                EntityType.POSTCODE,
                EntityType.CASE_REFERENCE,
                EntityType.AADHAAR_LIKE,
                EntityType.PAN_LIKE,
                EntityType.NATIONAL_ID,
                EntityType.PASSPORT_NUMBER,
                EntityType.DRIVER_LICENSE_NUMBER,
                EntityType.TAX_IDENTIFIER,
                EntityType.SOCIAL_IDENTIFIER,
                EntityType.PAYMENT_CARD_NUMBER,
            } and overlap >= 0.45:
                conflict = True
                break
        if conflict:
            continue
        if duplicate_index is None:
            accepted.append(candidate)
        elif candidate.confidence > accepted[duplicate_index].confidence:
            accepted[duplicate_index] = candidate
    return accepted
