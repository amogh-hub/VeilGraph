from __future__ import annotations

from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import detect_direct_identifiers, normalize_value
from app.detection.broad_pii import detect_broad_pii
from app.detection.contextual_v4 import detect_contextual_v4
from app.detection.generalization_v5 import detect_generalization_v5
from app.detection.models import DetectedMention
from app.detection.person_names import detect_person_name_candidates
from app.detection.quasi_identifiers import detect_quasi_identifiers
from app.detection.semantic_ner import detect_semantic_entities
from app.detection.semantic_ner_v2 import detect_semantic_entities_v2
from app.detection.semantic_ner_v3 import detect_semantic_entities_v3
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


def _is_v4_candidate(item: DetectedMention) -> bool:
    return bool((item.context_label or "").startswith("broad-pii-v4:"))


def _is_v5_candidate(item: DetectedMention) -> bool:
    label = item.context_label or ""
    return label.startswith("broad-pii-v5:") or label.startswith("semantic-ner-v3:")


def _is_v4_authoritative_field(item: DetectedMention) -> bool:
    label = item.context_label or ""
    return any(label.startswith(prefix) for prefix in (
        "broad-pii-v4:field:", "broad-pii-v4:inline-field:",
        "broad-pii-v4:adjacent-field:", "broad-pii-v4:key-value:",
    ))


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
        detect_generalization_v5(document)
        + detect_semantic_entities_v3(document)
        + detect_contextual_v4(document)
        + detect_direct_identifiers(document)
        + detect_broad_pii(document)
        + detect_person_name_candidates(document)
        + detect_quasi_identifiers(document)
        + detect_semantic_entities(document)
        + detect_semantic_entities_v2(document)
        + ([] if document.file_type in {FileType.TEXT, FileType.DATASET} else detect_visual_entities(document))
    )
    accepted: list[DetectedMention] = []
    ordered = sorted(
        candidates,
        key=lambda item: (
            item.page_index,
            item.rect[1],
            item.rect[0],
            0 if _is_v4_authoritative_field(item) else 1,
            _PRIORITY.get(item.entity_type, 1),
            1 if _is_v5_candidate(item) else 0,
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
            char_intersection = max(
                0,
                min(existing.page_char_end, candidate.page_char_end)
                - max(existing.page_char_start, candidate.page_char_start),
            )
            if existing.entity_type == candidate.entity_type:
                same_value = normalize_value(candidate.entity_type, candidate.plaintext) == normalize_value(
                    existing.entity_type, existing.plaintext
                )
                if same_value and overlap >= 0.35:
                    duplicate_index = index
                    break
                # A broader v5 address must not replace the established structural
                # street span (building/locality/postcode remain separate evidence).
                if (
                    candidate.entity_type == EntityType.STREET_ADDRESS
                    and _is_v5_candidate(candidate)
                    and not _is_v5_candidate(existing)
                    and char_intersection > 0
                ):
                    conflict = True
                    break
                # A context-anchored v5 person/org/place may compete with a legacy
                # over-long span of the same class. Any shared source characters
                # indicate the same mention family; let v5 replace the legacy span.
                if char_intersection > 0 and _is_v5_candidate(candidate) and not _is_v5_candidate(existing):
                    duplicate_index = index
                    break
                if char_intersection > 0 and _is_v5_candidate(existing) and not _is_v5_candidate(candidate):
                    if candidate.entity_type == EntityType.STREET_ADDRESS:
                        duplicate_index = index
                        break
                    conflict = True
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
            # v4 field/header semantics are authoritative for a cell/labelled span.
            # They prevent a value under e.g. employer.name from also becoming a
            # generic PERSON_NAME candidate.  A human may still review the chosen
            # semantic type, but the pipeline must not apply two conflicting
            # transformations to the same source span.
            if (
                _is_v4_authoritative_field(existing)
                and not _is_v4_authoritative_field(candidate)
                and existing.entity_type != candidate.entity_type
                and overlap >= 0.72
            ):
                conflict = True
                break

            # Existing structural street spans remain authoritative over a
            # broader v5 labelled-address span. This preserves the non-overlapping
            # building/street/locality/postcode representation used by transforms.
            if (
                _is_v5_candidate(candidate)
                and candidate.entity_type == EntityType.STREET_ADDRESS
                and existing.entity_type == EntityType.STREET_ADDRESS
                and not _is_v5_candidate(existing)
                and _containment_ratio(existing.rect, candidate.rect) >= 0.70
            ):
                conflict = True
                break

            # v5 semantic spans must not override a structured/high-specificity identifier
            # already occupying the same evidence region. This keeps high-recall prose
            # NER from reclassifying a passport/card/reference as a person or place.
            if (
                _is_v5_candidate(candidate)
                and existing.entity_type in {
                    EntityType.EMAIL, EntityType.PHONE, EntityType.AADHAAR_LIKE, EntityType.PAN_LIKE,
                    EntityType.DATE_OF_BIRTH, EntityType.POSTCODE, EntityType.CASE_REFERENCE,
                    EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER, EntityType.DRIVER_LICENSE_NUMBER,
                    EntityType.TAX_IDENTIFIER, EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
                }
                and candidate.entity_type != existing.entity_type
                and char_intersection > 0
                and overlap >= 0.55
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

    # v5 may intentionally nominate a tighter semantic span inside a legacy
    # over-long candidate (for example ``Dr. Alice Brown`` vs ``Alice Brown``).
    # The pairwise loop above can replace only the first conflicting legacy span;
    # remove any remaining same-class legacy duplicates that share source chars.
    v5_items = [item for item in accepted if _is_v5_candidate(item)]
    if v5_items:
        filtered: list[DetectedMention] = []
        for item in accepted:
            if _is_v5_candidate(item):
                # Structural STREET_ADDRESS decomposition remains authoritative.
                if item.entity_type == EntityType.STREET_ADDRESS and any(
                    other.entity_type == EntityType.STREET_ADDRESS
                    and not _is_v5_candidate(other)
                    and other.page_index == item.page_index
                    and max(0, min(other.page_char_end, item.page_char_end) - max(other.page_char_start, item.page_char_start)) > 0
                    for other in accepted
                ):
                    continue
                filtered.append(item)
                continue
            shadowed = any(
                v5.entity_type == item.entity_type
                and v5.entity_type != EntityType.STREET_ADDRESS
                and v5.page_index == item.page_index
                and max(0, min(v5.page_char_end, item.page_char_end) - max(v5.page_char_start, item.page_char_start)) > 0
                for v5 in v5_items
            )
            if not shadowed:
                filtered.append(item)
        accepted = filtered
    return accepted
