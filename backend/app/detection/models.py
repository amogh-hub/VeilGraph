from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import DetectionSource, EntityType, ReviewStatus, SensitivityLevel, TransformationType


@dataclass(frozen=True)
class DetectedMention:
    entity_type: EntityType
    plaintext: str
    page_index: int
    page_char_start: int
    page_char_end: int
    rect: tuple[float, float, float, float]
    confidence: float
    source: DetectionSource
    sensitivity: SensitivityLevel
    transformation: TransformationType
    review_status: ReviewStatus = ReviewStatus.NOT_REQUIRED
    context_label: str | None = None
