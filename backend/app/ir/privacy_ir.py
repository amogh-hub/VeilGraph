from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from PIL import Image

from app.core.enums import DetectionSource, FileType
from app.extraction.document_processor import (
    PageFrame,
    PositionedLine,
    PositionedToken,
    ProcessedDocument,
)

IR_SCHEMA = "veilgraph.privacy-ir.v1"
IRUnitKind = Literal["PAGE", "TEXT", "TABLE", "VIDEO_FRAME"]


@dataclass(frozen=True)
class IRTextSpan:
    """A positioned text span inside the Privacy IR.

    Text is retained only in process memory so downstream privacy detection can
    operate on a format-neutral representation. The public summary and audit
    metadata contain only counts and cryptographic commitments.
    """

    text: str
    tokens: tuple[PositionedToken, ...]
    source: DetectionSource
    unit_index: int
    char_start: int


@dataclass(frozen=True)
class IRUnit:
    """One logical source unit.

    Today document/image inputs normalize to PAGE units. TEXT, TABLE and
    VIDEO_FRAME are reserved by the schema so later adapters can enter the same
    detection / graph / policy / proof pipeline without creating parallel
    privacy engines.
    """

    unit_id: str
    kind: IRUnitKind
    index: int
    width: float
    height: float
    visual: Image.Image
    spans: tuple[IRTextSpan, ...]
    extraction_mode: Literal["TEXT_LAYER", "OCR", "MIXED"]


@dataclass(frozen=True)
class PrivacyIR:
    schema: str
    source_file_type: FileType
    units: tuple[IRUnit, ...]
    scanned_units: int
    commitment_sha256: str
    metadata: dict[str, Any]

    @property
    def unit_count(self) -> int:
        return len(self.units)

    @property
    def span_count(self) -> int:
        return sum(len(unit.spans) for unit in self.units)

    @property
    def token_count(self) -> int:
        return sum(len(span.tokens) for unit in self.units for span in unit.spans)


def _float(value: float) -> str:
    # Stable cross-platform representation for the commitment payload.
    return f"{float(value):.4f}"


def _token_commitment(token: PositionedToken) -> dict[str, Any]:
    return {
        "text_sha256": hashlib.sha256(token.text.encode("utf-8")).hexdigest(),
        "bbox": [_float(token.x0), _float(token.y0), _float(token.x1), _float(token.y1)],
        "confidence": _float(token.confidence),
    }


def _commitment_payload(source_file_type: FileType, units: tuple[IRUnit, ...], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": IR_SCHEMA,
        "source_file_type": source_file_type.value,
        "metadata": metadata or {},
        "units": [
            {
                "unit_id": unit.unit_id,
                "kind": unit.kind,
                "index": unit.index,
                "width": _float(unit.width),
                "height": _float(unit.height),
                "extraction_mode": unit.extraction_mode,
                "spans": [
                    {
                        "text_sha256": hashlib.sha256(span.text.encode("utf-8")).hexdigest(),
                        "source": span.source.value,
                        "char_start": span.char_start,
                        "tokens": [_token_commitment(token) for token in span.tokens],
                    }
                    for span in unit.spans
                ],
            }
            for unit in units
        ],
    }


def _commitment(source_file_type: FileType, units: tuple[IRUnit, ...], metadata: dict[str, Any] | None = None) -> str:
    encoded = json.dumps(
        _commitment_payload(source_file_type, units, metadata),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_privacy_ir(document: ProcessedDocument) -> PrivacyIR:
    units: list[IRUnit] = []
    scanned_units = 0
    for page in document.pages:
        spans = tuple(
            IRTextSpan(
                text=line.text,
                tokens=line.tokens,
                source=line.source,
                unit_index=page.page_index,
                char_start=line.page_char_start,
            )
            for line in page.lines
        )
        sources = {span.source for span in spans}
        if page.used_ocr:
            scanned_units += 1
        if sources == {DetectionSource.OCR} or page.used_ocr:
            mode: Literal["TEXT_LAYER", "OCR", "MIXED"] = "OCR"
        elif sources == {DetectionSource.TEXT_LAYER} or not sources:
            mode = "TEXT_LAYER"
        else:
            mode = "MIXED"
        unit_kind: IRUnitKind = (
            "TABLE" if document.file_type == FileType.DATASET
            else "VIDEO_FRAME" if document.file_type == FileType.VIDEO
            else "PAGE"
        )
        unit_id = (
            f"record:{page.page_index}" if unit_kind == "TABLE"
            else f"video-frame:{page.page_index}" if unit_kind == "VIDEO_FRAME"
            else f"page:{page.page_index}"
        )
        units.append(
            IRUnit(
                unit_id=unit_id,
                kind=unit_kind,
                index=page.page_index,
                width=page.width,
                height=page.height,
                visual=page.image,
                spans=spans,
                extraction_mode=mode,
            )
        )
    frozen_units = tuple(units)
    metadata = dict(document.metadata)
    return PrivacyIR(
        schema=IR_SCHEMA,
        source_file_type=document.file_type,
        units=frozen_units,
        scanned_units=scanned_units,
        commitment_sha256=_commitment(document.file_type, frozen_units, metadata),
        metadata=metadata,
    )


def to_processed_document(ir: PrivacyIR) -> ProcessedDocument:
    """Compatibility adapter for the existing detectors.

    Every detector now receives content that has first passed through Privacy
    IR. Later format adapters can therefore normalize to IR and reuse the same
    downstream detector/graph/policy/proof implementation.
    """

    pages: list[PageFrame] = []
    for unit in ir.units:
        if unit.kind not in {"PAGE", "TABLE", "VIDEO_FRAME"}:
            raise ValueError(f"Current detector adapter cannot render IR unit kind {unit.kind}")
        lines = tuple(
            PositionedLine(
                text=span.text,
                tokens=span.tokens,
                source=span.source,
                page_index=unit.index,
                page_char_start=span.char_start,
            )
            for span in unit.spans
        )
        pages.append(
            PageFrame(
                page_index=unit.index,
                width=unit.width,
                height=unit.height,
                image=unit.visual,
                lines=lines,
                used_ocr=unit.extraction_mode in {"OCR", "MIXED"},
            )
        )
    return ProcessedDocument(
        file_type=ir.source_file_type,
        pages=tuple(pages),
        page_count=len(pages),
        scanned_pages=ir.scanned_units,
        metadata=dict(ir.metadata),
    )


def privacy_ir_summary(ir: PrivacyIR) -> dict[str, Any]:
    source_breakdown = {
        "TEXT_LAYER": sum(
            span.source == DetectionSource.TEXT_LAYER
            for unit in ir.units
            for span in unit.spans
        ),
        "OCR": sum(
            span.source == DetectionSource.OCR
            for unit in ir.units
            for span in unit.spans
        ),
        "VISUAL": sum(
            span.source == DetectionSource.VISUAL
            for unit in ir.units
            for span in unit.spans
        ),
    }
    unit_kind_breakdown = {kind: sum(unit.kind == kind for unit in ir.units) for kind in ("PAGE", "TEXT", "TABLE", "VIDEO_FRAME")}
    return {
        "schema": ir.schema,
        "source_file_type": ir.source_file_type.value,
        "unit_count": ir.unit_count,
        "unit_kind_breakdown": unit_kind_breakdown,
        "span_count": ir.span_count,
        "token_count": ir.token_count,
        "scanned_units": ir.scanned_units,
        "source_breakdown": source_breakdown,
        "commitment_sha256": ir.commitment_sha256,
        "plaintext_persisted": False,
        "design_note": "Format-neutral in-memory IR; audit metadata contains commitments, never source text.",
        **dict(ir.metadata),
    }
