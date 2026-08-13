from __future__ import annotations

import hashlib
import io
import re
import os
import tempfile
from pathlib import Path
from dataclasses import asdict, dataclass

import fitz
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageOps

from app.core.enums import EntityType, FileType
from app.core.config import settings
from app.extraction.document_processor import _ocr_lines, _render_page
from app.extraction.text_formats import decode_text_document, encode_protected_text
from app.extraction.docx import DocxError, sanitize_docx
from app.extraction.video import VideoError, probe_video
from app.extraction.structured_data import (
    StructuredDataError, apply_structured_replacements, export_structured_data,
)


@dataclass(frozen=True)
class ProtectionInstruction:
    entity_id: str
    mention_id: str
    entity_type: EntityType
    page_index: int
    rect: tuple[float, float, float, float]
    replacement: str
    char_start: int | None = None
    char_end: int | None = None


def _font(size: int = 16) -> ImageFont.ImageFont:
    candidates = (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _pdf_fill(entity_type: EntityType) -> tuple[float, float, float]:
    if entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
        return (0.08, 0.08, 0.10)
    return (1.0, 1.0, 1.0)


_CORPORATE_SUFFIX_RE = re.compile(
    r"(?:\s*[,.-]?\s*)(?:pvt\.?\s*lt[d.]?|private\s+limited|llp|llc|ltd\.?|limited|inc\.?|incorporated|corp\.?|corporation|co\.?|company)\s*$",
    re.IGNORECASE,
)


def _compact_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _source_variants(entity_type: EntityType, source_text: str) -> list[str]:
    """Return conservative source variants that should share one transformation.

    This is intentionally narrow. It only propagates variants where the shorter
    form is a common presentation of the *same* canonical clue (for example a
    company without its legal suffix, or the first locality component of a
    comma-qualified locality). It never invents arbitrary token subsets.
    """
    source = _compact_text(source_text)
    if not source:
        return []
    alnum_len = len(re.sub(r"[^0-9A-Za-z]", "", source))
    variants: list[str] = [source] if alnum_len >= 5 else []
    if entity_type == EntityType.EMPLOYER:
        stem = _CORPORATE_SUFFIX_RE.sub("", source).strip(" ,.-")
        if len(stem) >= 5 and stem.casefold() != source.casefold():
            variants.append(stem)
    elif entity_type in {EntityType.LOCALITY, EntityType.STREET_ADDRESS} and "," in source:
        first = source.split(",", 1)[0].strip()
        # A short generic component is too risky to propagate globally.
        if len(first) >= 5 and re.search(r"[A-Za-z]", first):
            variants.append(first)
    # Longest first prevents a shorter alias from stealing an exact full match.
    return sorted(dict.fromkeys(variants), key=len, reverse=True)


def _flexible_literal_pattern(value: str) -> re.Pattern[str]:
    pieces = [re.escape(piece) for piece in re.split(r"\s+", value.strip()) if piece]
    body = r"\s+".join(pieces)
    left = r"(?<![\w@])" if value and value[0].isalnum() else ""
    right = r"(?![\w@])" if value and value[-1].isalnum() else ""
    return re.compile(left + body + right, re.IGNORECASE)


def _rect_overlaps(a: fitz.Rect, b: fitz.Rect, *, tolerance: float = 1.0) -> bool:
    expanded = fitz.Rect(b.x0 - tolerance, b.y0 - tolerance, b.x1 + tolerance, b.y1 + tolerance)
    intersection = a & expanded
    return not intersection.is_empty and intersection.get_area() > 0


def _pdf_source_text(page: fitz.Page, rect: fitz.Rect) -> str:
    try:
        return _compact_text(page.get_textbox(rect))
    except Exception:
        return ""


def _insert_pdf_replacement(page: fitz.Page, rect: fitz.Rect, text: str, *, visual: bool) -> None:
    """Render a deterministic replacement after the original region is removed.

    PyMuPDF's redaction-annotation replacement text can disappear when a
    replacement does not fit the original rectangle, especially for OCR-backed
    scanned PDFs. Removal and replacement rendering are therefore separated.
    """
    if not text:
        return
    page_rect = page.rect
    base = fitz.Rect(
        max(page_rect.x0, rect.x0),
        max(page_rect.y0, rect.y0),
        min(page_rect.x1, rect.x1),
        min(page_rect.y1, rect.y1),
    )
    if base.width < 4 or base.height < 4:
        return
    color = (1, 1, 1) if visual else (0, 0, 0)

    if not visual:
        # Keep replacements on one line so extraction preserves spaces exactly.
        # Pick the largest font that fits the committed width; this avoids
        # overwriting neighbouring sentence content in dense digital PDFs.
        available = max(3.0, base.width - 2.0)
        chosen = 3.2
        for size in (8.0, 7.0, 6.0, 5.0, 4.5, 4.0, 3.6, 3.2):
            if fitz.get_text_length(text, fontname="helv", fontsize=size) <= available:
                chosen = size
                break
        baseline = min(page_rect.y1 - 1.0, max(base.y0 + chosen + 0.5, base.y1 - 1.0))
        page.insert_text(
            (base.x0 + 1.0, baseline),
            text,
            fontname="helv",
            fontsize=chosen,
            color=color,
            overlay=True,
        )
        return

    # Visual REMOVE regions intentionally use the original region as a dark
    # sanitisation surface. Fit a compact human-readable label inside it.
    for size in (6.0, 5.0, 4.0, 3.5):
        result = page.insert_textbox(
            base,
            text,
            fontname="helv",
            fontsize=size,
            color=color,
            align=fitz.TEXT_ALIGN_LEFT,
            overlay=True,
        )
        if result >= 0:
            return
    page.insert_text(
        (base.x0 + 1.0, min(page_rect.y1 - 1.0, base.y0 + 5.0)),
        text,
        fontname="helv",
        fontsize=3.5,
        color=color,
        overlay=True,
    )




def _normalized_ocr_token(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "", value or "").casefold()


def _sequence_tokens(value: str) -> tuple[str, ...]:
    tokens = tuple(
        token for token in (_normalized_ocr_token(piece) for piece in re.split(r"\s+", value.strip())) if token
    )
    return tokens


def _sequence_matches(tokens: tuple[str, ...], needle: tuple[str, ...]) -> list[tuple[int, int]]:
    if not needle or len(needle) > len(tokens):
        return []
    width = len(needle)
    return [(index, index + width) for index in range(len(tokens) - width + 1) if tokens[index:index + width] == needle]


def _token_rect(token) -> fitz.Rect:
    return fitz.Rect(float(token.x0), float(token.y0), float(token.x1), float(token.y1))


def _token_center_inside(token, rect: fitz.Rect, *, padding: float = 2.0) -> bool:
    expanded = fitz.Rect(rect.x0 - padding, rect.y0 - padding, rect.x1 + padding, rect.y1 + padding)
    cx = (float(token.x0) + float(token.x1)) / 2.0
    cy = (float(token.y0) + float(token.y1)) / 2.0
    return expanded.contains(fitz.Point(cx, cy))


def _ocr_source_text_for_rect(lines, rect: fitz.Rect) -> str:
    """Recover the OCR value bound to one committed scan rectangle.

    The first OCR/detection pass already produced the rectangle. Re-running the
    local OCR here gives the sanitizer the canonical source phrase needed to
    propagate the same transformation to missed visual occurrences elsewhere
    on the scanned page. Only token centres inside the committed rectangle are
    accepted, so labels adjacent to a field are not accidentally captured.
    """
    selected: list[tuple[float, float, str]] = []
    for line in lines:
        for token in line.tokens:
            if _token_center_inside(token, rect):
                cleaned = _compact_text(token.text)
                if cleaned:
                    selected.append((float(token.y0), float(token.x0), cleaned))
    selected.sort(key=lambda item: (round(item[0] / 4.0), item[1]))
    return _compact_text(" ".join(item[2] for item in selected))


def _rect_for_token_span(line, start: int, end: int) -> fitz.Rect:
    span = line.tokens[start:end]
    return fitz.Rect(
        min(float(token.x0) for token in span),
        min(float(token.y0) for token in span),
        max(float(token.x1) for token in span),
        max(float(token.y1) for token in span),
    )


def _ocr_residual_rects(
    lines,
    *,
    source_text: str,
    replacement: str,
    committed_rects: list[fitz.Rect],
    entity_type: EntityType,
) -> list[fitz.Rect]:
    """Locate source-value OCR spans outside already-controlled regions.

    Exact approved replacement phrases are protected from self-matching. For
    example, the source ``Bengaluru`` is allowed inside the signed replacement
    ``Bengaluru metropolitan area`` while a standalone ``Bengaluru`` elsewhere
    on the raster remains a real leak and is returned for sanitization.
    """
    residuals: list[fitz.Rect] = []
    replacement_tokens = _sequence_tokens(replacement)
    variants = _source_variants(entity_type, source_text)
    if source_text and source_text not in variants:
        variants = [source_text, *variants]

    for line in lines:
        normalized = tuple(_normalized_ocr_token(token.text) for token in line.tokens)
        approved_spans = _sequence_matches(normalized, replacement_tokens) if replacement_tokens else []
        for variant in variants:
            needle = _sequence_tokens(variant)
            for start, end in _sequence_matches(normalized, needle):
                # Source text occurring as a token subset of the exact approved
                # replacement phrase is not a residual leak.
                if any(start >= a_start and end <= a_end for a_start, a_end in approved_spans):
                    continue
                candidate = _rect_for_token_span(line, start, end)
                # The committed field itself has already been structurally
                # redacted and rewritten. Never repeatedly attack that surface.
                if any(_rect_overlaps(candidate, controlled, tolerance=2.0) for controlled in committed_rects):
                    continue
                if any(_rect_overlaps(candidate, existing, tolerance=1.0) for existing in residuals):
                    continue
                residuals.append(candidate)
    return residuals


def _collect_scanned_sources(
    document: fitz.Document,
    instructions: list[ProtectionInstruction],
) -> tuple[dict[int, list[tuple[ProtectionInstruction, str]]], set[int]]:
    """Bind OCR source phrases to scan-backed instructions before mutation."""
    by_page: dict[int, list[ProtectionInstruction]] = {}
    for item in instructions:
        if 0 <= item.page_index < len(document):
            by_page.setdefault(item.page_index, []).append(item)

    sources: dict[int, list[tuple[ProtectionInstruction, str]]] = {}
    scanned_pages: set[int] = set()
    for page_index, page_items in by_page.items():
        page = document[page_index]
        # If any non-visual committed region lacks native text, treat the page
        # as scan/OCR-backed and recover source phrases from pixels.
        needs_ocr = any(
            item.entity_type not in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}
            and not _pdf_source_text(page, fitz.Rect(*item.rect))
            for item in page_items
        )
        if not needs_ocr:
            continue
        scanned_pages.add(page_index)
        image = _render_page(page)
        lines = _ocr_lines(image, page_index, float(page.rect.width), float(page.rect.height))
        for item in page_items:
            if item.entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
                continue
            source = _ocr_source_text_for_rect(lines, fitz.Rect(*item.rect))
            if source:
                sources.setdefault(page_index, []).append((item, source))
    return sources, scanned_pages


def _propagate_scanned_ocr_residuals(
    document: fitz.Document,
    scanned_sources: dict[int, list[tuple[ProtectionInstruction, str]]],
    by_page: dict[int, list[ProtectionInstruction]],
    *,
    max_passes: int = 2,
) -> tuple[int, int]:
    """Second-pass OCR closure for scan-backed PDFs.

    This is intentionally upstream of the Privacy Red Team. It repairs only
    residual visual occurrences that can be bound to a canonical instruction.
    Verification remains independent and fail-closed after sanitization.
    """
    propagated = 0
    passes_used = 0
    for _pass in range(max_passes):
        additions: dict[int, list[ProtectionInstruction]] = {}
        serial = 0
        for page_index, source_items in scanned_sources.items():
            page = document[page_index]
            image = _render_page(page)
            lines = _ocr_lines(image, page_index, float(page.rect.width), float(page.rect.height))
            controlled_by_entity: dict[str, list[fitz.Rect]] = {}
            for controlled_item in by_page.get(page_index, []):
                controlled_by_entity.setdefault(controlled_item.entity_id, []).append(fitz.Rect(*controlled_item.rect))
            for item, source_text in source_items:
                controlled = controlled_by_entity.setdefault(item.entity_id, [])
                rects = _ocr_residual_rects(
                    lines,
                    source_text=source_text,
                    replacement=item.replacement,
                    committed_rects=controlled,
                    entity_type=item.entity_type,
                )
                for rect in rects:
                    serial += 1
                    propagated_item = ProtectionInstruction(
                        entity_id=item.entity_id,
                        mention_id=f"{item.mention_id}:ocr-propagated:{_pass + 1}:{serial}",
                        entity_type=item.entity_type,
                        page_index=page_index,
                        rect=(rect.x0, rect.y0, rect.x1, rect.y1),
                        replacement=item.replacement,
                        char_start=None,
                        char_end=None,
                    )
                    additions.setdefault(page_index, []).append(propagated_item)
                    controlled.append(rect)
        if not additions:
            break
        passes_used += 1
        for page_index, page_additions in additions.items():
            page = document[page_index]
            for item in page_additions:
                page.add_redact_annot(
                    fitz.Rect(*item.rect),
                    text="",
                    fontname="helv",
                    fontsize=8,
                    fill=_pdf_fill(item.entity_type),
                    text_color=(0, 0, 0),
                    cross_out=False,
                )
            page.apply_redactions(
                images=fitz.PDF_REDACT_IMAGE_PIXELS,
                graphics=fitz.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED,
                text=fitz.PDF_REDACT_TEXT_REMOVE,
            )
            # ``apply_redactions`` mutates this page in place. Reusing the same
            # page object avoids PyMuPDF reload assertions when the preceding
            # OCR render still has an internal page reference on some builds.
            for item in page_additions:
                _insert_pdf_replacement(page, fitz.Rect(*item.rect), item.replacement, visual=False)
            by_page.setdefault(page_index, []).extend(page_additions)
            propagated += len(page_additions)
    return propagated, passes_used


def _augment_pdf_instructions(document: fitz.Document, instructions: list[ProtectionInstruction]) -> tuple[list[ProtectionInstruction], int]:
    """Propagate conservative canonical variants across digital PDF text layers."""
    augmented = list(instructions)
    existing_by_page: dict[int, list[fitz.Rect]] = {}
    for item in instructions:
        existing_by_page.setdefault(item.page_index, []).append(fitz.Rect(*item.rect))
    propagated = 0
    seen: set[tuple[int, int, int, int, int, int]] = set()
    for item in instructions:
        if item.page_index < 0 or item.page_index >= len(document):
            continue
        source_page = document[item.page_index]
        committed_rect = fitz.Rect(*item.rect)
        source = _pdf_source_text(source_page, committed_rect)
        if not source:
            # Scanned PDFs have no authoritative native source text here; their
            # OCR regions are already explicit instructions.
            continue
        for variant in _source_variants(item.entity_type, source):
            for page_index in range(len(document)):
                page = document[page_index]
                for found in page.search_for(variant):
                    occupied = existing_by_page.setdefault(page_index, [])
                    if any(_rect_overlaps(found, rect) for rect in occupied):
                        continue
                    key = (
                        page_index,
                        round(found.x0), round(found.y0), round(found.x1), round(found.y1),
                        hash((item.entity_id, item.replacement)),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    augmented.append(ProtectionInstruction(
                        entity_id=item.entity_id,
                        mention_id=f"{item.mention_id}:propagated:{propagated + 1}",
                        entity_type=item.entity_type,
                        page_index=page_index,
                        rect=(found.x0, found.y0, found.x1, found.y1),
                        replacement=item.replacement,
                        char_start=None,
                        char_end=None,
                    ))
                    occupied.append(found)
                    propagated += 1
    return augmented, propagated

def sanitize_pdf(data: bytes, instructions: list[ProtectionInstruction]) -> tuple[bytes, str, str, dict[str, object]]:
    if not instructions:
        raise ValueError("No protection instructions were supplied")
    document = fitz.open(stream=data, filetype="pdf")
    pages_modified: set[int] = set()
    try:
        scanned_sources, scanned_pages = _collect_scanned_sources(document, instructions)
        effective_instructions, propagated = _augment_pdf_instructions(document, instructions)
        by_page: dict[int, list[ProtectionInstruction]] = {}
        for instruction in effective_instructions:
            if instruction.page_index < 0 or instruction.page_index >= len(document):
                raise ValueError("Protection instruction references an invalid page")
            by_page.setdefault(instruction.page_index, []).append(instruction)
            page = document[instruction.page_index]
            rect = fitz.Rect(*instruction.rect)
            visual = instruction.entity_type in {
                EntityType.FACE,
                EntityType.QR_CODE,
                EntityType.SIGNATURE_CANDIDATE,
            }
            # Removal and replacement rendering are deliberately separated.
            # Redaction first irreversibly destroys source pixels/text; a second
            # deterministic pass writes the manifest replacement so a scanned
            # PDF cannot silently degrade PSEUDONYMIZE/GENERALIZE into REMOVE.
            page.add_redact_annot(
                rect,
                text="",
                fontname="helv",
                fontsize=6 if visual else 8,
                fill=_pdf_fill(instruction.entity_type),
                text_color=(1, 1, 1) if visual else (0, 0, 0),
                cross_out=False,
            )
            pages_modified.add(instruction.page_index)

        for page_index in sorted(pages_modified):
            page = document[page_index]
            page.apply_redactions(
                images=fitz.PDF_REDACT_IMAGE_PIXELS,
                graphics=fitz.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED,
                text=fitz.PDF_REDACT_TEXT_REMOVE,
            )
            page = document.reload_page(page)
            for instruction in by_page.get(page_index, []):
                visual = instruction.entity_type in {
                    EntityType.FACE,
                    EntityType.QR_CODE,
                    EntityType.SIGNATURE_CANDIDATE,
                }
                _insert_pdf_replacement(page, fitz.Rect(*instruction.rect), instruction.replacement, visual=visual)

        ocr_propagated, ocr_passes = _propagate_scanned_ocr_residuals(
            document, scanned_sources, by_page
        ) if scanned_sources else (0, 0)

        document.scrub(
            attached_files=True,
            clean_pages=True,
            embedded_files=True,
            hidden_text=True,
            javascript=True,
            metadata=True,
            redactions=True,
            redact_images=fitz.PDF_REDACT_IMAGE_PIXELS,
            remove_links=True,
            reset_fields=True,
            reset_responses=True,
            thumbnails=True,
            xml_metadata=True,
        )
        output = io.BytesIO()
        document.save(output, garbage=4, deflate=True, clean=True)
        protected = output.getvalue()
        return protected, "application/pdf", "protected.pdf", {
            "transformations": len(instructions),
            "propagated_occurrences": propagated,
            "ocr_propagated_occurrences": ocr_propagated,
            "ocr_residual_passes": ocr_passes,
            "scanned_pages_hardened": sorted(scanned_pages),
            "effective_redactions": len(effective_instructions) + ocr_propagated,
            "pages_modified": sorted(pages_modified),
            "output_sha256": hashlib.sha256(protected).hexdigest(),
            "method": "structural PDF redaction, canonical text propagation, post-transform OCR residual closure, deterministic replacement rendering and scrub",
        }
    finally:
        document.close()

def sanitize_image(data: bytes, instructions: list[ProtectionInstruction]) -> tuple[bytes, str, str, dict[str, object]]:
    if not instructions:
        raise ValueError("No protection instructions were supplied")
    image = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")
    draw = ImageDraw.Draw(image)
    font = _font(max(12, min(22, image.width // 70)))
    for instruction in instructions:
        if instruction.page_index != 0:
            raise ValueError("Standalone images have only page index 0")
        x0, y0, x1, y1 = instruction.rect
        visual = instruction.entity_type in {
            EntityType.FACE,
            EntityType.QR_CODE,
            EntityType.SIGNATURE_CANDIDATE,
        }
        fill = (18, 18, 24) if visual else (255, 255, 255)
        text_fill = (255, 255, 255) if visual else (0, 0, 0)
        draw.rectangle((x0, y0, x1, y1), fill=fill)
        label = instruction.replacement
        draw.text((x0 + 3, y0 + 2), label, fill=text_fill, font=font)
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    protected = output.getvalue()
    return protected, "image/png", "protected.png", {
        "transformations": len(instructions),
        "pages_modified": [0],
        "output_sha256": hashlib.sha256(protected).hexdigest(),
        "method": "irreversible pixel-region replacement and metadata-free PNG export",
    }


def sanitize_text(
    data: bytes,
    instructions: list[ProtectionInstruction],
    source_filename: str | None = None,
) -> tuple[bytes, str, str, dict[str, object]]:
    if not instructions:
        raise ValueError("No protection instructions were supplied")
    decoded = decode_text_document(data, source_filename)
    text = decoded.text

    spans: list[tuple[int, int, str, str]] = []
    sources: list[tuple[ProtectionInstruction, str]] = []
    for instruction in instructions:
        if instruction.char_start is None or instruction.char_end is None:
            raise ValueError("Native text protection requires exact character-span commitments")
        start = int(instruction.char_start)
        end = int(instruction.char_end)
        if start < 0 or end <= start or end > len(text):
            raise ValueError("Text protection instruction references an invalid character span")
        spans.append((start, end, instruction.replacement, instruction.mention_id))
        sources.append((instruction, text[start:end]))

    # Reject conflicting overlap rather than silently damaging structure. Exact
    # duplicate spans are de-duplicated deterministically.
    unique: dict[tuple[int, int], tuple[str, str]] = {}
    for start, end, replacement, mention_id in spans:
        key = (start, end)
        previous = unique.get(key)
        if previous is not None and previous[0] != replacement:
            raise ValueError("Conflicting replacements target the same text span")
        unique[key] = (replacement, mention_id)

    propagated = 0
    occupied = [(*key,) for key in unique]
    # Propagate only conservative same-clue variants. This closes the common
    # native-text failure where the canonical field is protected but a shorter
    # contextual occurrence (e.g. company without legal suffix) survives.
    candidates: list[tuple[int, int, str, str, int]] = []
    for instruction, source_text in sources:
        for variant in _source_variants(instruction.entity_type, source_text):
            pattern = _flexible_literal_pattern(variant)
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(start < old_end and end > old_start for old_start, old_end in occupied):
                    continue
                candidates.append((start, end, instruction.replacement, instruction.mention_id, len(variant)))
    # Longest match first, then deterministic source order.
    for start, end, replacement, mention_id, _length in sorted(candidates, key=lambda x: (-x[4], x[0], x[1])):
        if any(start < old_end and end > old_start for old_start, old_end in occupied):
            continue
        unique[(start, end)] = (replacement, f"{mention_id}:propagated:{propagated + 1}")
        occupied.append((start, end))
        propagated += 1

    ordered = sorted((start, end, replacement, mention_id) for (start, end), (replacement, mention_id) in unique.items())
    for (left_start, left_end, _left_replacement, _left_id), (right_start, _right_end, _right_replacement, _right_id) in zip(ordered, ordered[1:]):
        if right_start < left_end:
            raise ValueError("Overlapping text protection instructions are not allowed")

    protected_text = text
    for start, end, replacement, _mention_id in reversed(ordered):
        protected_text = protected_text[:start] + replacement + protected_text[end:]

    protected, media_type, extension = encode_protected_text(
        protected_text, source_filename, source_data=data
    )
    return protected, media_type, f"protected{extension}", {
        "transformations": len(instructions),
        "propagated_occurrences": propagated,
        "effective_replacements": len(ordered),
        "pages_modified": sorted({item.page_index for item in instructions}),
        "output_sha256": hashlib.sha256(protected).hexdigest(),
        "method": "native text character-span replacement with conservative canonical occurrence propagation and canonical metadata-free export",
        "source_text_format": decoded.extension,
        "source_encoding": decoded.source_encoding,
        "canonicalized_rtf": decoded.extension == ".rtf",
    }

def sanitize_dataset(
    data: bytes,
    instructions: list[ProtectionInstruction],
    source_filename: str | None = None,
) -> tuple[bytes, str, str, dict[str, object]]:
    if not instructions:
        raise ValueError("No protection instructions were supplied")
    replacements: list[tuple[int, int, int, str]] = []
    for instruction in instructions:
        if instruction.char_start is None or instruction.char_end is None:
            raise ValueError("Structured-data protection requires exact scalar-span commitments")
        replacements.append((
            int(instruction.page_index),
            int(instruction.char_start),
            int(instruction.char_end),
            instruction.replacement,
        ))
    try:
        dataset = apply_structured_replacements(data, replacements, source_filename)
        protected, media_type, extension = export_structured_data(dataset)
    except StructuredDataError as exc:
        raise ValueError(str(exc)) from exc
    return protected, media_type, f"protected{extension}", {
        "transformations": len(replacements),
        "records_modified": sorted({item.page_index for item in instructions}),
        "output_sha256": hashlib.sha256(protected).hexdigest(),
        "method": "schema-preserving scalar replacement with canonical metadata-free structured export",
        "structured_format": dataset.format.upper(),
    }


def _video_track_key(instruction: ProtectionInstruction) -> str:
    if instruction.entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
        return f"VISUAL:{instruction.entity_type.value}:{instruction.entity_id}"
    return f"ENTITY:{instruction.entity_id}"


def _video_interpolated_rect(
    anchors: list[tuple[int, tuple[float, float, float, float]]],
    frame_index: int,
    hold_frames: int,
) -> tuple[float, float, float, float] | None:
    if not anchors:
        return None
    anchors = sorted(anchors, key=lambda item: item[0])
    if len(anchors) == 1:
        anchor_frame, rect = anchors[0]
        return rect if abs(frame_index - anchor_frame) <= hold_frames else None
    if frame_index <= anchors[0][0]:
        return anchors[0][1] if anchors[0][0] - frame_index <= hold_frames else None
    if frame_index >= anchors[-1][0]:
        return anchors[-1][1] if frame_index - anchors[-1][0] <= hold_frames else None
    for (left_frame, left_rect), (right_frame, right_rect) in zip(anchors, anchors[1:]):
        if left_frame <= frame_index <= right_frame:
            if right_frame == left_frame:
                return left_rect
            alpha = (frame_index - left_frame) / float(right_frame - left_frame)
            return tuple(
                float(a + (b - a) * alpha)
                for a, b in zip(left_rect, right_rect)
            )
    return None



def _video_fitted_text_style(label: str, width: int, height: int, preferred_scale: float) -> tuple[float, int]:
    """Fit a policy label inside its protected video region without clipping.

    Video OCR boxes are often much narrower than generalized replacements (for
    example ``Bengaluru metropolitan area``). Scale the rendered alias down to
    the available region instead of silently truncating it in judge-facing
    output.
    """
    label = label[:64]
    inner_width = max(12, width - 8)
    inner_height = max(10, height - 4)
    scale = max(0.28, float(preferred_scale))
    thickness = max(1, int(round(scale * 2)))
    (text_width, text_height), _baseline = cv2.getTextSize(
        label, cv2.FONT_HERSHEY_SIMPLEX, scale, thickness
    )
    if text_width > inner_width and text_width > 0:
        scale *= inner_width / text_width
    if text_height > inner_height and text_height > 0:
        scale *= inner_height / text_height
    scale = max(0.28, min(float(preferred_scale), scale))
    thickness = max(1, int(round(scale * 2)))
    return scale, thickness

def sanitize_video(
    data: bytes,
    instructions: list[ProtectionInstruction],
    source_filename: str | None = None,
) -> tuple[bytes, str, str, dict[str, object]]:
    if not instructions:
        raise ValueError("No protection instructions were supplied")
    try:
        info = probe_video(data, source_filename)
    except VideoError as exc:
        raise ValueError(str(exc)) from exc
    tracks: dict[str, dict[str, object]] = {}
    for instruction in instructions:
        source_frame = int(instruction.page_index)
        if source_frame < 0 or source_frame >= info.total_frames:
            raise ValueError("Video protection instruction references an invalid physical frame")
        key = _video_track_key(instruction)
        track = tracks.setdefault(key, {
            "entity_type": instruction.entity_type,
            "replacement": instruction.replacement,
            "anchors": [],
        })
        track["anchors"].append((source_frame, instruction.rect))

    source_path = output_path = None
    capture = writer = None
    try:
        with tempfile.NamedTemporaryFile(suffix=info.source_extension, delete=False) as handle:
            handle.write(data)
            source_path = handle.name
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as handle:
            output_path = handle.name
        capture = cv2.VideoCapture(source_path)
        if not capture.isOpened():
            raise ValueError("OpenCV could not decode the source video for transformation")
        writer = cv2.VideoWriter(
            output_path,
            cv2.VideoWriter_fourcc(*"mp4v"),
            info.fps,
            (info.width, info.height),
        )
        if not writer.isOpened():
            raise ValueError("Local MP4 encoder is unavailable")

        # Instructions are now anchored to exact physical frames. A short hold
        # window bridges rare OCR dropouts while the full-frame security scan
        # supplies anchors for transient identifiers that appear between judge
        # evidence samples.
        hold_frames = max(2, int(round(info.fps * 0.5)))
        frames_written = 0
        changed_frames = 0
        frame_index = 0
        font_scale = max(0.45, min(0.9, info.width / 1200.0))
        while True:
            ok, frame = capture.read()
            if not ok or frame is None:
                break
            changed = False
            for track in tracks.values():
                rect = _video_interpolated_rect(track["anchors"], frame_index, hold_frames)
                if rect is None:
                    continue
                x0, y0, x1, y1 = rect
                pad = max(3, int(round(min(info.width, info.height) * 0.006)))
                ix0 = max(0, min(info.width - 1, int(round(x0)) - pad))
                iy0 = max(0, min(info.height - 1, int(round(y0)) - pad))
                ix1 = max(ix0 + 1, min(info.width, int(round(x1)) + pad))
                iy1 = max(iy0 + 1, min(info.height, int(round(y1)) + pad))
                entity_type = track["entity_type"]
                replacement = str(track["replacement"])
                if entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
                    roi = frame[iy0:iy1, ix0:ix1]
                    if roi.size:
                        k = max(9, (min(roi.shape[:2]) // 4) | 1)
                        k = min(k, 51)
                        if k % 2 == 0:
                            k += 1
                        frame[iy0:iy1, ix0:ix1] = cv2.GaussianBlur(roi, (k, k), 0)
                        cv2.rectangle(frame, (ix0, iy0), (ix1, iy1), (20, 20, 20), 2)
                else:
                    cv2.rectangle(frame, (ix0, iy0), (ix1, iy1), (20, 20, 20), thickness=-1)
                    label = replacement[:64]
                    fitted_scale, fitted_thickness = _video_fitted_text_style(
                        label, ix1 - ix0, iy1 - iy0, font_scale
                    )
                    (_tw, text_height), baseline = cv2.getTextSize(
                        label, cv2.FONT_HERSHEY_SIMPLEX, fitted_scale, fitted_thickness
                    )
                    baseline_y = iy0 + max(text_height + 2, ((iy1 - iy0) + text_height - baseline) // 2)
                    baseline_y = min(info.height - max(2, baseline), baseline_y)
                    cv2.putText(
                        frame, label, (ix0 + 4, baseline_y), cv2.FONT_HERSHEY_SIMPLEX,
                        fitted_scale, (255, 255, 255), fitted_thickness, cv2.LINE_AA,
                    )
                changed = True
            if changed:
                changed_frames += 1
            writer.write(frame)
            frames_written += 1
            frame_index += 1
        writer.release()
        writer = None
        capture.release()
        capture = None
        protected = Path(output_path).read_bytes()
        output_info = probe_video(protected, "protected.mp4")
        if output_info.total_frames <= 0:
            raise ValueError("Protected video contains no decodable frames")
        return protected, "video/mp4", "protected.mp4", {
            "transformations": len(instructions),
            "temporal_tracks": len(tracks),
            "frames_written": frames_written,
            "frames_materially_targeted": changed_frames,
            "duration_seconds": round(output_info.duration_seconds, 3),
            "fps": round(output_info.fps, 3),
            "width": output_info.width,
            "height": output_info.height,
            "audio_present_in_source": info.has_audio,
            "audio_stripped": True,
            "output_sha256": hashlib.sha256(protected).hexdigest(),
            "security_frames_targetable": info.total_frames,
            "method": "full-physical-frame video protection with temporal track interpolation and fail-closed audio stripping",
        }
    finally:
        if capture is not None:
            capture.release()
        if writer is not None:
            writer.release()
        for path in (source_path, output_path):
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass


def sanitize_document(
    data: bytes,
    file_type: FileType,
    instructions: list[ProtectionInstruction],
    source_filename: str | None = None,
) -> tuple[bytes, str, str, dict[str, object]]:
    if file_type == FileType.PDF:
        return sanitize_pdf(data, instructions)
    if file_type == FileType.TEXT:
        return sanitize_text(data, instructions, source_filename)
    if file_type == FileType.DOCX:
        try:
            return sanitize_docx(data, instructions, source_filename)
        except DocxError as exc:
            raise ValueError(str(exc)) from exc
    if file_type == FileType.DATASET:
        return sanitize_dataset(data, instructions, source_filename)
    if file_type == FileType.VIDEO:
        return sanitize_video(data, instructions, source_filename)
    return sanitize_image(data, instructions)


def instruction_manifest(instructions: list[ProtectionInstruction]) -> list[dict[str, object]]:
    manifest = []
    for instruction in instructions:
        item = asdict(instruction)
        item["entity_type"] = instruction.entity_type.value
        item["rect"] = list(instruction.rect)
        manifest.append(item)
    return manifest
