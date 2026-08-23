from __future__ import annotations

import io
import os
from dataclasses import dataclass, field
from typing import Iterable

import fitz
import pytesseract
from PIL import Image, ImageDraw, ImageFont, ImageOps
from pytesseract import Output

from app.core.config import settings

os.environ.setdefault("OMP_THREAD_LIMIT", "1")
from app.core.enums import DetectionSource, FileType
from app.extraction.text_formats import TextFormatError, decode_text_document


class DocumentProcessingError(ValueError):
    pass


@dataclass(frozen=True)
class PositionedToken:
    text: str
    x0: float
    y0: float
    x1: float
    y1: float
    confidence: float


@dataclass(frozen=True)
class PositionedLine:
    text: str
    tokens: tuple[PositionedToken, ...]
    source: DetectionSource
    page_index: int
    page_char_start: int


@dataclass(frozen=True)
class PageFrame:
    page_index: int
    width: float
    height: float
    image: Image.Image
    lines: tuple[PositionedLine, ...]
    used_ocr: bool


@dataclass(frozen=True)
class ProcessedDocument:
    file_type: FileType
    pages: tuple[PageFrame, ...]
    page_count: int
    scanned_pages: int
    metadata: dict[str, object] = field(default_factory=dict)


def _join_tokens(tokens: Iterable[PositionedToken]) -> str:
    return " ".join(token.text for token in tokens).strip()


def _digital_lines(page: fitz.Page, page_index: int) -> list[PositionedLine]:
    grouped: dict[tuple[int, int], list[PositionedToken]] = {}
    for word in page.get_text("words", sort=True):
        x0, y0, x1, y1, text, block_no, line_no, _word_no = word[:8]
        cleaned = str(text).strip()
        if not cleaned:
            continue
        grouped.setdefault((int(block_no), int(line_no)), []).append(
            PositionedToken(cleaned, float(x0), float(y0), float(x1), float(y1), 1.0)
        )

    lines: list[PositionedLine] = []
    running_offset = 0
    for key in sorted(grouped):
        tokens = tuple(sorted(grouped[key], key=lambda item: item.x0))
        text = _join_tokens(tokens)
        if text:
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
    return lines


def _orientation_rotation(image: Image.Image) -> int:
    if not settings.ocr_auto_rotate:
        return 0
    try:
        osd = pytesseract.image_to_osd(image, config="--psm 0")
    except Exception:
        return 0
    rotation_match = __import__("re").search(r"Rotate:\s*(0|90|180|270)", osd)
    confidence_match = __import__("re").search(r"Orientation confidence:\s*([0-9.]+)", osd)
    if not rotation_match:
        return 0
    confidence = float(confidence_match.group(1)) if confidence_match else 0.0
    if confidence < settings.ocr_min_orientation_confidence:
        return 0
    return int(rotation_match.group(1))


def _rotate_clockwise(image: Image.Image, degrees: int) -> Image.Image:
    if degrees == 90:
        return image.transpose(Image.Transpose.ROTATE_270)
    if degrees == 180:
        return image.transpose(Image.Transpose.ROTATE_180)
    if degrees == 270:
        return image.transpose(Image.Transpose.ROTATE_90)
    return image


def _inverse_oriented_point(
    x: float,
    y: float,
    rotation: int,
    original_width: float,
    original_height: float,
) -> tuple[float, float]:
    if rotation == 90:
        return y, original_height - x
    if rotation == 180:
        return original_width - x, original_height - y
    if rotation == 270:
        return original_width - y, x
    return x, y


def _map_oriented_rect_to_original(
    left: float,
    top: float,
    width: float,
    height: float,
    *,
    rotation: int,
    upscale: float,
    original_width: float,
    original_height: float,
    target_width: float,
    target_height: float,
) -> tuple[float, float, float, float]:
    x0, y0 = left / upscale, top / upscale
    x1, y1 = (left + width) / upscale, (top + height) / upscale
    points = (
        _inverse_oriented_point(x0, y0, rotation, original_width, original_height),
        _inverse_oriented_point(x1, y0, rotation, original_width, original_height),
        _inverse_oriented_point(x0, y1, rotation, original_width, original_height),
        _inverse_oriented_point(x1, y1, rotation, original_width, original_height),
    )
    scale_x = target_width / original_width
    scale_y = target_height / original_height
    xs = [max(0.0, min(original_width, point[0])) * scale_x for point in points]
    ys = [max(0.0, min(original_height, point[1])) * scale_y for point in points]
    return min(xs), min(ys), max(xs), max(ys)


def _ocr_lines(image: Image.Image, page_index: int, target_width: float, target_height: float) -> list[PositionedLine]:
    original = ImageOps.exif_transpose(image).convert("RGB")
    original_width = float(original.width)
    original_height = float(original.height)

    # OSD is completely local. It corrects 90/180/270-degree scans before
    # identifier detection while the inverse transform below keeps every OCR
    # bounding box in the original page coordinate system.
    rotation = _orientation_rotation(original)
    oriented = _rotate_clockwise(original, rotation)

    # Improve low-resolution camera/scanner captures without changing the
    # coordinate system visible to the rest of VeilGraph.
    short_side = max(1, min(oriented.width, oriented.height))
    upscale = min(
        settings.ocr_max_upscale,
        max(1.0, settings.ocr_min_short_side_pixels / float(short_side)),
    )
    if upscale > 1.01:
        oriented = oriented.resize(
            (max(1, int(round(oriented.width * upscale))), max(1, int(round(oriented.height * upscale)))),
            Image.Resampling.LANCZOS,
        )

    prepared = ImageOps.autocontrast(ImageOps.grayscale(oriented)).convert("RGB")
    data = pytesseract.image_to_data(
        prepared,
        lang=settings.ocr_language,
        config="--psm 6",
        output_type=Output.DICT,
    )
    grouped: dict[tuple[int, int, int], list[PositionedToken]] = {}

    count = len(data.get("text", []))
    for index in range(count):
        text = str(data["text"][index]).strip()
        if not text:
            continue
        try:
            confidence = float(data["conf"][index]) / 100.0
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence < 0.20:
            continue
        left = float(data["left"][index])
        top = float(data["top"][index])
        width = float(data["width"][index])
        height = float(data["height"][index])
        x0, y0, x1, y1 = _map_oriented_rect_to_original(
            left,
            top,
            width,
            height,
            rotation=rotation,
            upscale=upscale,
            original_width=original_width,
            original_height=original_height,
            target_width=target_width,
            target_height=target_height,
        )
        token = PositionedToken(
            text=text,
            x0=x0,
            y0=y0,
            x1=x1,
            y1=y1,
            confidence=max(0.0, min(1.0, confidence)),
        )
        key = (
            int(data["block_num"][index]),
            int(data["par_num"][index]),
            int(data["line_num"][index]),
        )
        grouped.setdefault(key, []).append(token)

    lines: list[PositionedLine] = []
    running_offset = 0
    for key in sorted(grouped):
        # pytesseract already yields word order in the corrected orientation.
        # Sorting by x0 after mapping boxes back to a rotated source page would
        # scramble vertical lines, so preserve OCR reading order here.
        tokens = tuple(grouped[key])
        text = _join_tokens(tokens)
        if text:
            lines.append(
                PositionedLine(
                    text=text,
                    tokens=tokens,
                    source=DetectionSource.OCR,
                    page_index=page_index,
                    page_char_start=running_offset,
                )
            )
            running_offset += len(text) + 1
    return lines


def _render_page(page: fitz.Page) -> Image.Image:
    zoom = settings.ocr_dpi / 72.0
    pixmap = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
    return Image.open(io.BytesIO(pixmap.tobytes("png"))).convert("RGB")




def _text_font(size: int = 20) -> ImageFont.ImageFont:
    for candidate in (
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def processed_document_from_decoded_text(source: str) -> ProcessedDocument:
    """Build a virtual text document from an already-decoded Unicode string.

    This deliberately bypasses byte-level upload validation. It is intended for
    trusted in-process sources such as benchmark corpora that have already been
    parsed from UTF-8 JSON and whose character offsets must remain byte-for-byte
    equivalent at the Python string level. Production file uploads still enter
    through ``process_document`` and retain all binary/control-character checks.
    """
    if not isinstance(source, str):
        raise DocumentProcessingError("Decoded text source must be a Unicode string")

    # Native text is normalized into deterministic virtual pages. Character
    # offsets remain global source-text offsets so transformation can replace
    # exact spans without relying on visual coordinates.
    font = _text_font(20)
    page_width = 1200
    margin_x = 52
    margin_y = 52
    line_height = 30
    lines_per_page = 44
    usable_width = page_width - 2 * margin_x

    logical_lines = source.splitlines(keepends=True)
    if not logical_lines:
        logical_lines = [source]

    pages: list[PageFrame] = []
    page_lines: list[PositionedLine] = []
    page_index = 0
    line_on_page = 0
    global_offset = 0

    def flush_page() -> None:
        nonlocal page_lines, page_index, line_on_page
        # `line_on_page` counts every logical source row, including blank rows.
        # The old renderer enumerated only non-empty PositionedLine objects,
        # visually collapsing blank rows while evidence coordinates still kept
        # them. That made every overlay after a blank line drift downward.
        height = max(300, margin_y * 2 + max(1, line_on_page) * line_height)
        image = Image.new("RGB", (page_width, height), "white")
        draw = ImageDraw.Draw(image)
        for line in page_lines:
            if not line.tokens:
                continue
            # The token y-coordinate is the authoritative virtual-layout row.
            # Rendering from it keeps preview pixels and stored evidence geometry
            # on the same coordinate system even when the source contains blanks.
            draw_y = min(float(token.y0) for token in line.tokens)
            draw.text((margin_x, draw_y), line.text, font=font, fill="black")
        pages.append(
            PageFrame(
                page_index=page_index,
                width=float(page_width),
                height=float(height),
                image=image,
                lines=tuple(page_lines),
                used_ocr=False,
            )
        )
        page_lines = []
        page_index += 1
        line_on_page = 0

    for raw_line in logical_lines:
        newline_len = len(raw_line) - len(raw_line.rstrip("\r\n"))
        line_text = raw_line[:-newline_len] if newline_len else raw_line
        # Preserve empty lines in page structure, but detectors do not need a
        # token-less PositionedLine for them.
        if line_text:
            tokens: list[PositionedToken] = []
            y0 = float(margin_y + line_on_page * line_height)
            y1 = y0 + float(line_height - 4)
            for match in __import__("re").finditer(r"\S+", line_text):
                # Measure with the exact font used by the renderer instead of
                # approximating every character as an "M". This keeps geometry
                # correct for indentation, tabs and Unicode glyph advances.
                x0 = float(margin_x) + min(
                    float(usable_width - 2), float(font.getlength(line_text[:match.start()]))
                )
                x1 = float(margin_x) + min(
                    float(usable_width), float(font.getlength(line_text[:match.end()]))
                )
                tokens.append(
                    PositionedToken(
                        text=match.group(0),
                        x0=x0, y0=y0, x1=max(x0 + 2.0, x1), y1=y1, confidence=1.0,
                    )
                )
            if tokens:
                page_lines.append(
                    PositionedLine(
                        text=line_text,
                        tokens=tuple(tokens),
                        source=DetectionSource.TEXT_LAYER,
                        page_index=page_index,
                        page_char_start=global_offset,
                    )
                )
        global_offset += len(raw_line)
        line_on_page += 1
        if line_on_page >= lines_per_page:
            flush_page()

    if page_lines or not pages:
        flush_page()

    return ProcessedDocument(
        file_type=FileType.TEXT,
        pages=tuple(pages),
        page_count=len(pages),
        scanned_pages=0,
    )


def _text_document(data: bytes) -> ProcessedDocument:
    try:
        decoded = decode_text_document(data)
    except TextFormatError as exc:
        raise DocumentProcessingError(str(exc)) from exc
    return processed_document_from_decoded_text(decoded.text)


def process_document(data: bytes, file_type: FileType, source_filename: str | None = None) -> ProcessedDocument:
    try:
        if file_type == FileType.DOCX:
            from app.extraction.docx import DocxError, docx_to_processed_document
            try:
                return docx_to_processed_document(data)
            except DocxError as exc:
                raise DocumentProcessingError(str(exc)) from exc

        if file_type == FileType.DATASET:
            from app.extraction.structured_data import structured_to_processed_document
            return structured_to_processed_document(data, source_filename)

        if file_type == FileType.VIDEO:
            from app.extraction.video import VideoError, video_to_processed_document
            try:
                return video_to_processed_document(data, source_filename)
            except VideoError as exc:
                raise DocumentProcessingError(str(exc)) from exc

        if file_type == FileType.TEXT:
            return _text_document(data)

        if file_type == FileType.IMAGE:
            image = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")
            width = float(image.width)
            height = float(image.height)
            lines = _ocr_lines(image, 0, width, height)
            page = PageFrame(0, width, height, image, tuple(lines), True)
            return ProcessedDocument(file_type, (page,), 1, 1)

        document = fitz.open(stream=data, filetype="pdf")
        pages: list[PageFrame] = []
        scanned_pages = 0
        try:
            for page_index, page in enumerate(document):
                image = _render_page(page)
                digital = _digital_lines(page, page_index)
                digital_text = " ".join(line.text for line in digital).strip()
                use_ocr = len(digital_text) < 32
                if use_ocr:
                    scanned_pages += 1
                    lines = _ocr_lines(image, page_index, float(page.rect.width), float(page.rect.height))
                else:
                    lines = digital
                pages.append(
                    PageFrame(
                        page_index=page_index,
                        width=float(page.rect.width),
                        height=float(page.rect.height),
                        image=image,
                        lines=tuple(lines),
                        used_ocr=use_ocr,
                    )
                )
        finally:
            document.close()
        return ProcessedDocument(file_type, tuple(pages), len(pages), scanned_pages)
    except Exception as exc:
        if isinstance(exc, DocumentProcessingError):
            raise
        raise DocumentProcessingError(f"Document processing failed: {exc}") from exc
