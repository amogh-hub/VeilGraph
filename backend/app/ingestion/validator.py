from __future__ import annotations

import hashlib
import io
import re
from pathlib import Path

import fitz
from PIL import Image

from app.core.config import settings
from app.core.enums import FileType
from app.extraction.text_formats import TEXT_EXTENSIONS, TextFormatError, decode_text_document
from app.extraction.structured_data import DATASET_EXTENSIONS, StructuredDataError, parse_structured_data, XLSX_MEDIA_TYPE
from app.extraction.docx import DOCX_EXTENSION, DOCX_MEDIA_TYPE, DocxError, validate_docx
from app.extraction.video import VIDEO_EXTENSIONS, VIDEO_MEDIA_TYPES, VideoError, probe_video


class ValidationError(ValueError):
    pass


_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._ ()\-]+")


def sanitize_filename(filename: str) -> str:
    """Return a header-safe basename while preserving a useful extension."""
    candidate = (filename or "input").replace("\\", "/").split("/")[-1]
    candidate = _CONTROL_CHARS.sub("", candidate).strip()
    candidate = _UNSAFE_FILENAME_CHARS.sub("_", candidate)
    candidate = re.sub(r"\s+", " ", candidate).strip(" .")
    if not candidate:
        candidate = "input"
    if len(candidate) > 120:
        suffix = Path(candidate).suffix[:12]
        stem_budget = max(1, 120 - len(suffix))
        candidate = candidate[:stem_budget].rstrip(" .") + suffix
    return candidate or "input"


def _render_pixel_estimate(width_points: float, height_points: float) -> int:
    zoom = settings.ocr_dpi / 72.0
    width_px = max(1, int(round(width_points * zoom)))
    height_px = max(1, int(round(height_points * zoom)))
    return width_px * height_px


def validate_upload(data: bytes, filename: str) -> tuple[FileType, str, str]:
    if not data:
        raise ValidationError("File is empty")
    if len(data) > settings.max_file_size_bytes:
        raise ValidationError(
            f"File is {len(data) / (1024 * 1024):.1f} MB; maximum is "
            f"{settings.max_file_size_bytes / (1024 * 1024):.0f} MB"
        )

    safe_filename = sanitize_filename(filename)
    extension = Path(safe_filename).suffix.lower()
    sha256 = hashlib.sha256(data).hexdigest()

    if data.startswith(b"%PDF-"):
        if extension != ".pdf":
            raise ValidationError("PDF magic bytes do not match the filename extension")
        try:
            document = fitz.open(stream=data, filetype="pdf")
            try:
                if document.needs_pass or document.is_encrypted:
                    raise ValidationError("Password-protected or encrypted PDFs are not accepted")
                page_count = len(document)
                if page_count == 0:
                    raise ValidationError("PDF contains no pages")
                if page_count > settings.max_pdf_pages:
                    raise ValidationError(f"PDF exceeds the {settings.max_pdf_pages}-page limit")

                total_render_pixels = 0
                for page_index, page in enumerate(document):
                    width = float(page.rect.width)
                    height = float(page.rect.height)
                    if width <= 0 or height <= 0:
                        raise ValidationError(f"PDF page {page_index + 1} has invalid dimensions")
                    pixels = _render_pixel_estimate(width, height)
                    if pixels > settings.max_render_pixels_per_page:
                        raise ValidationError(
                            f"PDF page {page_index + 1} exceeds the safe rendering budget "
                            f"({pixels:,} pixels > {settings.max_render_pixels_per_page:,})"
                        )
                    total_render_pixels += pixels
                    if total_render_pixels > settings.max_total_render_pixels:
                        raise ValidationError(
                            "PDF exceeds the total safe rendering budget for local analysis"
                        )
            finally:
                document.close()
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Invalid PDF: {exc}") from exc
        return FileType.PDF, "application/pdf", sha256

    if extension in TEXT_EXTENSIONS:
        try:
            decoded = decode_text_document(data, safe_filename)
        except TextFormatError as exc:
            raise ValidationError(str(exc)) from exc
        if not decoded.text.strip():
            raise ValidationError("Text document contains no visible text")
        return FileType.TEXT, decoded.media_type, sha256

    if extension == DOCX_EXTENSION:
        try:
            validate_docx(data)
        except DocxError as exc:
            raise ValidationError(str(exc)) from exc
        return FileType.DOCX, DOCX_MEDIA_TYPE, sha256

    if extension in DATASET_EXTENSIONS:
        try:
            dataset = parse_structured_data(data, safe_filename)
        except StructuredDataError as exc:
            raise ValidationError(str(exc)) from exc
        media_type = {
            "csv": "text/csv; charset=utf-8",
            "json": "application/json",
            "xlsx": XLSX_MEDIA_TYPE,
        }[dataset.format]
        return FileType.DATASET, media_type, sha256

    if extension in VIDEO_EXTENSIONS:
        try:
            probe_video(data, safe_filename)
        except VideoError as exc:
            raise ValidationError(str(exc)) from exc
        return FileType.VIDEO, VIDEO_MEDIA_TYPES[extension], sha256

    if extension not in _IMAGE_EXTENSIONS:
        raise ValidationError("Supported inputs are PDF, PNG, JPG, JPEG, TXT, MD, RTF, DOCX, CSV, JSON, XLSX, MP4 and MOV")
    try:
        image = Image.open(io.BytesIO(data))
        width, height = image.size
        if width <= 0 or height <= 0:
            raise ValidationError("Image has invalid dimensions")
        pixels = int(width) * int(height)
        if pixels > settings.max_image_pixels:
            raise ValidationError(
                f"Image exceeds the {settings.max_image_pixels:,}-pixel decoding limit"
            )
        image.verify()
        detected = (image.format or "").upper()
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(f"Invalid image: {exc}") from exc

    if detected not in {"PNG", "JPEG"}:
        raise ValidationError(f"Unsupported image encoding: {detected or 'unknown'}")
    if detected == "PNG" and extension != ".png":
        raise ValidationError("PNG magic bytes do not match the filename extension")
    if detected == "JPEG" and extension not in {".jpg", ".jpeg"}:
        raise ValidationError("JPEG magic bytes do not match the filename extension")
    media_type = "image/png" if detected == "PNG" else "image/jpeg"
    return FileType.IMAGE, media_type, sha256
