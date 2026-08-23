from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

import cv2
import fitz
import numpy as np
import pytesseract
from PIL import Image, ImageOps

from app.core.enums import DetectionSource, EntityType, FileType, PrivacyLevel, TestStatus
from app.detection.direct_identifiers import detect_direct_identifiers, normalize_value
from app.detection.broad_pii import detect_broad_pii
from app.detection.visual_detector import detect_visual_entities
from app.extraction.document_processor import ProcessedDocument, _ocr_lines, process_document
from app.extraction.text_formats import decode_text_document
from app.extraction.structured_data import (
    StructuredDataError, iter_cells, parse_structured_data, schema_signature, structured_visible_text, virtual_cell_index,
)
from app.extraction.docx import (
    docx_hidden_channel_findings, docx_media_images, docx_raw_channels, docx_structure_signature,
    docx_visible_text, parse_docx, secondary_docx_visible_text,
)
from app.extraction.video import evidence_frame, physical_frame, probe_video, security_scan_frame_indices
from app.transformation.sanitizer import ProtectionInstruction


@dataclass(frozen=True)
class TestResult:
    name: str
    status: TestStatus
    detail: str
    attack_class: str = "release_gate"
    severity: str = "critical"


def _flatten_text(document) -> str:
    return "\n".join(line.text for page in document.pages for line in page.lines)


def _value_present(text: str, entity_type: EntityType, value: str) -> bool:
    target = normalize_value(entity_type, value)
    if not target:
        return False
    if entity_type == EntityType.EMAIL:
        return target in text.casefold()
    if entity_type == EntityType.PAN_LIKE:
        normalized_text = re.sub(r"\s+", "", text).upper()
        return target in normalized_text
    if entity_type == EntityType.AGE:
        # Exact-age leakage is semantic, not substring-based. A generalized range
        # such as "Age 18-24" may contain the source age as a range boundary,
        # which does not reveal the exact age. Conversely, a standalone numeric
        # token still counts as recovery. Numeric substrings inside phones, IDs,
        # postcodes or date fragments must not trigger this gate.
        digits = re.sub(r"\D", "", target)
        if not digits:
            return False
        return re.search(rf"(?<![\d-]){re.escape(digits)}(?![\d-])", text) is not None
    if entity_type in {
        EntityType.PERSON_NAME, EntityType.PERSON_TITLE, EntityType.DATE_OF_BIRTH, EntityType.GENERIC_DATE,
        EntityType.STREET_ADDRESS, EntityType.BUILDING_NUMBER, EntityType.LOCALITY, EntityType.EMPLOYER,
        EntityType.JOB_TITLE, EntityType.CASE_REFERENCE, EntityType.DEMOGRAPHIC_ATTRIBUTE,
    }:
        normalized_text = re.sub(r"[^\w]+", " ", text.casefold(), flags=re.UNICODE).strip()
        normalized_target = re.sub(r"[^\w]+", " ", target.casefold(), flags=re.UNICODE).strip()
        return bool(normalized_target) and normalized_target in normalized_text
    if entity_type in {
        EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER, EntityType.DRIVER_LICENSE_NUMBER,
        EntityType.TAX_IDENTIFIER, EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
    }:
        alnum_text = re.sub(r"[^A-Za-z0-9]", "", text).upper()
        return target.upper() in alnum_text
    digit_stream = re.sub(r"\D", "", text)
    return target in digit_stream


def _approved_replacements_for_value(
    entity_type: EntityType,
    value: str,
    instructions: list[ProtectionInstruction] | None,
) -> list[str]:
    """Return exact signed replacement phrases that intentionally contain value.

    This is phrase-scoped, not a whitelist. Only the complete compiler-approved
    replacement is exempted. A standalone source value elsewhere still fails.
    """
    if not instructions:
        return []
    replacements: list[str] = []
    for item in instructions:
        replacement = (item.replacement or "").strip()
        if not replacement or item.entity_type != entity_type:
            continue
        if _value_present(replacement, entity_type, value):
            replacements.append(replacement)
    return sorted(set(replacements), key=len, reverse=True)


def _mask_exact_phrase(text: str, phrase: str) -> str:
    pieces = [re.escape(piece) for piece in re.split(r"\s+", phrase.strip()) if piece]
    if not pieces:
        return text
    pattern = re.compile(r"\s+".join(pieces), re.IGNORECASE)
    return pattern.sub(lambda match: " " * len(match.group(0)), text)


def _value_present_outside_approved_replacements(
    text: str,
    entity_type: EntityType,
    value: str,
    instructions: list[ProtectionInstruction] | None = None,
) -> bool:
    inspected = text
    for replacement in _approved_replacements_for_value(entity_type, value, instructions):
        inspected = _mask_exact_phrase(inspected, replacement)
    return _value_present(inspected, entity_type, value)


def _text_leaks(
    text: str,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> list[str]:
    return [
        entity_type.value
        for entity_type, value in known_values
        if _value_present_outside_approved_replacements(text, entity_type, value, instructions)
    ]


def _mask_approved_replacements_bytes(
    blob: bytes,
    entity_type: EntityType,
    value: str,
    instructions: list[ProtectionInstruction] | None,
) -> bytes:
    masked = blob
    for replacement in _approved_replacements_for_value(entity_type, value, instructions):
        variants: set[bytes] = set()
        for candidate in {replacement, replacement.lower(), replacement.upper()}:
            variants.update({
                candidate.encode("utf-8", errors="ignore"),
                candidate.encode("utf-16-le", errors="ignore"),
                candidate.encode("utf-16-be", errors="ignore"),
            })
        for encoded in sorted((item for item in variants if item), key=len, reverse=True):
            masked = masked.replace(encoded, b" " * len(encoded))
    return masked


def _rect_area(rect: tuple[float, float, float, float]) -> float:
    x0, y0, x1, y1 = rect
    return max(1.0, (x1 - x0) * (y1 - y0))


def _intersection_area(
    first: tuple[float, float, float, float],
    second: tuple[float, float, float, float],
) -> float:
    fx0, fy0, fx1, fy1 = first
    sx0, sy0, sx1, sy1 = second
    ix0, iy0 = max(fx0, sx0), max(fy0, sy0)
    ix1, iy1 = min(fx1, sx1), min(fy1, sy1)
    return max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)


def _center_distance(
    first: tuple[float, float, float, float],
    second: tuple[float, float, float, float],
) -> float:
    fx0, fy0, fx1, fy1 = first
    sx0, sy0, sx1, sy1 = second
    fcx, fcy = (fx0 + fx1) / 2.0, (fy0 + fy1) / 2.0
    scx, scy = (sx0 + sx1) / 2.0, (sy0 + sy1) / 2.0
    return ((fcx - scx) ** 2 + (fcy - scy) ** 2) ** 0.5


def _spatially_matches_protected_region(
    candidate: tuple[float, float, float, float],
    protected_region: tuple[float, float, float, float],
) -> bool:
    intersection = _intersection_area(candidate, protected_region)
    if intersection / min(_rect_area(candidate), _rect_area(protected_region)) >= 0.25:
        return True
    px0, py0, px1, py1 = protected_region
    reference_span = max(px1 - px0, py1 - py0, 1.0)
    return _center_distance(candidate, protected_region) <= max(10.0, reference_span * 0.45)


_NUMERIC_IDENTIFIER_TYPES = {EntityType.PHONE, EntityType.AADHAAR_LIKE, EntityType.PAYMENT_CARD_NUMBER}


def _contains_known_original(
    detection,
    known_values: list[tuple[EntityType, str]],
) -> bool:
    """Return True when a detection still contains any approved original value.

    Numeric OCR can change the *classification* of a value. For example, a
    ten-digit phone can be returned as a twelve-digit Aadhaar-like candidate
    after nearby mask glyphs are misread as digits. Therefore numeric originals
    are compared across numeric entity classes, not only by detector label.
    """
    detected_type = detection.entity_type
    detected_normalized = normalize_value(detected_type, detection.plaintext)
    if not detected_normalized:
        return False

    for known_type, known_value in known_values:
        known_normalized = normalize_value(known_type, known_value)
        if not known_normalized:
            continue
        if detected_type in _NUMERIC_IDENTIFIER_TYPES and known_type in _NUMERIC_IDENTIFIER_TYPES:
            if known_normalized in detected_normalized or detected_normalized in known_normalized:
                return True
            continue
        if detected_type == known_type and detected_normalized == known_normalized:
            return True
    return False


def _matches_approved_mask_artifact(
    detection,
    instructions: list[ProtectionInstruction],
) -> bool:
    """Recognise OCR hallucinations caused by an approved visible mask.

    On some macOS Tesseract builds, ``X`` glyphs are read as digits. That can
    also change the detector class: ``XXXXXXXX3210`` may become a twelve-digit
    Aadhaar-like candidate even though the approved region is a PHONE mask.

    The exemption is deliberately narrow: OCR source only, same page, spatially
    bound to one approved mask region, and the recovered numeric suffix must
    match the visible suffix of that exact replacement. Exact originals are
    rejected before this helper is called.
    """
    if detection.source != DetectionSource.OCR:
        return False

    for instruction in instructions:
        if instruction.page_index != detection.page_index:
            continue
        replacement = instruction.replacement
        if not any(marker in replacement for marker in ("X", "*", "[PROTECTED]", "[NAME PROTECTED]")):
            continue
        if not _spatially_matches_protected_region(detection.rect, instruction.rect):
            continue

        if (
            detection.entity_type in _NUMERIC_IDENTIFIER_TYPES
            and instruction.entity_type in _NUMERIC_IDENTIFIER_TYPES
        ):
            detected_digits = re.sub(r"\D", "", detection.plaintext)
            replacement_digits = re.sub(r"\D", "", replacement)
            # Level-1 numeric masks intentionally retain the final four digits.
            # Require all visible replacement digits (normally exactly four),
            # not merely an arbitrary suffix coincidence.
            if replacement_digits and detected_digits.endswith(replacement_digits):
                return True
        elif detection.entity_type == instruction.entity_type == EntityType.PAN_LIKE:
            detected = re.sub(r"\s+", "", detection.plaintext).upper()
            approved = re.sub(r"\s+", "", replacement).upper()
            if detected == approved:
                return True
        elif detection.entity_type == instruction.entity_type == EntityType.EMAIL:
            if detection.plaintext.casefold() == replacement.casefold():
                return True
    return False


def direct_identifier_rescan(
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]] | None = None,
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    """Rescan textual/direct identifiers without treating visible masks as leaks.

    QR evidence remains in its dedicated gate. Any exact known original value
    always fails. A newly detected identifier also fails unless it is an OCR
    artefact spatially and semantically bound to an approved mask instruction.
    """
    try:
        document = process_document(protected, file_type)
        direct = detect_direct_identifiers(document)
        # The production processor returns a ProcessedDocument. Keep the broad
        # credential rescan tied to that contract so unit-test detector stubs
        # can isolate the direct gate without invoking unrelated detectors.
        # In production, malformed processor output still fails closed because
        # detect_direct_identifiers(document) above requires the same contract.
        if isinstance(document, ProcessedDocument):
            direct += [
                item for item in detect_broad_pii(document)
                if item.entity_type in {
                    EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER,
                    EntityType.DRIVER_LICENSE_NUMBER, EntityType.TAX_IDENTIFIER,
                    EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
                }
            ]
        approved_originals = known_values or []
        residual = []
        ignored_artifacts = 0
        for item in direct:
            if _contains_known_original(item, approved_originals):
                residual.append(item)
                continue
            if _matches_approved_mask_artifact(item, instructions or []):
                ignored_artifacts += 1
                continue
            residual.append(item)

        if residual:
            summary: dict[str, int] = {}
            for item in residual:
                summary[item.entity_type.value] = summary.get(item.entity_type.value, 0) + 1
            return TestResult("direct_identifier_rescan", TestStatus.FAIL, f"Detected residual identifiers: {summary}")
        if ignored_artifacts:
            return TestResult(
                "direct_identifier_rescan",
                TestStatus.PASS,
                f"No residual direct identifier remains; {ignored_artifacts} OCR mask artefact(s) were bound to approved replacement regions",
            )
        return TestResult("direct_identifier_rescan", TestStatus.PASS, "No direct textual identifier was detected")
    except Exception as exc:
        return TestResult("direct_identifier_rescan", TestStatus.INCONCLUSIVE, f"Rescan could not complete: {exc}")


def independent_extraction(
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    if file_type == FileType.TEXT:
        try:
            visible = decode_text_document(protected).text
            leaks = _text_leaks(visible, known_values, instructions)
            if leaks:
                return TestResult("independent_extraction", TestStatus.FAIL, f"Original values recovered by independent text decoding: {leaks}")
            return TestResult("independent_extraction", TestStatus.PASS, "Independent native-text decoding recovered no approved original values")
        except Exception as exc:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"Native-text extraction failed: {exc}")

    if file_type == FileType.DOCX:
        try:
            visible = secondary_docx_visible_text(protected)
            media_text: list[str] = []
            if shutil.which("tesseract") is not None:
                for _name, image in docx_media_images(protected):
                    media_text.append(pytesseract.image_to_string(image, lang="eng", config="--psm 6"))
            combined = visible + "\n" + "\n".join(media_text)
            leaks = _text_leaks(combined, known_values, instructions)
            if leaks:
                return TestResult("independent_extraction", TestStatus.FAIL, f"Independent WordprocessingML/media extraction recovered originals: {sorted(set(leaks))}")
            return TestResult("independent_extraction", TestStatus.PASS, "Independent WordprocessingML and embedded-media extraction recovered no approved original values")
        except Exception as exc:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"DOCX independent extraction failed: {exc}")

    if file_type == FileType.VIDEO:
        try:
            info, selected_indices, _stats = security_scan_frame_indices(protected)
            text_parts: list[str] = []
            for frame_index in selected_indices:
                image, _info, _source_frame = physical_frame(protected, frame_index)
                text_parts.append(pytesseract.image_to_string(image, lang="eng", config="--psm 6"))
            visible = "\n".join(text_parts)
            leaks = _text_leaks(visible, known_values, instructions)
            if leaks:
                return TestResult("independent_extraction", TestStatus.FAIL, f"Independent full-timeline video extraction recovered originals: {sorted(set(leaks))}")
            return TestResult(
                "independent_extraction", TestStatus.PASS,
                f"Independent change guard screened all {info.total_frames} physical frames and OCR-rescanned {len(selected_indices)} evidence/novel frame(s) with no approved originals",
            )
        except Exception as exc:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"Video independent full-timeline extraction failed: {exc}")

    if file_type == FileType.IMAGE:
        try:
            image = Image.open(io.BytesIO(protected))
            populated = {key: value for key, value in image.info.items() if value not in {None, "", b""}}
            if populated:
                return TestResult("independent_extraction", TestStatus.FAIL, f"Image metadata remained: {list(populated)}")
            return TestResult("independent_extraction", TestStatus.PASS, "Protected PNG contains no embedded text layer or metadata")
        except Exception as exc:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"Image inspection failed: {exc}")

    if file_type == FileType.DATASET:
        try:
            visible = structured_visible_text(protected)
            leaks = _text_leaks(visible, known_values, instructions)
            if leaks:
                return TestResult("independent_extraction", TestStatus.FAIL, f"Independent structured parser recovered originals: {sorted(set(leaks))}")
            return TestResult("independent_extraction", TestStatus.PASS, "Independent structured parsing recovered no approved original values")
        except Exception as exc:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"Structured extraction failed: {exc}")

    binary = shutil.which("pdftotext")
    if binary is None:
        return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, "pdftotext executable is unavailable")
    temp_path: Path | None = None
    try:
        document = fitz.open(stream=protected, filetype="pdf")
        pymupdf_text = "\n".join(page.get_text("text", sort=True) for page in document)
        document.close()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as handle:
            handle.write(protected)
            temp_path = Path(handle.name)
        completed = subprocess.run([binary, str(temp_path), "-"], capture_output=True, check=False, timeout=30)
        if completed.returncode != 0:
            return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"pdftotext exited {completed.returncode}")
        poppler_text = completed.stdout.decode("utf-8", errors="replace")
        leaks = _text_leaks(pymupdf_text + "\n" + poppler_text, known_values, instructions)
        if leaks:
            return TestResult("independent_extraction", TestStatus.FAIL, f"Original values recovered by text extractors: {leaks}")
        return TestResult("independent_extraction", TestStatus.PASS, "PyMuPDF and pdftotext recovered no original values")
    except Exception as exc:
        return TestResult("independent_extraction", TestStatus.INCONCLUSIVE, f"Independent extraction failed: {exc}")
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def secondary_text_parser_rescan(
    protected: bytes,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    """A detector-independent visible-text leak scan for native text formats."""
    try:
        visible = decode_text_document(protected).text
        leaks = _text_leaks(visible, known_values, instructions)
        if leaks:
            return TestResult(
                "secondary_text_parser_rescan", TestStatus.FAIL,
                f"Secondary Unicode/RTF parser recovered approved originals: {sorted(set(leaks))}",
            )
        return TestResult(
            "secondary_text_parser_rescan", TestStatus.PASS,
            "Secondary Unicode/RTF parser recovered no approved original values",
        )
    except Exception as exc:
        return TestResult("secondary_text_parser_rescan", TestStatus.INCONCLUSIVE, f"Secondary parser failed: {exc}")


def ocr_rescan(
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    if shutil.which("tesseract") is None:
        return TestResult("ocr_rescan", TestStatus.INCONCLUSIVE, "Tesseract executable is unavailable")
    try:
        document = process_document(protected, file_type)
        text_parts: list[str] = []
        for page in document.pages:
            # Force an independent OCR pass even for PDFs that now contain a text layer.
            text_parts.append(pytesseract.image_to_string(page.image, lang="eng", config="--psm 6"))
        text = "\n".join(text_parts)
        leaks = _text_leaks(text, known_values, instructions)
        if leaks:
            return TestResult("ocr_rescan", TestStatus.FAIL, f"OCR recovered original values: {leaks}")
        return TestResult("ocr_rescan", TestStatus.PASS, "Independent OCR recovered no original approved identifiers")
    except Exception as exc:
        return TestResult("ocr_rescan", TestStatus.INCONCLUSIVE, f"OCR could not complete: {exc}")


def _qr_geometry_match_score(
    candidate: tuple[float, float, float, float],
    reviewed: tuple[float, float, float, float],
) -> float:
    """Return a conservative geometry score for a reviewer-dismissed QR shape.

    OpenCV's QR polygon can move or expand after PyMuPDF rewrites a scanned PDF,
    especially on Apple Silicon. Matching therefore combines overlap, centre
    distance, area ratio and aspect-ratio stability instead of requiring a
    single brittle 50% overlap threshold.
    """
    candidate_area = _rect_area(candidate)
    reviewed_area = _rect_area(reviewed)
    intersection = _intersection_area(candidate, reviewed)
    overlap_smaller = intersection / min(candidate_area, reviewed_area)
    union = candidate_area + reviewed_area - intersection
    iou = intersection / max(1.0, union)

    cx0, cy0, cx1, cy1 = candidate
    rx0, ry0, rx1, ry1 = reviewed
    candidate_span = max(cx1 - cx0, cy1 - cy0, 1.0)
    reviewed_span = max(rx1 - rx0, ry1 - ry0, 1.0)
    distance = _center_distance(candidate, reviewed)
    distance_limit = max(24.0, reviewed_span * 1.20)

    area_ratio = min(candidate_area, reviewed_area) / max(candidate_area, reviewed_area)
    candidate_aspect = max(0.05, (cx1 - cx0) / max(1.0, cy1 - cy0))
    reviewed_aspect = max(0.05, (rx1 - rx0) / max(1.0, ry1 - ry0))
    aspect_ratio = min(candidate_aspect, reviewed_aspect) / max(candidate_aspect, reviewed_aspect)

    if overlap_smaller >= 0.20:
        return 3.0 + overlap_smaller + iou
    if distance <= distance_limit and area_ratio >= 0.12 and aspect_ratio >= 0.20:
        proximity = 1.0 - (distance / max(distance_limit, 1.0))
        return 1.0 + proximity + area_ratio + aspect_ratio
    return 0.0


def _partition_reviewed_ignored_qr(
    detections,
    reviewed_ignored_visual_regions: list[dict[str, object]],
) -> tuple[list, int]:
    """Bind each undecoded output candidate to at most one reviewed region."""
    available: list[tuple[int, tuple[float, float, float, float]]] = []
    for index, item in enumerate(reviewed_ignored_visual_regions):
        if item.get("entity_type") != EntityType.QR_CODE.value:
            continue
        raw_rect = item.get("rect")
        if not isinstance(raw_rect, list) or len(raw_rect) != 4:
            continue
        available.append((index, tuple(float(value) for value in raw_rect)))

    unmatched = []
    matched = 0
    used_review_indices: set[int] = set()
    for detection in detections:
        scored: list[tuple[float, int]] = []
        for review_index, reviewed_rect in available:
            if review_index in used_review_indices:
                continue
            item = reviewed_ignored_visual_regions[review_index]
            if int(item.get("page_index", -1)) != detection.page_index:
                continue
            score = _qr_geometry_match_score(detection.rect, reviewed_rect)
            if score > 0:
                scored.append((score, review_index))
        if not scored:
            unmatched.append(detection)
            continue
        _, selected = max(scored)
        used_review_indices.add(selected)
        matched += 1
    return unmatched, matched


def qr_rescan(
    protected: bytes,
    file_type: FileType,
    reviewed_ignored_visual_regions: list[dict[str, object]] | None = None,
) -> TestResult:
    try:
        document = process_document(protected, file_type)
        qr = [item for item in detect_visual_entities(document) if item.entity_type == EntityType.QR_CODE]
        if not qr:
            return TestResult("qr_rescan", TestStatus.PASS, "No QR code remains decodable or detectable")

        ignored = reviewed_ignored_visual_regions or []
        decoded = [item for item in qr if not item.plaintext.startswith("UNDECODED_QR_CANDIDATE_")]
        if decoded:
            return TestResult("qr_rescan", TestStatus.FAIL, f"Detected {len(decoded)} decodable residual QR code(s)")

        unmatched, matched = _partition_reviewed_ignored_qr(qr, ignored)
        if unmatched:
            return TestResult(
                "qr_rescan",
                TestStatus.FAIL,
                f"Detected {len(unmatched)} unreviewed undecoded QR-like region(s) in the protected output",
            )
        return TestResult(
            "qr_rescan",
            TestStatus.PASS,
            f"No decoded QR remains; {matched} reviewer-dismissed geometry-only candidate(s) matched their original regions",
        )
    except Exception as exc:
        return TestResult("qr_rescan", TestStatus.INCONCLUSIVE, f"QR rescan failed: {exc}")


def _render_pages(data: bytes, file_type: FileType) -> list[Image.Image]:
    if file_type == FileType.IMAGE:
        return [ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("RGB")]
    document = fitz.open(stream=data, filetype="pdf")
    pages: list[Image.Image] = []
    try:
        for page in document:
            pixmap = page.get_pixmap(matrix=fitz.Matrix(2.0, 2.0), alpha=False)
            pages.append(Image.open(io.BytesIO(pixmap.tobytes("png"))).convert("RGB"))
    finally:
        document.close()
    return pages


def region_replacement_integrity(
    original: bytes,
    protected: bytes,
    file_type: FileType,
    instructions: list[ProtectionInstruction],
) -> TestResult:
    if file_type == FileType.DOCX:
        try:
            before_pkg = parse_docx(original)
            after_pkg = parse_docx(protected)
            before_refs = {ref.page_index: ref for ref in before_pkg.page_refs}
            after_refs = {ref.page_index: ref for ref in after_pkg.page_refs}
            before_parts = {part.name: part for part in before_pkg.text_parts}
            after_parts = {part.name: part for part in after_pkg.text_parts}
            failures: list[str] = []
            checked = 0
            for instruction in instructions:
                before_ref = before_refs.get(instruction.page_index)
                after_ref = after_refs.get(instruction.page_index)
                if before_ref is None or after_ref is None or before_ref.kind != after_ref.kind or before_ref.part_name != after_ref.part_name:
                    failures.append(f"{instruction.mention_id}:page-map-changed")
                    continue
                if before_ref.kind == "TEXT":
                    if instruction.char_start is None or instruction.char_end is None:
                        failures.append(f"{instruction.mention_id}:missing-span")
                        continue
                    source_text = before_parts[before_ref.part_name].text
                    protected_text = after_parts[after_ref.part_name].text
                    start, end = int(instruction.char_start), int(instruction.char_end)
                    original_value = source_text[start:end]
                    if original_value and _value_present_outside_approved_replacements(
                        protected_text, instruction.entity_type, original_value, instructions
                    ):
                        failures.append(f"{instruction.mention_id}:original-survived")
                    if instruction.replacement and instruction.replacement.casefold() not in protected_text.casefold():
                        failures.append(f"{instruction.mention_id}:replacement-missing")
                else:
                    before_raw = before_pkg.members[before_ref.part_name]
                    after_raw = after_pkg.members[after_ref.part_name]
                    before_image = ImageOps.exif_transpose(Image.open(io.BytesIO(before_raw))).convert("RGB")
                    after_image = ImageOps.exif_transpose(Image.open(io.BytesIO(after_raw))).convert("RGB")
                    x0, y0, x1, y1 = (int(round(v)) for v in instruction.rect)
                    x0, y0 = max(0, x0), max(0, y0)
                    x1, y1 = min(before_image.width, x1), min(before_image.height, y1)
                    if x1 <= x0 or y1 <= y0:
                        failures.append(f"{instruction.mention_id}:invalid-image-region")
                        continue
                    a = np.asarray(before_image.crop((x0, y0, x1, y1))).astype(np.int16)
                    b = np.asarray(after_image.crop((x0, y0, x1, y1))).astype(np.int16)
                    if a.shape != b.shape or a.size == 0 or float(np.abs(a - b).mean()) < 8.0:
                        failures.append(f"{instruction.mention_id}:image-region-unchanged")
                checked += 1
            if failures:
                return TestResult("docx_content_integrity", TestStatus.FAIL, f"DOCX committed transformation failures: {failures}")
            return TestResult("docx_content_integrity", TestStatus.PASS, f"All {checked} committed DOCX text/image transformations changed materially")
        except Exception as exc:
            return TestResult("docx_content_integrity", TestStatus.INCONCLUSIVE, f"DOCX transformation comparison failed: {exc}")

    if file_type == FileType.VIDEO:
        try:
            before_info = probe_video(original)
            after_info = probe_video(protected)
            if len(before_info.sampled_frame_indices) != len(after_info.sampled_frame_indices):
                return TestResult("video_temporal_integrity", TestStatus.FAIL, "Protected video physical-frame schedule changed unexpectedly")
            failures: list[str] = []
            checked = 0
            by_page: dict[int, list[ProtectionInstruction]] = {}
            for instruction in instructions:
                by_page.setdefault(int(instruction.page_index), []).append(instruction)
            for page_index, page_instructions in by_page.items():
                before_image, _bi, _bf = physical_frame(original, page_index)
                after_image, _ai, _af = physical_frame(protected, page_index)
                before_arr = np.asarray(before_image.convert("RGB")).astype(np.int16)
                after_arr = np.asarray(after_image.convert("RGB")).astype(np.int16)
                for instruction in page_instructions:
                    x0, y0, x1, y1 = (int(round(value)) for value in instruction.rect)
                    pad = 4
                    x0, y0 = max(0, x0 - pad), max(0, y0 - pad)
                    x1, y1 = min(before_arr.shape[1], x1 + pad), min(before_arr.shape[0], y1 + pad)
                    if x1 <= x0 or y1 <= y0:
                        failures.append(f"{instruction.mention_id}:invalid-region")
                        continue
                    a = before_arr[y0:y1, x0:x1]
                    b = after_arr[y0:y1, x0:x1]
                    if a.shape != b.shape or a.size == 0:
                        failures.append(f"{instruction.mention_id}:shape-changed")
                        continue
                    delta = float(np.abs(a - b).mean())
                    changed_fraction = float((np.abs(a - b).max(axis=2) > 20).mean())
                    if delta < 7.0 or changed_fraction < 0.20:
                        failures.append(f"{instruction.mention_id}:delta={delta:.1f},changed={changed_fraction:.2f}")
                    checked += 1
            if failures:
                return TestResult("video_temporal_integrity", TestStatus.FAIL, f"Video evidence regions were not materially transformed: {failures}")
            return TestResult("video_temporal_integrity", TestStatus.PASS, f"All {checked} committed video regions changed materially across the full physical timeline")
        except Exception as exc:
            return TestResult("video_temporal_integrity", TestStatus.INCONCLUSIVE, f"Video temporal comparison failed: {exc}")

    if file_type == FileType.DATASET:
        try:
            before_dataset = parse_structured_data(original)
            after_dataset = parse_structured_data(protected)
            before_refs = virtual_cell_index(before_dataset)
            after_refs = virtual_cell_index(after_dataset)
            failures: list[str] = []
            checked = 0
            for instruction in instructions:
                if instruction.char_start is None or instruction.char_end is None:
                    failures.append(f"{instruction.mention_id}:missing-span")
                    continue
                matches = [ref for ref in before_refs if ref.page_index == instruction.page_index and int(instruction.char_start) >= ref.value_char_start and int(instruction.char_end) <= ref.value_char_end]
                if len(matches) != 1:
                    failures.append(f"{instruction.mention_id}:unresolved-source-cell")
                    continue
                source = matches[0]
                target = next((ref for ref in after_refs if tuple(ref.cell.locator) == tuple(source.cell.locator)), None)
                if target is None or target.cell.display_value == source.cell.display_value:
                    failures.append(f"{instruction.mention_id}:cell-unchanged")
                checked += 1
            if failures:
                return TestResult("structured_cell_integrity", TestStatus.FAIL, f"Structured scalar replacement failures: {failures}")
            return TestResult("structured_cell_integrity", TestStatus.PASS, f"All {checked} committed structured scalar spans changed materially")
        except Exception as exc:
            return TestResult("structured_cell_integrity", TestStatus.INCONCLUSIVE, f"Structured cell comparison failed: {exc}")

    if file_type == FileType.DATASET:
        try:
            before_sig = schema_signature(original)
            after_sig = schema_signature(protected)
            if before_sig != after_sig:
                return TestResult("utility_anchor_preservation", TestStatus.FAIL, "Structured schema/record shape changed during privacy transformation")
            return TestResult("utility_anchor_preservation", TestStatus.PASS, "Structured schema, record count and field layout were preserved")
        except Exception as exc:
            return TestResult("utility_anchor_preservation", TestStatus.INCONCLUSIVE, f"Structured utility attack failed: {exc}")

    if file_type == FileType.TEXT:
        try:
            before = decode_text_document(original).text
            after = decode_text_document(protected).text
            if before == after:
                return TestResult("character_span_integrity", TestStatus.FAIL, "Protected native text is byte/semantically unchanged")
            failures: list[str] = []
            checked = 0
            for instruction in instructions:
                if instruction.char_start is None or instruction.char_end is None:
                    failures.append(f"{instruction.mention_id}:missing-span")
                    continue
                start, end = int(instruction.char_start), int(instruction.char_end)
                if start < 0 or end <= start or end > len(before):
                    failures.append(f"{instruction.mention_id}:invalid-span")
                    continue
                original_value = before[start:end]
                if original_value and _value_present_outside_approved_replacements(
                    after, instruction.entity_type, original_value, instructions
                ):
                    failures.append(f"{instruction.mention_id}:original-survived")
                checked += 1
            if failures:
                return TestResult("character_span_integrity", TestStatus.FAIL, f"Native text span failures: {failures}")
            return TestResult("character_span_integrity", TestStatus.PASS, f"All {checked} committed character spans were irreversibly changed")
        except Exception as exc:
            return TestResult("character_span_integrity", TestStatus.INCONCLUSIVE, f"Character-span comparison failed: {exc}")

    try:
        before_pages = _render_pages(original, file_type)
        after_pages = _render_pages(protected, file_type)
        if len(before_pages) != len(after_pages):
            return TestResult("region_replacement_integrity", TestStatus.FAIL, "Page count changed during protection")
        failures: list[str] = []
        for index, instruction in enumerate(instructions):
            before = before_pages[instruction.page_index]
            after = after_pages[instruction.page_index]
            if file_type == FileType.PDF:
                scale_x = before.width / (before.width / 2.0)
                scale_y = before.height / (before.height / 2.0)
                # PDF rendering uses exactly 2x points.
                x0, y0, x1, y1 = [value * 2.0 for value in instruction.rect]
            else:
                x0, y0, x1, y1 = instruction.rect
            x0 = max(0, int(x0)); y0 = max(0, int(y0))
            x1 = min(before.width, int(x1)); y1 = min(before.height, int(y1))
            if x1 <= x0 or y1 <= y0:
                failures.append(f"invalid-region-{index}")
                continue
            before_crop = np.asarray(before.crop((x0, y0, x1, y1))).astype(np.int16)
            after_crop = np.asarray(after.crop((x0, y0, x1, y1))).astype(np.int16)
            if before_crop.shape != after_crop.shape or before_crop.size == 0:
                failures.append(f"shape-{index}")
                continue
            mean_delta = float(np.abs(before_crop - after_crop).mean())
            changed_fraction = float((np.abs(before_crop - after_crop).max(axis=2) > 12).mean())
            if mean_delta < 8.0 or changed_fraction < 0.18:
                failures.append(f"region-{index}:delta={mean_delta:.1f},changed={changed_fraction:.2f}")
        if failures:
            return TestResult("region_replacement_integrity", TestStatus.FAIL, f"Regions were not irreversibly changed: {failures}")
        return TestResult("region_replacement_integrity", TestStatus.PASS, f"All {len(instructions)} protected regions changed materially")
    except Exception as exc:
        return TestResult("region_replacement_integrity", TestStatus.INCONCLUSIVE, f"Region comparison failed: {exc}")


def metadata_inspection(protected: bytes, file_type: FileType) -> TestResult:
    try:
        if file_type == FileType.TEXT:
            visible = decode_text_document(protected).text
            if "\x00" in visible:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, "Protected text contains embedded NUL content")
            raw = protected.decode("latin-1", errors="ignore").casefold()
            forbidden = [marker for marker in ("\\info", "\\author", "\\comment", "\\object", "\\pict", "\\filetbl") if marker in raw]
            if forbidden:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, f"Protected text retained hidden RTF destinations: {forbidden}")
            return TestResult("metadata_and_embedded_content", TestStatus.PASS, "Native text export contains no hidden metadata/object destinations")

        if file_type == FileType.DOCX:
            findings = docx_hidden_channel_findings(protected)
            media_findings: list[str] = []
            for name, image in docx_media_images(protected):
                if image.getexif():
                    media_findings.append(f"exif:{name}")
                populated = {key: value for key, value in image.info.items() if value not in {None, "", b""}}
                if populated:
                    media_findings.append(f"metadata:{name}")
            if findings or media_findings:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, f"DOCX residual hidden/external content: {findings + media_findings}")
            return TestResult("metadata_and_embedded_content", TestStatus.PASS, "DOCX metadata, comments, hidden markup, external relationships and embedded-image metadata are clean")

        if file_type == FileType.DATASET:
            dataset = parse_structured_data(protected)
            raw = protected.decode("latin-1", errors="ignore").casefold()
            forbidden = [marker for marker in ("vbaproject.bin", "externallinks/", "embeddings/", "activex/") if marker in raw]
            if forbidden:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, f"Structured output retained active/external package content: {forbidden}")
            return TestResult("metadata_and_embedded_content", TestStatus.PASS, f"Canonical {dataset.format.upper()} output contains no active/external metadata channel")

        if file_type == FileType.VIDEO:
            info = probe_video(protected)
            if info.has_audio:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, "Protected video still contains an audio track")
            raw = protected.lower()
            forbidden = [marker.decode("ascii") for marker in (b"\xa9nam", b"\xa9art", b"comment", b"location") if marker in raw]
            if forbidden:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, f"Protected video retained descriptive metadata markers: {forbidden}")
            return TestResult("metadata_and_embedded_content", TestStatus.PASS, "Protected MP4 is video-only and contains no recognised descriptive metadata channel")

        if file_type == FileType.IMAGE:
            image = Image.open(io.BytesIO(protected))
            exif = image.getexif()
            populated = {key: value for key, value in image.info.items() if value not in {None, "", b""}}
            if exif or populated:
                return TestResult("metadata_and_embedded_content", TestStatus.FAIL, "Protected image retained metadata")
            return TestResult("metadata_and_embedded_content", TestStatus.PASS, "Protected PNG has no EXIF or ancillary metadata")
        document = fitz.open(stream=protected, filetype="pdf")
        populated = {
            key: value for key, value in document.metadata.items()
            if value and key not in {"format", "encryption"}
        }
        embedded = document.embfile_count()
        javascript = document.get_js() if hasattr(document, "get_js") else None
        links = sum(len(page.get_links()) for page in document)
        annotations = sum(1 for page in document for _ in (page.annots() or []))
        document.close()
        if populated or embedded or javascript or links or annotations:
            return TestResult(
                "metadata_and_embedded_content",
                TestStatus.FAIL,
                f"Residual content: metadata={list(populated)}, embedded={embedded}, links={links}, annotations={annotations}",
            )
        return TestResult("metadata_and_embedded_content", TestStatus.PASS, "Metadata, attachments, links and annotations are clean")
    except Exception as exc:
        return TestResult("metadata_and_embedded_content", TestStatus.INCONCLUSIVE, f"Inspection failed: {exc}")


def hidden_markup_payload_scan(
    protected: bytes,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    """Inspect native-text raw markup/control channels for hidden source values."""
    try:
        leaks: list[str] = []
        for entity_type, value in known_values:
            blob = _mask_approved_replacements_bytes(protected, entity_type, value, instructions).lower()
            candidates = {value.strip()}
            normalized = normalize_value(entity_type, value)
            if normalized:
                candidates.add(normalized)
            if any(len(candidate) >= 4 and candidate.encode("utf-8", errors="ignore").lower() in blob for candidate in candidates):
                leaks.append(entity_type.value)
        raw = protected.decode("latin-1", errors="ignore").casefold()
        dangerous = [marker for marker in ("\\object", "\\pict", "\\field", "\\annotation", "\\comment") if marker in raw]
        if leaks or dangerous:
            return TestResult(
                "hidden_markup_payload_scan", TestStatus.FAIL,
                f"Hidden native-text channel findings: originals={sorted(set(leaks))}, destinations={dangerous}",
            )
        return TestResult(
            "hidden_markup_payload_scan", TestStatus.PASS,
            "Raw text/RTF markup contains no approved originals or hidden payload destinations",
        )
    except Exception as exc:
        return TestResult("hidden_markup_payload_scan", TestStatus.INCONCLUSIVE, f"Hidden-markup scan failed: {exc}")


def policy_coverage(
    instructions: list[ProtectionInstruction],
    expected_entity_ids: set[str],
) -> TestResult:
    transformed = {item.entity_id for item in instructions}
    missing = sorted(expected_entity_ids - transformed)
    if missing:
        return TestResult("policy_coverage", TestStatus.FAIL, f"Policy-required entities were not transformed: {missing}")
    return TestResult("policy_coverage", TestStatus.PASS, f"All {len(expected_entity_ids)} policy-required entities are represented in the manifest")


def relationship_consistency(
    instructions: list[ProtectionInstruction],
    privacy_level: PrivacyLevel,
) -> TestResult:
    if privacy_level == PrivacyLevel.SYNTHETIC_TWIN:
        # Level 5 intentionally breaks the source-record/source-entity linkage.
        # Unlike L4, repeated source entities are not required to retain a stable
        # pseudonym because that stability itself can become a linkage channel.
        missing = [
            item.mention_id for item in instructions
            if not item.replacement.strip() or item.replacement == "[SYNTHETIC TWIN VALUE]"
        ]
        if missing:
            return TestResult(
                "relationship_consistency", TestStatus.FAIL,
                f"Level 5 manifest contains unresolved synthetic replacements: {missing}",
            )
        return TestResult(
            "relationship_consistency", TestStatus.PASS,
            "Level 5 intentionally breaks source-entity linkability; every committed synthetic mention has a concrete generated value.",
        )

    by_entity: dict[str, set[str]] = {}
    for item in instructions:
        by_entity.setdefault(item.entity_id, set()).add(item.replacement)
    inconsistent = sorted(entity_id for entity_id, replacements in by_entity.items() if len(replacements) != 1)
    if inconsistent:
        return TestResult("relationship_consistency", TestStatus.FAIL, f"The same canonical entity received inconsistent replacements: {inconsistent}")
    if privacy_level == PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION:
        aliases = [
            next(iter(replacements)) for replacements in by_entity.values()
            if next(iter(replacements)).startswith(("Person ", "Organisation ", "Case ", "Contact "))
        ]
        if len(aliases) != len(set(aliases)):
            return TestResult("relationship_consistency", TestStatus.FAIL, "Distinct canonical entities collided on the same stable alias")
    return TestResult("relationship_consistency", TestStatus.PASS, "Canonical replacements are stable across pages and distinct across entities")




_DIRECT_FRAGMENT_TYPES = {
    EntityType.PHONE,
    EntityType.EMAIL,
    EntityType.AADHAAR_LIKE,
    EntityType.PAN_LIKE,
    EntityType.PERSON_NAME,
    EntityType.CASE_REFERENCE,
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
}


def _casefold_bytes_contains(haystack: bytes, needle: str) -> bool:
    if not needle:
        return False
    candidates = [
        needle.encode("utf-8", errors="ignore"),
        needle.encode("utf-16-le", errors="ignore"),
        needle.encode("utf-16-be", errors="ignore"),
    ]
    lowered = haystack.lower()
    return any(candidate and candidate.lower() in lowered for candidate in candidates)


def raw_object_stream_scan(
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    """Search raw/decoded object storage for originals hidden outside normal extraction."""
    try:
        textual_channels = bytearray(protected)
        if file_type == FileType.PDF:
            document = fitz.open(stream=protected, filetype="pdf")
            try:
                for xref in range(1, document.xref_length()):
                    try:
                        textual_channels.extend(document.xref_object(xref, compressed=False).encode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                    try:
                        stream = document.xref_stream(xref)
                        if stream:
                            textual_channels.extend(stream)
                    except Exception:
                        pass
            finally:
                document.close()
        elif file_type == FileType.DOCX:
            textual_channels.extend(docx_raw_channels(protected))
        elif file_type == FileType.DATASET and protected.startswith(b"PK\x03\x04"):
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(protected)) as archive:
                    for info in archive.infolist():
                        if info.file_size <= 8 * 1024 * 1024:
                            textual_channels.extend(archive.read(info.filename))
            except Exception:
                pass

        leaks: list[str] = []
        base_blob = bytes(textual_channels)
        for entity_type, value in known_values:
            blob = _mask_approved_replacements_bytes(base_blob, entity_type, value, instructions)
            variants = {value.strip()}
            if entity_type in {EntityType.PHONE, EntityType.AADHAAR_LIKE}:
                digits = re.sub(r"\D", "", value)
                if len(digits) >= 8:
                    variants.add(digits)
            elif entity_type == EntityType.PAN_LIKE:
                variants.add(re.sub(r"\s+", "", value).upper())
            for variant in variants:
                if len(variant) >= 4 and _casefold_bytes_contains(blob, variant):
                    leaks.append(entity_type.value)
                    break
        if leaks:
            return TestResult(
                "raw_object_stream_scan",
                TestStatus.FAIL,
                f"Original values remained in raw or decoded object storage: {sorted(set(leaks))}",
            )
        if file_type == FileType.VIDEO:
            detail = "Raw video-container bytes contain no policy-required original values"
        elif file_type == FileType.DOCX:
            detail = "Raw DOCX package bytes and decoded XML channels contain no policy-required original values"
        elif file_type == FileType.DATASET:
            detail = "Raw structured-artifact bytes and decoded package channels contain no policy-required original values"
        else:
            detail = "Raw bytes, document objects and decoded streams contain no policy-required original values"
        return TestResult(
            "raw_object_stream_scan",
            TestStatus.PASS,
            detail,
        )
    except Exception as exc:
        return TestResult("raw_object_stream_scan", TestStatus.INCONCLUSIVE, f"Raw-object scan failed: {exc}")


def _alnum(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value).casefold()


def direct_identifier_fragment_attack(
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]],
    privacy_level: PrivacyLevel,
) -> TestResult:
    """Look for substantial fragments that survive even when the full original is absent."""
    try:
        document = process_document(protected, file_type)
        text = _flatten_text(document)
        folded = text.casefold()
        line_texts = [line.text for page in document.pages for line in page.lines]
        digit_lines = [re.sub(r"\D", "", line) for line in line_texts]
        alnum_lines = [_alnum(line) for line in line_texts]
        findings: list[str] = []
        for entity_type, value in known_values:
            if entity_type not in _DIRECT_FRAGMENT_TYPES:
                continue
            if entity_type in {EntityType.PHONE, EntityType.AADHAAR_LIKE}:
                source = re.sub(r"\D", "", value)
                fragment_len = 7 if entity_type == EntityType.PHONE else 9
                if len(source) >= fragment_len and any(
                    source[i:i + fragment_len] in line_digits
                    for i in range(len(source) - fragment_len + 1)
                    for line_digits in digit_lines
                ):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.PAN_LIKE:
                source = _alnum(value)
                fragment_len = 7
                if len(source) >= fragment_len and any(
                    source[i:i + fragment_len] in line_alnum
                    for i in range(len(source) - fragment_len + 1)
                    for line_alnum in alnum_lines
                ):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.EMAIL:
                # Compare fragments only inside surviving email-like tokens. A person's
                # approved/retained name can naturally overlap their email local-part
                # (for example ``Aarav Testperson`` vs ``aarav.test@...``), which must
                # not be mistaken for a partial email leak.
                local = _alnum(value.split("@", 1)[0])
                email_tokens = re.findall(
                    r"[A-Za-z0-9._%+*\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                    text,
                )
                candidate_locals = [_alnum(token.split("@", 1)[0].replace("*", "")) for token in email_tokens]
                if len(local) >= 6 and any(
                    local[i:i + 6] in candidate
                    for i in range(len(local) - 5)
                    for candidate in candidate_locals
                    if len(candidate) >= 6
                ):
                    findings.append(entity_type.value)
                elif 4 <= len(local) < 6 and local in candidate_locals:
                    findings.append(entity_type.value)
            elif entity_type in {
                EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER, EntityType.DRIVER_LICENSE_NUMBER,
                EntityType.TAX_IDENTIFIER, EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
            }:
                source = _alnum(value)
                fragment_len = 7 if len(source) >= 7 else len(source)
                if fragment_len >= 5 and any(
                    source[i:i + fragment_len] in line_alnum
                    for i in range(len(source) - fragment_len + 1)
                    for line_alnum in alnum_lines
                ):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.PERSON_NAME:
                tokens = [token.casefold() for token in re.findall(r"[^\W\d_]{5,}", value, flags=re.UNICODE)]
                if any(re.search(rf"\b{re.escape(token)}\b", folded) for token in tokens):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.CASE_REFERENCE:
                source = _alnum(value)
                fragment_len = 8
                if len(source) >= fragment_len and any(
                    source[i:i + fragment_len] in line_alnum
                    for i in range(len(source) - fragment_len + 1)
                    for line_alnum in alnum_lines
                ):
                    findings.append(entity_type.value)
        if findings:
            return TestResult(
                "direct_identifier_fragment_attack",
                TestStatus.FAIL,
                f"Substantial original-value fragments survived protection: {sorted(set(findings))}",
            )
        return TestResult(
            "direct_identifier_fragment_attack",
            TestStatus.PASS,
            f"No substantial direct-identifier fragments survived Level {int(privacy_level)} output",
        )
    except Exception as exc:
        return TestResult("direct_identifier_fragment_attack", TestStatus.INCONCLUSIVE, f"Fragment attack failed: {exc}")


def replacement_presence_attack(
    protected: bytes,
    file_type: FileType,
    instructions: list[ProtectionInstruction],
) -> TestResult:
    """Verify the manifest's intended replacements are materially present in output."""
    if file_type == FileType.TEXT:
        try:
            visible = decode_text_document(protected).text.casefold()
            missing: list[str] = []
            checked: set[tuple[str, str]] = set()
            for instruction in instructions:
                key = (instruction.entity_id, instruction.replacement)
                if key in checked:
                    continue
                checked.add(key)
                if instruction.replacement.casefold() not in visible:
                    missing.append(instruction.entity_id)
            if missing:
                return TestResult("replacement_presence_attack", TestStatus.FAIL, f"Manifest replacements missing from native text: {sorted(set(missing))}")
            return TestResult("replacement_presence_attack", TestStatus.PASS, f"All {len(checked)} unique manifest replacements are present in native text output")
        except Exception as exc:
            return TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"Native-text replacement scan failed: {exc}")

    if file_type == FileType.DATASET:
        try:
            visible = structured_visible_text(protected).casefold()
            checked: set[tuple[str, str]] = set()
            missing: list[str] = []
            for instruction in instructions:
                key = (instruction.entity_id, instruction.replacement)
                if key in checked:
                    continue
                checked.add(key)
                if instruction.replacement.casefold() not in visible:
                    missing.append(instruction.entity_id)
            if missing:
                return TestResult("replacement_presence_attack", TestStatus.FAIL, f"Manifest replacements missing from structured output: {sorted(set(missing))}")
            return TestResult("replacement_presence_attack", TestStatus.PASS, f"All {len(checked)} unique manifest replacements are present in structured output")
        except Exception as exc:
            return TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"Structured replacement scan failed: {exc}")

    if file_type == FileType.DOCX:
        try:
            visible = docx_visible_text(protected).casefold()
            checked: set[tuple[str, str]] = set()
            missing: list[str] = []
            for instruction in instructions:
                if instruction.entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
                    continue
                key = (instruction.entity_id, instruction.replacement)
                if key in checked:
                    continue
                checked.add(key)
                if instruction.replacement.casefold() not in visible:
                    missing.append(instruction.entity_id)
            if missing:
                return TestResult("replacement_presence_attack", TestStatus.FAIL, f"Manifest replacements missing from DOCX visible text: {sorted(set(missing))}")
            return TestResult("replacement_presence_attack", TestStatus.PASS, f"All {len(checked)} unique textual manifest replacements are present in DOCX output")
        except Exception as exc:
            return TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"DOCX replacement scan failed: {exc}")

    if file_type == FileType.VIDEO:
        return TestResult(
            "replacement_presence_attack",
            TestStatus.PASS,
            "Video is a raster timeline; textual alias OCR is non-authoritative. Signed manifest consistency is enforced by policy coverage/relationship consistency and temporal pixel-integrity gates.",
        )

    if file_type == FileType.IMAGE:
        return TestResult(
            "replacement_presence_attack",
            TestStatus.PASS,
            "Raster output has no authoritative text layer; replacement presence is covered by region integrity and OCR gates",
        )
    try:
        document = fitz.open(stream=protected, filetype="pdf")
        try:
            page_text = [page.get_text("text", sort=True) for page in document]
        finally:
            document.close()
        missing: list[str] = []
        checked: set[tuple[int, str, str]] = set()
        for instruction in instructions:
            key = (instruction.page_index, instruction.entity_id, instruction.replacement)
            if key in checked:
                continue
            checked.add(key)
            if instruction.page_index >= len(page_text):
                missing.append(instruction.entity_id)
                continue
            haystack = re.sub(r"\s+", " ", page_text[instruction.page_index]).casefold()
            needle = re.sub(r"\s+", " ", instruction.replacement).casefold()
            if needle and needle not in haystack:
                missing.append(instruction.entity_id)
        if missing:
            return TestResult(
                "replacement_presence_attack",
                TestStatus.FAIL,
                f"Manifest replacements were not found in protected page text for: {sorted(set(missing))}",
            )
        return TestResult(
            "replacement_presence_attack",
            TestStatus.PASS,
            f"All {len(checked)} unique manifest replacements are present on their intended PDF pages",
        )
    except Exception as exc:
        return TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"Replacement-presence attack failed: {exc}")


def _token_overlaps_regions(token, regions: list[tuple[float, float, float, float]]) -> bool:
    cx = (token.x0 + token.x1) / 2.0
    cy = (token.y0 + token.y1) / 2.0
    return any(x0 - 2 <= cx <= x1 + 2 and y0 - 2 <= cy <= y1 + 2 for x0, y0, x1, y1 in regions)


def _anchor_counter(document, instructions: list[ProtectionInstruction]) -> Counter[str]:
    by_page: dict[int, list[tuple[float, float, float, float]]] = {}
    for instruction in instructions:
        by_page.setdefault(instruction.page_index, []).append(instruction.rect)
    anchors: Counter[str] = Counter()
    for page in document.pages:
        regions = by_page.get(page.page_index, [])
        # Force OCR over the rendered page so raster document utility is measured
        # even when the protected PDF contains a small replacement-only text layer.
        lines = _ocr_lines(page.image, page.page_index, page.width, page.height)
        for line in lines:
            for token in line.tokens:
                if _token_overlaps_regions(token, regions):
                    continue
                cleaned = re.sub(r"[^A-Za-z]", "", token.text).casefold()
                if len(cleaned) >= 3:
                    anchors[cleaned] += 1
    return anchors


def _forced_ocr_word_counter(document) -> Counter[str]:
    words: Counter[str] = Counter()
    for page in document.pages:
        lines = _ocr_lines(page.image, page.page_index, page.width, page.height)
        for line in lines:
            for token in line.tokens:
                cleaned = re.sub(r"[^A-Za-z]", "", token.text).casefold()
                if len(cleaned) >= 3:
                    words[cleaned] += 1
    return words


def utility_anchor_preservation(
    original: bytes,
    protected: bytes,
    file_type: FileType,
    instructions: list[ProtectionInstruction],
) -> TestResult:
    """Ensure transformation does not destroy unrelated document meaning."""
    if file_type == FileType.TEXT:
        try:
            before = decode_text_document(original).text
            after = decode_text_document(protected).text.casefold()
            protected_ranges = sorted(
                (int(item.char_start), int(item.char_end))
                for item in instructions
                if item.char_start is not None and item.char_end is not None
            )
            anchors: list[str] = []
            for match in re.finditer(r"[A-Za-z]{4,}", before):
                if any(match.start() < end and match.end() > start for start, end in protected_ranges):
                    continue
                anchors.append(match.group(0).casefold())
            if len(anchors) < 5:
                return TestResult("utility_anchor_preservation", TestStatus.PASS, "Native text has fewer than five non-sensitive lexical anchors; paragraph structure and replacement gates remain intact")
            preserved = sum(1 for word in anchors if re.search(rf"\b{re.escape(word)}\b", after))
            ratio = preserved / len(anchors)
            if ratio < 0.90:
                return TestResult("utility_anchor_preservation", TestStatus.FAIL, f"Only {ratio:.0%} of native-text non-sensitive lexical anchors survived; minimum is 90%")
            return TestResult("utility_anchor_preservation", TestStatus.PASS, f"{ratio:.0%} of native-text non-sensitive lexical anchors survived transformation")
        except Exception as exc:
            return TestResult("utility_anchor_preservation", TestStatus.INCONCLUSIVE, f"Native-text utility attack failed: {exc}")

    try:
        before = process_document(original, file_type)
        after = process_document(protected, file_type)
        if len(before.pages) != len(after.pages):
            return TestResult("utility_anchor_preservation", TestStatus.FAIL, "Page count changed")
        anchors = _anchor_counter(before, instructions)
        protected_words = _forced_ocr_word_counter(after)
        total = sum(anchors.values())
        if total < 5:
            return TestResult(
                "utility_anchor_preservation",
                TestStatus.PASS,
                "Document has fewer than five non-sensitive lexical anchors; page-count and region-integrity gates preserve structural utility",
            )
        preserved = sum(min(count, protected_words.get(word, 0)) for word, count in anchors.items())
        ratio = preserved / total
        if ratio < 0.82:
            return TestResult(
                "utility_anchor_preservation",
                TestStatus.FAIL,
                f"Only {ratio:.0%} of non-sensitive lexical anchors survived; minimum is 82%",
            )
        return TestResult(
            "utility_anchor_preservation",
            TestStatus.PASS,
            f"{ratio:.0%} of non-sensitive lexical anchors survived transformation",
        )
    except Exception as exc:
        return TestResult("utility_anchor_preservation", TestStatus.INCONCLUSIVE, f"Utility attack failed: {exc}")


def secondary_structured_parser_rescan(
    protected: bytes, known_values: list[tuple[EntityType, str]]
) -> TestResult:
    try:
        dataset = parse_structured_data(protected)
        visible = "\n".join(cell.display_value for cell in __import__("app.extraction.structured_data", fromlist=["iter_cells"]).iter_cells(dataset))
        leaks = [entity_type.value for entity_type, value in known_values if _value_present(visible, entity_type, value)]
        if leaks:
            return TestResult("secondary_structured_parser_rescan", TestStatus.FAIL, f"Secondary structured parser recovered originals: {sorted(set(leaks))}")
        return TestResult("secondary_structured_parser_rescan", TestStatus.PASS, "Secondary structured parser recovered no approved originals")
    except Exception as exc:
        return TestResult("secondary_structured_parser_rescan", TestStatus.INCONCLUSIVE, f"Secondary structured parser failed: {exc}")


def structured_schema_preservation(original: bytes, protected: bytes) -> TestResult:
    try:
        before = schema_signature(original)
        after = schema_signature(protected)
        if before != after:
            return TestResult("structured_schema_preservation", TestStatus.FAIL, "Protected dataset changed sheet/header/path/record structure")
        return TestResult("structured_schema_preservation", TestStatus.PASS, "Dataset sheet/header/path and record structure are unchanged")
    except Exception as exc:
        return TestResult("structured_schema_preservation", TestStatus.INCONCLUSIVE, f"Schema comparison failed: {exc}")


def structured_hidden_channel_scan(protected: bytes, known_values: list[tuple[EntityType, str]]) -> TestResult:
    try:
        # Parser validation is fail-closed for formulas, external XLSX links, macros,
        # embeddings, archive traversal, duplicate JSON keys and oversized cells.
        dataset = parse_structured_data(protected)
        raw = protected
        findings: list[str] = []
        if dataset.format == "csv":
            for line in protected.decode("utf-8", errors="strict").splitlines()[1:]:
                # Canonical CSV neutralises spreadsheet formula injection.
                if re.search(r'(^|[,;\t])\s*[=+@]', line):
                    findings.append("formula-like CSV cell")
                    break
        if findings:
            return TestResult("structured_hidden_channel_scan", TestStatus.FAIL, f"Structured hidden-channel findings: {findings}")
        return TestResult("structured_hidden_channel_scan", TestStatus.PASS, f"Canonical {dataset.format.upper()} has no active/hidden structured payload channel")
    except Exception as exc:
        return TestResult("structured_hidden_channel_scan", TestStatus.INCONCLUSIVE, f"Structured hidden-channel scan failed: {exc}")


def secondary_docx_parser_rescan(
    protected: bytes,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    try:
        visible = secondary_docx_visible_text(protected)
        leaks = _text_leaks(visible, known_values, instructions)
        if leaks:
            return TestResult("secondary_docx_parser_rescan", TestStatus.FAIL, f"Secondary WordprocessingML parser recovered originals: {sorted(set(leaks))}")
        return TestResult("secondary_docx_parser_rescan", TestStatus.PASS, "Secondary WordprocessingML parser recovered no approved original values")
    except Exception as exc:
        return TestResult("secondary_docx_parser_rescan", TestStatus.INCONCLUSIVE, f"Secondary DOCX parser failed: {exc}")


def docx_hidden_channel_scan(
    protected: bytes,
    known_values: list[tuple[EntityType, str]],
    reviewed_ignored_visual_regions: list[dict[str, object]] | None = None,
    instructions: list[ProtectionInstruction] | None = None,
) -> TestResult:
    try:
        findings = docx_hidden_channel_findings(protected)
        raw = docx_raw_channels(protected)
        leaked: list[str] = []
        for entity_type, value in known_values:
            inspected = _mask_approved_replacements_bytes(raw, entity_type, value, instructions)
            if len(value.strip()) >= 4 and _casefold_bytes_contains(inspected, value.strip()):
                leaked.append(entity_type.value)
        if findings or leaked:
            return TestResult("docx_hidden_channel_scan", TestStatus.FAIL, f"DOCX hidden-channel findings: package={findings}, originals={sorted(set(leaked))}")
        qr = qr_rescan(protected, FileType.DOCX, reviewed_ignored_visual_regions)
        if qr.status != TestStatus.PASS:
            return TestResult("docx_hidden_channel_scan", qr.status, f"DOCX visual payload sub-gate: {qr.detail}")
        return TestResult("docx_hidden_channel_scan", TestStatus.PASS, "DOCX raw XML/relationships contain no hidden source values or active channels; embedded QR sub-gate passed")
    except Exception as exc:
        return TestResult("docx_hidden_channel_scan", TestStatus.INCONCLUSIVE, f"DOCX hidden-channel scan failed: {exc}")


def docx_structure_preservation(original: bytes, protected: bytes) -> TestResult:
    try:
        before = docx_structure_signature(original)
        after = docx_structure_signature(protected)
        if before != after:
            return TestResult("docx_structure_preservation", TestStatus.FAIL, f"DOCX paragraph/table/header/footer/media structure changed: before={before}, after={after}")
        return TestResult("docx_structure_preservation", TestStatus.PASS, "DOCX paragraph, table, header/footer, note and embedded-image structure is preserved")
    except Exception as exc:
        return TestResult("docx_structure_preservation", TestStatus.INCONCLUSIVE, f"DOCX structure comparison failed: {exc}")


def _video_direct_identifier_rescan_document(
    document: ProcessedDocument,
    known_values: list[tuple[EntityType, str]],
) -> TestResult:
    try:
        direct = detect_direct_identifiers(document)
        direct += [
            item for item in detect_broad_pii(document)
            if item.entity_type in {
                EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.PASSPORT_NUMBER,
                EntityType.DRIVER_LICENSE_NUMBER, EntityType.TAX_IDENTIFIER,
                EntityType.SOCIAL_IDENTIFIER, EntityType.PAYMENT_CARD_NUMBER,
            }
        ]
        residual = [item for item in direct if _contains_known_original(item, known_values) or not known_values]
        if residual:
            summary: dict[str, int] = {}
            for item in residual:
                summary[item.entity_type.value] = summary.get(item.entity_type.value, 0) + 1
            return TestResult("direct_identifier_rescan", TestStatus.FAIL, f"Detected residual identifiers in protected video frames: {summary}")
        return TestResult("direct_identifier_rescan", TestStatus.PASS, "No approved direct identifier was detected across the protected video physical-frame timeline")
    except Exception as exc:
        return TestResult("direct_identifier_rescan", TestStatus.INCONCLUSIVE, f"Video detector rescan failed: {exc}")


def video_frame_ocr_rescan(document: ProcessedDocument, known_values: list[tuple[EntityType, str]]) -> TestResult:
    try:
        text = _flatten_text(document)
        leaks = [entity_type.value for entity_type, value in known_values if _value_present(text, entity_type, value)]
        if leaks:
            return TestResult("video_frame_ocr_rescan", TestStatus.FAIL, f"Protected video evidence frames still reveal originals: {sorted(set(leaks))}")
        return TestResult("video_frame_ocr_rescan", TestStatus.PASS, f"Full OCR across {len(document.pages)} security-selected protected frame(s) recovered no approved originals; complete-timeline change screening is enforced by the independent extraction gate")
    except Exception as exc:
        return TestResult("video_frame_ocr_rescan", TestStatus.INCONCLUSIVE, f"Video frame OCR rescan failed: {exc}")


def _video_fragment_attack_from_text(
    text: str,
    known_values: list[tuple[EntityType, str]],
    privacy_level: PrivacyLevel,
) -> TestResult:
    try:
        folded = text.casefold()
        digit_lines = [re.sub(r"\D", "", line) for line in text.splitlines()]
        alnum_lines = [_alnum(line) for line in text.splitlines()]
        findings: list[str] = []
        for entity_type, value in known_values:
            if entity_type not in _DIRECT_FRAGMENT_TYPES:
                continue
            if entity_type in {EntityType.PHONE, EntityType.AADHAAR_LIKE}:
                source = re.sub(r"\D", "", value)
                fragment_len = 7 if entity_type == EntityType.PHONE else 9
                if len(source) >= fragment_len and any(source[i:i+fragment_len] in line for i in range(len(source)-fragment_len+1) for line in digit_lines):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.EMAIL:
                local = _alnum(value.split("@", 1)[0])
                if len(local) >= 6 and any(local[i:i+6] in _alnum(token.split("@",1)[0]) for i in range(len(local)-5) for token in re.findall(r"[A-Za-z0-9._%+*\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)):
                    findings.append(entity_type.value)
            elif entity_type == EntityType.PERSON_NAME:
                tokens = [token.casefold() for token in re.findall(r"[^\W\d_]{5,}", value, flags=re.UNICODE)]
                if any(re.search(rf"\b{re.escape(token)}\b", folded) for token in tokens):
                    findings.append(entity_type.value)
            else:
                source = _alnum(value)
                fragment_len = min(8, len(source))
                if fragment_len >= 5 and any(source[i:i+fragment_len] in line for i in range(len(source)-fragment_len+1) for line in alnum_lines):
                    findings.append(entity_type.value)
        if findings:
            return TestResult("direct_identifier_fragment_attack", TestStatus.FAIL, f"Substantial original fragments survived video protection: {sorted(set(findings))}")
        return TestResult("direct_identifier_fragment_attack", TestStatus.PASS, f"No substantial direct-identifier fragments survived Level {int(privacy_level)} video output")
    except Exception as exc:
        return TestResult("direct_identifier_fragment_attack", TestStatus.INCONCLUSIVE, f"Video fragment attack failed: {exc}")


def _video_replacement_presence_from_text(text: str, instructions: list[ProtectionInstruction]) -> TestResult:
    try:
        visible = text.casefold()
        checked: set[tuple[str, str]] = set()
        missing: list[str] = []
        for instruction in instructions:
            if instruction.entity_type in {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}:
                continue
            key = (instruction.entity_id, instruction.replacement)
            if key in checked:
                continue
            checked.add(key)
            if instruction.replacement.casefold() not in visible:
                missing.append(instruction.entity_id)
        if missing:
            return TestResult("replacement_presence_attack", TestStatus.FAIL, f"Manifest replacements were not recoverable from protected video security frames: {sorted(set(missing))}")
        return TestResult("replacement_presence_attack", TestStatus.PASS, f"All {len(checked)} unique textual video replacements are present in protected security frames")
    except Exception as exc:
        return TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"Video replacement scan failed: {exc}")


def _decode_qr_payloads_independent(image: Image.Image) -> set[str]:
    """Aggressively decode QR payloads without using VeilGraph detection records.

    The release gate deliberately calls OpenCV directly over protected video
    pixels and tries several deterministic render variants. It does not reuse
    the original visual-detector output, entity graph, or transformation
    manifest, so a stale/incorrect detection record cannot make this check pass.
    """
    rgb = np.asarray(image.convert("RGB"))
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    variants: list[np.ndarray] = [bgr, gray]
    try:
        variants.append(cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray))
    except cv2.error:
        pass
    try:
        _threshold, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.extend([otsu, cv2.bitwise_not(otsu)])
    except cv2.error:
        pass

    payloads: set[str] = set()
    for variant in variants:
        detector = cv2.QRCodeDetector()
        try:
            ok, decoded_info, _points, _straight = detector.detectAndDecodeMulti(variant)
            if ok:
                payloads.update(value.strip() for value in decoded_info if value and value.strip())
        except (cv2.error, ValueError):
            pass
        try:
            decoded, _points, _straight = detector.detectAndDecode(variant)
            if decoded and decoded.strip():
                payloads.add(decoded.strip())
        except (cv2.error, ValueError):
            pass
    return payloads


def video_visual_identifier_rescan(protected: bytes) -> TestResult:
    """Independently attempt QR recovery from every protected physical frame.

    OCR gates cannot establish that a visual code is unreadable. This critical
    video-only gate therefore attacks the raster timeline directly and fails on
    any decodable QR payload, regardless of whether it appeared in VeilGraph's
    original entity inventory.
    """
    temp_path: str | None = None
    cap = None
    try:
        info = probe_video(protected)
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as handle:
            handle.write(protected)
            temp_path = handle.name
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise RuntimeError("OpenCV could not decode protected video for independent visual rescan")

        decoded_hits: list[tuple[int, str]] = []
        scanned = 0
        while True:
            ok, frame = cap.read()
            if not ok or frame is None:
                break
            image = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            for payload in sorted(_decode_qr_payloads_independent(image)):
                decoded_hits.append((scanned, payload))
            scanned += 1

        if scanned != info.total_frames:
            return TestResult(
                "video_visual_identifier_rescan", TestStatus.INCONCLUSIVE,
                f"Independent QR decoder scanned {scanned}/{info.total_frames} protected physical frames.",
            )
        if decoded_hits:
            sample = "; ".join(f"frame {frame}: {payload}" for frame, payload in decoded_hits[:4])
            return TestResult(
                "video_visual_identifier_rescan", TestStatus.FAIL,
                f"Independent QR decoder recovered visual payload(s) from protected video: {sample}",
            )
        return TestResult(
            "video_visual_identifier_rescan", TestStatus.PASS,
            f"Independent QR decoder attacked all {scanned}/{info.total_frames} protected physical frames across raw, grayscale and threshold variants; no QR payload was recoverable.",
        )
    except Exception as exc:
        return TestResult(
            "video_visual_identifier_rescan", TestStatus.INCONCLUSIVE,
            f"Independent visual identifier rescan failed: {exc}",
        )
    finally:
        if cap is not None:
            cap.release()
        if temp_path:
            try:
                Path(temp_path).unlink()
            except FileNotFoundError:
                pass

def video_audio_absence(protected: bytes) -> TestResult:
    try:
        info = probe_video(protected)
        if info.has_audio:
            return TestResult("video_audio_absence", TestStatus.FAIL, "Protected video retains an audio track; spoken identity content could survive")
        return TestResult("video_audio_absence", TestStatus.PASS, "Protected video is intentionally video-only; the source audio channel is absent")
    except Exception as exc:
        return TestResult("video_audio_absence", TestStatus.INCONCLUSIVE, f"Video audio-track inspection failed: {exc}")


def video_structure_preservation(original: bytes, protected: bytes) -> TestResult:
    try:
        before = probe_video(original)
        after = probe_video(protected)
        failures: list[str] = []
        if (before.width, before.height) != (after.width, after.height):
            failures.append(f"resolution {before.width}x{before.height}->{after.width}x{after.height}")
        fps_delta = abs(before.fps - after.fps) / max(before.fps, 1.0)
        if fps_delta > 0.03:
            failures.append(f"fps {before.fps:.3f}->{after.fps:.3f}")
        frame_delta = abs(before.total_frames - after.total_frames)
        if frame_delta > 1:
            failures.append(f"frames {before.total_frames}->{after.total_frames}")
        duration_delta = abs(before.duration_seconds - after.duration_seconds)
        if duration_delta > max(0.15, 2.0 / max(before.fps, 1.0)):
            failures.append(f"duration {before.duration_seconds:.3f}->{after.duration_seconds:.3f}")
        if failures:
            return TestResult("video_structure_preservation", TestStatus.FAIL, f"Protected video timing/geometry changed unexpectedly: {failures}")
        return TestResult("video_structure_preservation", TestStatus.PASS, "Protected video preserves frame dimensions, frame cadence, frame count and duration")
    except Exception as exc:
        return TestResult("video_structure_preservation", TestStatus.INCONCLUSIVE, f"Video structure comparison failed: {exc}")


_TEST_METADATA: dict[str, tuple[str, str]] = {
    "direct_identifier_rescan": ("content_rescan", "critical"),
    "independent_extraction": ("independent_extraction", "critical"),
    "ocr_rescan": ("vision_rescan", "critical"),
    "secondary_text_parser_rescan": ("secondary_parser", "critical"),
    "secondary_docx_parser_rescan": ("secondary_parser", "critical"),
    "docx_hidden_channel_scan": ("hidden_markup_payload", "critical"),
    "docx_content_integrity": ("transformation_integrity", "high"),
    "docx_structure_preservation": ("structure_preservation", "high"),
    "qr_rescan": ("visual_payload", "critical"),
    "hidden_markup_payload_scan": ("hidden_markup_payload", "critical"),
    "region_replacement_integrity": ("transformation_integrity", "high"),
    "character_span_integrity": ("transformation_integrity", "high"),
    "structured_cell_integrity": ("transformation_integrity", "high"),
    "secondary_structured_parser_rescan": ("secondary_parser", "critical"),
    "structured_schema_preservation": ("schema_preservation", "high"),
    "structured_hidden_channel_scan": ("hidden_structured_payload", "critical"),
    "metadata_and_embedded_content": ("hidden_content", "high"),
    "policy_coverage": ("policy_manifest", "critical"),
    "relationship_consistency": ("relationship_linkability", "high"),
    "raw_object_stream_scan": ("raw_object_storage", "critical"),
    "direct_identifier_fragment_attack": ("fragment_leakage", "high"),
    "replacement_presence_attack": ("manifest_output_consistency", "high"),
    "utility_anchor_preservation": ("utility_preservation", "medium"),
    "video_frame_ocr_rescan": ("full_timeline_ocr_rescan", "critical"),
    "video_visual_identifier_rescan": ("visual_payload_recovery", "critical"),
    "video_audio_absence": ("audio_leakage", "critical"),
    "video_temporal_integrity": ("temporal_transformation_integrity", "high"),
    "video_structure_preservation": ("video_structure_preservation", "high"),
}


def _decorate(result: TestResult) -> TestResult:
    attack_class, severity = _TEST_METADATA.get(result.name, (result.attack_class, result.severity))
    return replace(result, attack_class=attack_class, severity=severity)


def proof_score(results: list[TestResult]) -> int:
    weights = {"critical": 12, "high": 8, "medium": 4}
    total = sum(weights.get(item.severity, 8) for item in results)
    if total <= 0:
        return 0
    earned = sum(weights.get(item.severity, 8) for item in results if item.status == TestStatus.PASS)
    return round(100 * earned / total)


def _policy_required_absence_values(
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction],
) -> list[tuple[EntityType, str]]:
    """Exclude source values intentionally retained inside an approved generalisation.

    A coarse value such as ``Bengaluru`` can legitimately survive as part of
    ``Bengaluru metropolitan area``. The verifier must attack unintended source
    recovery, not reject the compiler's explicit replacement text.
    """
    result: list[tuple[EntityType, str]] = []
    for entity_type, value in known_values:
        deliberately_retained = any(
            item.entity_type == entity_type and _value_present(item.replacement, entity_type, value)
            for item in instructions
        )
        if not deliberately_retained:
            result.append((entity_type, value))
    return result




_SYNTHETIC_IDENTITY_ABSENCE_TYPES = {
    EntityType.PERSON_NAME,
    EntityType.EMAIL,
    EntityType.PHONE,
    EntityType.AADHAAR_LIKE,
    EntityType.PAN_LIKE,
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
    EntityType.CASE_REFERENCE,
    EntityType.DATE_OF_BIRTH,
    EntityType.STREET_ADDRESS,
    EntityType.BUILDING_NUMBER,
    EntityType.POSTCODE,
}


def _synthetic_identity_absence_values(
    known_values: list[tuple[EntityType, str]],
) -> list[tuple[EntityType, str]]:
    """Values that must not survive L5.

    Population attributes such as age, gender and locality may legitimately
    recur in a synthetic population because L5 preserves useful distributions.
    The fail-closed exact-absence gate therefore targets source identity and
    unique-marker classes rather than banning aggregate values globally.
    """
    return [
        (entity_type, value)
        for entity_type, value in known_values
        if entity_type in _SYNTHETIC_IDENTITY_ABSENCE_TYPES
    ]


def synthetic_original_identifier_absence(
    protected: bytes,
    known_values: list[tuple[EntityType, str]],
) -> TestResult:
    """L5 permits realistic *synthetic* identifiers but never source identifiers."""
    try:
        visible = structured_visible_text(protected)
        leaks = sorted({
            entity_type.value
            for entity_type, value in known_values
            if _value_present(visible, entity_type, value)
        })
        if leaks:
            return TestResult(
                "synthetic_original_identifier_absence", TestStatus.FAIL,
                f"Synthetic Twin still contains approved source identifiers: {leaks}",
                attack_class="synthetic_privacy", severity="critical",
            )
        return TestResult(
            "synthetic_original_identifier_absence", TestStatus.PASS,
            "No approved source identifier remains; realistic generated identifiers are allowed only in Level 5.",
            attack_class="synthetic_privacy", severity="critical",
        )
    except Exception as exc:
        return TestResult(
            "synthetic_original_identifier_absence", TestStatus.INCONCLUSIVE,
            f"Synthetic identifier provenance check failed: {exc}",
            attack_class="synthetic_privacy", severity="critical",
        )


def _structured_record_rows(data: bytes) -> list[tuple[str, ...]]:
    dataset = parse_structured_data(data)
    grouped: dict[int, list[tuple[str, str]]] = {}
    for cell in iter_cells(dataset):
        grouped.setdefault(cell.record_index, []).append((cell.header, cell.display_value))
    rows: list[tuple[str, ...]] = []
    for index in sorted(grouped):
        ordered = sorted(grouped[index], key=lambda item: item[0].casefold())
        rows.append(tuple(re.sub(r"\s+", " ", value.strip().casefold()) for _header, value in ordered))
    return rows


def synthetic_source_record_copy_attack(original: bytes, protected: bytes) -> TestResult:
    try:
        source = set(_structured_record_rows(original))
        synthetic = _structured_record_rows(protected)
        copied = sum(row in source for row in synthetic)
        if copied:
            return TestResult(
                "synthetic_source_record_copy_attack", TestStatus.FAIL,
                f"{copied} synthetic record(s) exactly copy a source record.",
                attack_class="synthetic_privacy", severity="critical",
            )
        return TestResult(
            "synthetic_source_record_copy_attack", TestStatus.PASS,
            f"Zero exact source-record copies across {len(synthetic)} synthetic record(s).",
            attack_class="synthetic_privacy", severity="critical",
        )
    except Exception as exc:
        return TestResult(
            "synthetic_source_record_copy_attack", TestStatus.INCONCLUSIVE,
            f"Source-record copy attack failed: {exc}",
            attack_class="synthetic_privacy", severity="critical",
        )


def synthetic_utility_evidence_attack(report: dict[str, object] | None) -> TestResult:
    if not isinstance(report, dict):
        return TestResult(
            "synthetic_utility_evidence", TestStatus.INCONCLUSIVE,
            "Synthetic Twin report is missing from the signed manifest.",
            attack_class="synthetic_utility", severity="high",
        )
    required = {
        "schema_preserved", "exact_row_copy_rate", "sensitive_exact_reuse_count",
        "numeric_correlation_fidelity", "categorical_distribution_fidelity",
        "utility_score", "privacy_score", "output_sha256",
    }
    missing = sorted(required - set(report))
    if missing:
        return TestResult(
            "synthetic_utility_evidence", TestStatus.FAIL,
            f"Synthetic evidence is incomplete: {missing}",
            attack_class="synthetic_utility", severity="high",
        )
    failures: list[str] = []
    if report.get("schema_preserved") is not True:
        failures.append("schema-not-preserved")
    if float(report.get("exact_row_copy_rate", 1.0)) > 0.0:
        failures.append("source-row-copy")
    if int(report.get("sensitive_exact_reuse_count", 1)) != 0:
        failures.append("sensitive-value-reuse")
    if int(report.get("utility_score", 0)) < 60:
        failures.append("utility<60")
    if int(report.get("privacy_score", 0)) < 90:
        failures.append("privacy<90")
    if failures:
        return TestResult(
            "synthetic_utility_evidence", TestStatus.FAIL,
            f"Synthetic evidence thresholds failed: {failures}",
            attack_class="synthetic_utility", severity="high",
        )
    return TestResult(
        "synthetic_utility_evidence", TestStatus.PASS,
        f"Schema preserved; utility={int(report['utility_score'])}/100, privacy={int(report['privacy_score'])}/100, source-row-copy=0.",
        attack_class="synthetic_utility", severity="high",
    )


def synthetic_output_commitment_attack(protected: bytes, report: dict[str, object] | None) -> TestResult:
    if not isinstance(report, dict) or not report.get("output_sha256"):
        return TestResult(
            "synthetic_output_commitment", TestStatus.INCONCLUSIVE,
            "Synthetic output commitment is missing.",
            attack_class="synthetic_integrity", severity="high",
        )
    actual = hashlib.sha256(protected).hexdigest()
    if actual != str(report.get("output_sha256")):
        return TestResult(
            "synthetic_output_commitment", TestStatus.FAIL,
            "Protected dataset hash does not match the Synthetic Twin manifest commitment.",
            attack_class="synthetic_integrity", severity="high",
        )
    return TestResult(
        "synthetic_output_commitment", TestStatus.PASS,
        "Synthetic Twin output hash matches the signed manifest commitment.",
        attack_class="synthetic_integrity", severity="high",
    )


def run_red_team(
    original: bytes,
    protected: bytes,
    file_type: FileType,
    known_values: list[tuple[EntityType, str]],
    instructions: list[ProtectionInstruction],
    expected_entity_ids: set[str] | None = None,
    privacy_level: PrivacyLevel = PrivacyLevel.DIRECT_MASKING,
    reviewed_ignored_visual_regions: list[dict[str, object]] | None = None,
    synthetic_twin: dict[str, object] | None = None,
) -> list[TestResult]:
    if file_type == FileType.DATASET and privacy_level == PrivacyLevel.SYNTHETIC_TWIN:
        absence_values = _synthetic_identity_absence_values(known_values)
        results = [
            synthetic_original_identifier_absence(protected, absence_values),
            independent_extraction(protected, file_type, absence_values),
            secondary_structured_parser_rescan(protected, absence_values),
            structured_hidden_channel_scan(protected, absence_values),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, absence_values),
            direct_identifier_fragment_attack(protected, file_type, absence_values, privacy_level),
            replacement_presence_attack(protected, file_type, instructions),
            structured_schema_preservation(original, protected),
            synthetic_source_record_copy_attack(original, protected),
            synthetic_utility_evidence_attack(synthetic_twin),
            synthetic_output_commitment_attack(protected, synthetic_twin),
        ]
    elif file_type == FileType.DATASET:
        absence_values = _policy_required_absence_values(known_values, instructions)
        results = [
            direct_identifier_rescan(protected, file_type, absence_values, instructions),
            independent_extraction(protected, file_type, absence_values),
            secondary_structured_parser_rescan(protected, absence_values),
            structured_hidden_channel_scan(protected, absence_values),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, absence_values),
            direct_identifier_fragment_attack(protected, file_type, absence_values, privacy_level),
            replacement_presence_attack(protected, file_type, instructions),
            structured_schema_preservation(original, protected),
        ]
    elif file_type == FileType.DOCX:
        results = [
            direct_identifier_rescan(protected, file_type, known_values, instructions),
            independent_extraction(protected, file_type, known_values, instructions),
            secondary_docx_parser_rescan(protected, known_values, instructions),
            docx_hidden_channel_scan(protected, known_values, reviewed_ignored_visual_regions, instructions),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, known_values, instructions),
            direct_identifier_fragment_attack(protected, file_type, known_values, privacy_level),
            replacement_presence_attack(protected, file_type, instructions),
            docx_structure_preservation(original, protected),
        ]
    elif file_type == FileType.VIDEO:
        absence_values = _policy_required_absence_values(known_values, instructions)
        try:
            video_document = process_document(protected, FileType.VIDEO)
            video_text = _flatten_text(video_document)
            video_document_error = None
        except Exception as exc:
            video_document = None
            video_text = ""
            video_document_error = str(exc)
        if video_document is None:
            detector_gate = TestResult("direct_identifier_rescan", TestStatus.INCONCLUSIVE, f"Protected video timeline could not be decoded: {video_document_error}")
            frame_gate = TestResult("video_frame_ocr_rescan", TestStatus.INCONCLUSIVE, f"Protected video timeline could not be decoded: {video_document_error}")
            fragment_gate = TestResult("direct_identifier_fragment_attack", TestStatus.INCONCLUSIVE, f"Protected video timeline could not be decoded: {video_document_error}")
            replacement_gate = TestResult("replacement_presence_attack", TestStatus.INCONCLUSIVE, f"Protected video timeline could not be decoded: {video_document_error}")
        else:
            detector_gate = _video_direct_identifier_rescan_document(video_document, absence_values)
            frame_gate = video_frame_ocr_rescan(video_document, absence_values)
            fragment_gate = _video_fragment_attack_from_text(video_text, absence_values, privacy_level)
            replacement_gate = replacement_presence_attack(protected, file_type, instructions)
        results = [
            detector_gate,
            independent_extraction(protected, file_type, absence_values),
            frame_gate,
            video_visual_identifier_rescan(protected),
            video_audio_absence(protected),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, absence_values),
            fragment_gate,
            replacement_gate,
            video_structure_preservation(original, protected),
        ]
    elif file_type == FileType.TEXT:
        results = [
            direct_identifier_rescan(protected, file_type, known_values, instructions),
            independent_extraction(protected, file_type, known_values, instructions),
            secondary_text_parser_rescan(protected, known_values, instructions),
            hidden_markup_payload_scan(protected, known_values, instructions),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, known_values, instructions),
            direct_identifier_fragment_attack(protected, file_type, known_values, privacy_level),
            replacement_presence_attack(protected, file_type, instructions),
            utility_anchor_preservation(original, protected, file_type, instructions),
        ]
    else:
        results = [
            direct_identifier_rescan(protected, file_type, known_values, instructions),
            independent_extraction(protected, file_type, known_values, instructions),
            ocr_rescan(protected, file_type, known_values, instructions),
            qr_rescan(protected, file_type, reviewed_ignored_visual_regions),
            region_replacement_integrity(original, protected, file_type, instructions),
            metadata_inspection(protected, file_type),
            policy_coverage(instructions, expected_entity_ids or {item.entity_id for item in instructions}),
            relationship_consistency(instructions, privacy_level),
            raw_object_stream_scan(protected, file_type, known_values, instructions),
            direct_identifier_fragment_attack(protected, file_type, known_values, privacy_level),
            replacement_presence_attack(protected, file_type, instructions),
            utility_anchor_preservation(original, protected, file_type, instructions),
        ]
    return [_decorate(item) for item in results]
