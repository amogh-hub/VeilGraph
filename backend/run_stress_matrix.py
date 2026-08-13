from __future__ import annotations

import io
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import fitz
from PIL import Image, ImageDraw, ImageFont

from app.core.config import settings
from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import normalize_value
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.ingestion.validator import ValidationError, sanitize_filename, validate_upload
from app.transformation.sanitizer import ProtectionInstruction, sanitize_pdf


@dataclass
class CaseResult:
    name: str
    expected: str
    observed: str
    passed: bool
    elapsed_ms: int
    detail: str


def png_bytes(image: Image.Image) -> bytes:
    out = io.BytesIO(); image.save(out, format="PNG"); return out.getvalue()


def rotated_png() -> bytes:
    font = ImageFont.load_default(size=26)
    image = Image.new("RGB", (1100, 1500), "white")
    draw = ImageDraw.Draw(image)
    lines = [
        "FICTIONAL CITIZEN RECORD", "Citizen: Aarav Testperson",
        "Mobile: +91 98765 43210", "Email: aarav.test@example.org",
        "Date of birth: 11 June 2007", "Address: 42 Test Road Bengaluru Karnataka",
        "Employer: Example Systems Private Limited", "Case reference: VG-TEST-2026-001",
    ]
    y = 70
    for _ in range(3):
        for line in lines:
            draw.text((60, y), line, font=font, fill="black"); y += 44
        y += 18
    return png_bytes(image.transpose(Image.Transpose.ROTATE_270))


def multipage_pdf(count: int) -> bytes:
    document = fitz.open()
    try:
        for index in range(count):
            page = document.new_page(width=595, height=842)
            page.insert_text((72, 90), f"FICTIONAL PAGE {index + 1}", fontsize=12)
            page.insert_text((72, 130), "Mobile: +91 98765 43210", fontsize=12)
            page.insert_text((72, 160), "Email: stress.user@example.org", fontsize=12)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def run_case(name: str, expected: str, fn) -> CaseResult:
    started = time.perf_counter()
    try:
        observed, detail = fn()
        passed = observed == expected
    except Exception as exc:
        observed, detail, passed = "EXCEPTION", f"{type(exc).__name__}: {exc}", False
    return CaseResult(name, expected, observed, passed, int((time.perf_counter() - started) * 1000), detail)


def case_rotated_scan():
    detections = detect_all(process_document(rotated_png(), FileType.IMAGE))
    types = {item.entity_type for item in detections}
    required = {EntityType.PHONE, EntityType.EMAIL, EntityType.PERSON_NAME}
    ok = required.issubset(types)
    return ("DETECTED" if ok else "MISSED", ", ".join(sorted(t.value for t in types)))


def case_twelve_pages():
    document = process_document(multipage_pdf(12), FileType.PDF)
    detections = detect_all(document)
    phones = [item for item in detections if item.entity_type == EntityType.PHONE and normalize_value(item.entity_type, item.plaintext).endswith("9876543210")]
    ok = len(phones) == 12 and {item.page_index for item in phones} == set(range(12))
    return ("PRESERVED" if ok else "LOST_MENTIONS", f"phone_mentions={len(phones)} pages={document.page_count}")


def case_encrypted_pdf():
    doc = fitz.open(); page = doc.new_page(); page.insert_text((72,72), "Sensitive")
    data = doc.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="secret"); doc.close()
    try:
        validate_upload(data, "locked.pdf")
        return "ACCEPTED", "encrypted PDF reached ingestion"
    except ValidationError as exc:
        return "REJECTED", str(exc)


def case_render_bomb():
    doc = fitz.open(); doc.new_page(width=10_000, height=10_000); data = doc.tobytes(); doc.close()
    try:
        validate_upload(data, "huge.pdf")
        return "ACCEPTED", "oversized render geometry reached ingestion"
    except ValidationError as exc:
        return "REJECTED", str(exc)


def case_malformed_pdf():
    try:
        validate_upload(b"%PDF-1.7\nnot a valid PDF object graph", "broken.pdf")
        return "ACCEPTED", "malformed PDF reached ingestion"
    except ValidationError as exc:
        return "REJECTED", str(exc)


def case_filename_injection():
    safe = sanitize_filename('../../evil\r\nX-Injected: yes.pdf')
    ok = all(ch not in safe for ch in "/\\\r\n:") and safe.endswith(".pdf")
    return ("SANITIZED" if ok else "UNSAFE", safe)


def case_hidden_content_scrub():
    doc = fitz.open(); page = doc.new_page(width=595, height=842)
    page.insert_text((72,100), "Mobile: +91 98765 43210", fontsize=12)
    page.insert_text((72,140), "hidden.user@example.org", fontsize=12, color=(1,1,1))
    doc.set_metadata({"author":"Sensitive Author", "subject":"hidden.user@example.org"})
    doc.embfile_add("secret.txt", b"hidden.user@example.org")
    original = doc.tobytes(); doc.close()
    processed = process_document(original, FileType.PDF)
    target = next(item for item in detect_all(processed) if item.entity_type == EntityType.EMAIL)
    protected, _, _, _ = sanitize_pdf(original, [ProtectionInstruction("e","m",EntityType.EMAIL,target.page_index,target.rect,"h***@example.org")])
    checked = fitz.open(stream=protected, filetype="pdf")
    extracted = "\n".join(page.get_text() for page in checked)
    clean = checked.embfile_count() == 0 and not (checked.metadata.get("author") or "") and "hidden.user@example.org" not in extracted
    checked.close()
    return ("SCRUBBED" if clean else "LEAK", "attachment=0 metadata-cleared hidden-identifier-absent" if clean else "residual hidden content")


def main() -> int:
    cases = [
        run_case("rotated_90_degree_scan", "DETECTED", case_rotated_scan),
        run_case("twelve_page_cross_page_consistency", "PRESERVED", case_twelve_pages),
        run_case("encrypted_pdf", "REJECTED", case_encrypted_pdf),
        run_case("oversized_render_geometry", "REJECTED", case_render_bomb),
        run_case("malformed_pdf", "REJECTED", case_malformed_pdf),
        run_case("filename_header_injection", "SANITIZED", case_filename_injection),
        run_case("hidden_metadata_attachment_text", "SCRUBBED", case_hidden_content_scrub),
    ]
    payload = {
        "suite": "VeilGraph Final Hardening Pass 2 stress matrix",
        "version": settings.version,
        "offline": True,
        "cases": [asdict(case) for case in cases],
        "passed": sum(case.passed for case in cases),
        "total": len(cases),
        "all_passed": all(case.passed for case in cases),
    }
    output = Path(__file__).resolve().parents[1] / "competition" / "stress-matrix-results.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"\nWrote {output}")
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
