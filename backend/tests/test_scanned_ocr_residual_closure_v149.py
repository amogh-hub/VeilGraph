from __future__ import annotations

import io

import fitz
from PIL import Image, ImageDraw, ImageFont

from pathlib import Path

from app.core.enums import EntityType, FileType, TestStatus as GateStatus
from app.transformation.sanitizer import ProtectionInstruction, sanitize_pdf
from app.verification.red_team import ocr_rescan, replacement_presence_attack


def _font(size: int = 34):
    for path in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            pass
    return ImageFont.load_default()


def _fixture() -> tuple[bytes, list[ProtectionInstruction]]:
    # One raster-only page with source values in labelled fields and again in a
    # context sentence. The initial instructions intentionally target only the
    # labelled fields, reproducing the missed secondary OCR occurrence found in
    # 05_scanned_application.pdf during target-Mac acceptance.
    width, height = 1600, 1200
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    font = _font(34)

    fields = [
        ("Age", "29", EntityType.AGE, "Age 25-34", 220),
        ("City", "Bengaluru", EntityType.LOCALITY, "Bengaluru metropolitan area", 330),
        ("Event", "2026-07-14", EntityType.GENERIC_DATE, "Date in 2026", 440),
    ]
    instructions: list[ProtectionInstruction] = []
    for idx, (label, value, entity_type, replacement, y) in enumerate(fields, start=1):
        draw.text((150, y), f"{label}:", fill="black", font=font)
        draw.text((520, y), value, fill="black", font=font)
        # PDF is half the raster dimensions.
        bbox = draw.textbbox((520, y), value, font=font)
        rect = tuple(float(v) / 2.0 for v in bbox)
        instructions.append(
            ProtectionInstruction(
                entity_id=f"entity-{idx}",
                mention_id=f"mention-{idx}",
                entity_type=entity_type,
                page_index=0,
                rect=rect,
                replacement=replacement,
            )
        )

    draw.text(
        (150, 650),
        "Context: 29-year-old Bengaluru delegate; rare fictional event on 2026-07-14.",
        fill="black",
        font=font,
    )

    png = io.BytesIO()
    image.save(png, format="PNG")
    doc = fitz.open()
    page = doc.new_page(width=800, height=600)
    page.insert_image(page.rect, stream=png.getvalue())
    data = doc.tobytes(garbage=4, deflate=True, clean=True)
    doc.close()
    return data, instructions


def test_scanned_pdf_post_transform_ocr_closes_secondary_visual_occurrences():
    original, instructions = _fixture()
    protected, _, _, report = sanitize_pdf(original, instructions)

    assert report["ocr_propagated_occurrences"] >= 1, report
    assert report["ocr_residual_passes"] >= 1, report
    assert report["scanned_pages_hardened"] == [0]

    known = [
        (EntityType.AGE, "29"),
        (EntityType.LOCALITY, "Bengaluru"),
        (EntityType.GENERIC_DATE, "2026-07-14"),
    ]
    result = ocr_rescan(protected, FileType.PDF, known, instructions)
    assert result.status == GateStatus.PASS, result.detail

    # Manifest fidelity still has to pass; OCR closure must not achieve privacy
    # by silently deleting the compiler-promised replacements.
    replacement = replacement_presence_attack(protected, FileType.PDF, instructions)
    assert replacement.status == GateStatus.PASS, replacement.detail


def test_scanned_pdf_ocr_closure_does_not_modify_v148_red_team_contract():
    # This package must repair the transformation surface, not weaken the gate.
    original, instructions = _fixture()
    protected, _, _, _ = sanitize_pdf(original, instructions)
    known = [(EntityType.LOCALITY, "Bengaluru")]
    assert ocr_rescan(protected, FileType.PDF, known, instructions).status == GateStatus.PASS



def test_judge_scanned_application_exact_fixture_reaches_12_of_12_after_ocr_closure(client):
    fixture = Path(__file__).resolve().parents[2] / "competition" / "datasets" / "judge_showcase_v1" / "05_scanned_application.pdf"
    assert fixture.is_file(), fixture

    created = client.post(
        "/api/v1/jobs",
        json={"purpose": "Public release", "recipient": "Citizen portal", "privacy_level": 4},
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]

    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": (fixture.name, fixture.read_bytes(), "application/pdf")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]

    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    assert analysed.json()["scanned_pages"] == 1

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities")
    assert entities.status_code == 200, entities.text
    for item in entities.json():
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                reviewed = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert reviewed.status_code == 200, reviewed.text

    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]

    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    payload = verified.json()
    assert payload["status"] == "VERIFIED_SAFE", payload
    assert payload["passed"] == 12, payload
    assert payload["failed"] == 0, payload
    assert payload["inconclusive"] == 0, payload
    assert payload["critical_failures"] == 0, payload
    assert payload["proof_score"] == 100, payload
