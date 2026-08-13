from __future__ import annotations

import re

import pytest

from app.core.enums import FileType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.extraction.text_formats import decode_text_document, text_to_canonical_rtf
from app.ingestion.validator import ValidationError, validate_upload
from app.ir.privacy_ir import build_privacy_ir, to_processed_document


BASE_TEXT = """FICTIONAL CITIZEN RECORD
Citizen: Aarav Testperson
Mobile: +91 98765 43210
Email: aarav.test@example.org
Date of birth: 11 June 2007
Age: 19
Address: 42 Test Road Bengaluru Karnataka
Locality: Indiranagar Bengaluru
PIN code: 560038
Employer: Example Systems Private Limited
Job title: Junior Security Analyst
Case reference: VG-TEST-2026-001
Purpose: This fictional record exists only for privacy testing and training.
"""


def _create_job(client, level: int = 4) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public evidence release",
            "recipient": "Citizen information portal",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": level,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _protect_pending(client, job_id: str, file_id: str) -> None:
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    for item in entities:
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                response = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert response.status_code == 200, response.text


def _end_to_end(client, filename: str, data: bytes, content_type: str, level: int = 4):
    job_id = _create_job(client, level)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": (filename, data, content_type)},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    assert analysed.json()["file_type"] == "TEXT"
    assert analysed.json()["privacy_ir_schema"] == "veilgraph.privacy-ir.v1"
    _protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": level},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()
    assert verified.json()["passed"] == 12
    assert verified.json()["failed"] == 0
    assert verified.json()["inconclusive"] == 0
    assert verified.json()["proof_score"] == 100
    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200, downloaded.text
    return job_id, file_id, output_id, analysed.json(), transformed.json(), downloaded


def test_validator_accepts_txt_markdown_and_rtf_and_rejects_spoofed_binary():
    for filename, data in (
        ("record.txt", BASE_TEXT.encode("utf-8")),
        ("record.md", ("# Record\n\n" + BASE_TEXT).encode("utf-8")),
        ("record.rtf", text_to_canonical_rtf(BASE_TEXT)),
    ):
        file_type, media_type, sha256 = validate_upload(data, filename)
        assert file_type == FileType.TEXT
        assert len(sha256) == 64
        assert media_type

    with pytest.raises(ValidationError):
        validate_upload(b"\x00\x01\x02\x03\xff\xfe" * 50, "spoofed.txt")


def test_native_text_enters_privacy_ir_without_changing_detection_semantics():
    document = process_document(BASE_TEXT.encode("utf-8"), FileType.TEXT)
    before = detect_all(document)
    ir = build_privacy_ir(document)
    after = detect_all(to_processed_document(ir))
    signature = lambda items: sorted(
        (item.entity_type.value, item.plaintext, item.page_index, item.page_char_start, item.page_char_end)
        for item in items
    )
    assert signature(before) == signature(after)
    assert ir.source_file_type == FileType.TEXT
    assert ir.scanned_units == 0
    assert ir.unit_count >= 1
    assert {item.entity_type.value for item in before} >= {
        "PERSON_NAME", "PHONE", "EMAIL", "DATE_OF_BIRTH", "POSTCODE", "EMPLOYER", "CASE_REFERENCE"
    }


def test_txt_level4_end_to_end_runs_format_aware_12_attack_release_gate(client):
    _job, _file, _output, analysis, transformed, downloaded = _end_to_end(
        client, "record.txt", BASE_TEXT.encode("utf-8"), "text/plain", 4
    )
    assert analysis["scanned_pages"] == 0
    assert transformed["output_media_type"].startswith("text/plain")
    assert transformed["download_name"].endswith(".txt")
    protected = downloaded.content.decode("utf-8")
    assert "Aarav Testperson" not in protected
    assert "98765 43210" not in protected
    assert "aarav.test@example.org" not in protected
    assert "Person A" in protected
    assert "Purpose: This fictional record exists only for privacy testing and training." in protected


def test_markdown_output_preserves_markdown_structure_and_native_extension(client):
    markdown = (
        "# Privacy Test Record\n\n"
        "This document must keep its useful Markdown structure.\n\n"
        + BASE_TEXT
        + "\n## Non-sensitive analysis\n\n- retain this bullet\n- retain this second bullet\n"
    ).encode("utf-8")
    _job, _file, _output, _analysis, transformed, downloaded = _end_to_end(
        client, "record.md", markdown, "text/markdown", 4
    )
    assert transformed["output_media_type"].startswith("text/markdown")
    assert transformed["download_name"].endswith(".md")
    protected = downloaded.content.decode("utf-8")
    assert protected.startswith("# Privacy Test Record")
    assert "## Non-sensitive analysis" in protected
    assert "- retain this bullet" in protected
    assert "Aarav Testperson" not in protected


def test_rtf_is_regenerated_without_hidden_author_metadata_and_passes_release_gate(client):
    visible = BASE_TEXT
    body = text_to_canonical_rtf(visible).decode("ascii")
    # Add an input metadata group containing the same fictional identity. The
    # secure RTF exporter must never carry it into the protected artifact.
    source = body.replace("{\\rtf1\\ansi", "{\\rtf1\\ansi{\\info{\\author Aarav Testperson}{\\comment aarav.test@example.org}}")
    _job, _file, _output, _analysis, transformed, downloaded = _end_to_end(
        client, "record.rtf", source.encode("ascii"), "application/rtf", 4
    )
    assert transformed["output_media_type"] == "application/rtf"
    assert transformed["download_name"].endswith(".rtf")
    raw = downloaded.content.decode("latin-1").casefold()
    assert "\\author" not in raw
    assert "\\comment" not in raw
    assert "aarav testperson" not in raw
    assert "aarav.test@example.org" not in raw
    visible_protected = decode_text_document(downloaded.content, "protected.rtf").text
    assert "Person A" in visible_protected


def test_native_text_original_and_protected_previews_render_in_gui(client):
    job_id, file_id, output_id, _analysis, _transformed, _downloaded = _end_to_end(
        client, "preview.txt", BASE_TEXT.encode("utf-8"), "text/plain", 4
    )
    original_preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=0")
    protected_preview = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/preview?page=0")
    for response in (original_preview, protected_preview):
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("image/png")
        assert response.content.startswith(b"\x89PNG")


def test_long_text_crosses_virtual_pages_but_global_character_spans_remain_correct(client):
    filler = "\n".join(f"Non-sensitive audit context line {index:03d} remains useful." for index in range(55))
    text = (
        filler
        + "\nCitizen: Aarav Testperson\n"
        + "Mobile: +91 98765 43210\n"
        + "Email: aarav.test@example.org\n"
        + "Case reference: VG-TEST-2026-001\n"
        + "Final useful statement remains available after protection.\n"
    )
    _job, _file, _output, analysis, _transformed, downloaded = _end_to_end(
        client, "long.txt", text.encode("utf-8"), "text/plain", 4
    )
    assert analysis["page_count"] >= 2
    protected = downloaded.content.decode("utf-8")
    assert "Aarav Testperson" not in protected
    assert "98765 43210" not in protected
    assert "aarav.test@example.org" not in protected
    assert "Final useful statement remains available after protection." in protected


def test_native_text_proof_package_and_certificate_are_issued_after_verified_release(client):
    job_id, _file_id, output_id, _analysis, _transformed, _downloaded = _end_to_end(
        client, "proof.txt", BASE_TEXT.encode("utf-8"), "text/plain", 4
    )
    certificate = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate")
    assert certificate.status_code == 200, certificate.text
    assert certificate.json()["signature_valid"] is True
    package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert package.status_code == 200, package.text
    assert package.headers["content-type"].startswith("application/zip")
    assert len(package.headers["x-veilgraph-bundle-sha256"]) == 64
