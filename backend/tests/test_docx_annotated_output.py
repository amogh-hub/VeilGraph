from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.core.enums import FileType
from app.extraction.docx import (
    DOCX_MEDIA_TYPE,
    docx_hidden_channel_findings,
    docx_structure_signature,
    docx_visible_text,
    parse_docx,
)
from app.ingestion.validator import ValidationError, validate_upload
from app.ir.privacy_ir import build_privacy_ir, privacy_ir_summary
from app.proof.package import verify_proof_package_bytes


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _docx_bytes(*, include_external_link: bool = True, split_name_runs: bool = True) -> bytes:
    name_runs = (
        '<w:r><w:t>Aarav </w:t></w:r><w:r><w:t>Testperson</w:t></w:r>'
        if split_name_runs else '<w:r><w:t>Aarav Testperson</w:t></w:r>'
    )
    document = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W}" xmlns:r="{R}"><w:body>
  <w:p><w:r><w:t>FICTIONAL CITIZEN RECORD</w:t></w:r></w:p>
  <w:p><w:r><w:t>Citizen: </w:t></w:r>{name_runs}</w:p>
  <w:p><w:r><w:t>Mobile: +91 98765 43210</w:t></w:r></w:p>
  <w:p><w:r><w:t>Email: aarav.test@example.org</w:t></w:r></w:p>
  <w:p><w:r><w:t>Date of birth: 11 June 2007</w:t></w:r></w:p>
  <w:p><w:r><w:t>Age: 19</w:t></w:r></w:p>
  <w:p><w:r><w:t>Address: 42 Test Road Bengaluru Karnataka</w:t></w:r></w:p>
  <w:p><w:r><w:t>Locality: Indiranagar Bengaluru</w:t></w:r></w:p>
  <w:tbl><w:tr><w:tc><w:p><w:r><w:t>Case reference</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>VG-TEST-2026-001</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
  <w:p><w:hyperlink r:id="rIdLink"><w:r><w:t>Public portal</w:t></w:r></w:hyperlink></w:p>
  <w:p><w:r><w:t>Purpose: This fictional record exists only for privacy testing and training.</w:t></w:r></w:p>
  <w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/></w:sectPr>
</w:body></w:document>'''.encode()
    header = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>Header contact: aarav.test@example.org</w:t></w:r></w:p></w:hdr>'''.encode()
    footer = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="{W}"><w:p><w:r><w:t>Training-only footer remains useful.</w:t></w:r></w:p></w:ftr>'''.encode()
    content_types = b'''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>'''
    root_rels = b'''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>'''
    link = (
        '<Relationship Id="rIdLink" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/profile?email=aarav.test@example.org" TargetMode="External"/>'
        if include_external_link else ""
    )
    doc_rels = f'''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
{link}
</Relationships>'''.encode()
    core = b'''<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Aarav Testperson</dc:creator><dc:title>aarav.test@example.org</dc:title></cp:coreProperties>'''

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("word/document.xml", document)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/header1.xml", header)
        z.writestr("word/footer1.xml", footer)
        z.writestr("docProps/core.xml", core)
    return out.getvalue()


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


def _verified_docx(client):
    source = _docx_bytes()
    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("citizen-record.docx", source, DOCX_MEDIA_TYPE)},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    assert uploaded.json()["file_type"] == "DOCX"
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    assert analysed.json()["file_type"] == "DOCX"
    assert analysed.json()["privacy_ir_schema"] == "veilgraph.privacy-ir.v1"
    _protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    assert transformed.json()["download_name"].endswith(".docx")
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()
    assert verified.json()["attack_coverage"] == 12
    assert verified.json()["passed"] == 12
    assert verified.json()["failed"] == 0
    assert verified.json()["inconclusive"] == 0
    return source, job_id, file_id, output_id, analysed.json(), transformed.json(), verified.json()


def test_docx_validator_accepts_real_docx_and_rejects_spoof_and_active_package():
    source = _docx_bytes()
    file_type, media_type, digest = validate_upload(source, "citizen-record.docx")
    assert file_type == FileType.DOCX
    assert media_type == DOCX_MEDIA_TYPE
    assert len(digest) == 64

    with pytest.raises(ValidationError):
        validate_upload(b"PK\x03\x04not-a-docx", "spoof.docx")

    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(source)) as zin, zipfile.ZipFile(out, "w") as zout:
        for name in zin.namelist():
            zout.writestr(name, zin.read(name))
        zout.writestr("word/embeddings/oleObject1.bin", b"danger")
    with pytest.raises(ValidationError, match="embedded|active|OLE"):
        validate_upload(out.getvalue(), "active.docx")


def test_docx_enters_privacy_ir_with_header_footer_and_split_runs():
    source = _docx_bytes()
    package = parse_docx(source)
    assert any(part.name == "word/header1.xml" for part in package.text_parts)
    assert any(part.name == "word/footer1.xml" for part in package.text_parts)
    assert "Aarav Testperson" in docx_visible_text(source)
    from app.extraction.document_processor import process_document
    doc = process_document(source, FileType.DOCX, "citizen-record.docx")
    ir = build_privacy_ir(doc)
    summary = privacy_ir_summary(ir)
    assert ir.source_file_type == FileType.DOCX
    assert summary["docx_text_parts"] == 3
    assert summary["docx_virtual_pages"] >= 3
    assert summary["plaintext_persisted"] is False
    assert "Aarav Testperson" not in json.dumps(summary, sort_keys=True)


def test_docx_level4_end_to_end_preserves_structure_scrubs_metadata_and_passes_12_gates(client):
    source, job_id, file_id, output_id, _analysis, _transformed, proof = _verified_docx(client)
    assert proof["proof_score"] == 100
    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith(DOCX_MEDIA_TYPE)
    protected = downloaded.content
    visible = docx_visible_text(protected)
    assert "Aarav Testperson" not in visible
    assert "+91 98765 43210" not in visible
    assert "aarav.test@example.org" not in visible
    assert "Person A" in visible
    assert "Purpose: This fictional record exists only for privacy testing and training." in visible
    assert docx_structure_signature(source) == docx_structure_signature(protected)
    assert docx_hidden_channel_findings(protected) == []
    with zipfile.ZipFile(io.BytesIO(protected)) as z:
        names = {name.casefold() for name in z.namelist()}
        assert "docprops/core.xml" not in names
        rels = z.read("word/_rels/document.xml.rels").decode("utf-8").casefold()
        assert "targetmode=\"external\"" not in rels
        assert "aarav.test@example.org" not in rels

    for page in range(min(3, int(_analysis["page_count"]))):
        preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page={page}")
        assert preview.status_code == 200, preview.text
        assert preview.content.startswith(b"\x89PNG")


def test_annotated_export_is_separate_source_plaintext_free_and_certificate_bound(client):
    _source, job_id, _file_id, output_id, _analysis, transformed, _proof = _verified_docx(client)
    export = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/annotated-export")
    assert export.status_code == 200, export.text
    assert export.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(export.content)) as z:
        names = set(z.namelist())
        assert transformed["download_name"] in names
        assert "veilgraph-annotation-manifest.json" in names
        assert "veilgraph-certificate.json" in names
        assert "veilgraph-annotated-export-index.json" in names
        assert any(name.startswith("annotated-previews/") and name.endswith(".png") for name in names)
        annotation = json.loads(z.read("veilgraph-annotation-manifest.json"))
        encoded = json.dumps(annotation, sort_keys=True)
        assert annotation["schema"] == "veilgraph.annotation-evidence.v1"
        assert annotation["source_plaintext_included"] is False
        assert annotation["entry_count"] > 0
        assert "Aarav Testperson" not in encoded
        assert "aarav.test@example.org" not in encoded
        assert all("replacement_preview" in entry for entry in annotation["entries"])

    proof_package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert proof_package.status_code == 200, proof_package.text
    result = verify_proof_package_bytes(proof_package.content)
    assert result["valid"] is True, result
    checks = {item["name"]: item for item in result["checks"]}
    assert checks["annotation_manifest_integrity"]["valid"] is True
    assert checks["annotation_manifest_binding"]["valid"] is True


def test_annotated_export_remains_locked_before_verification(client):
    source = _docx_bytes()
    job_id = _create_job(client, 4)
    file_id = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("citizen-record.docx", source, DOCX_MEDIA_TYPE)},
    ).json()["id"]
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    _protect_pending(client, job_id, file_id)
    transformed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 4})
    output_id = transformed.json()["output_id"]
    locked = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/annotated-export")
    assert locked.status_code == 423


def test_docx_embedded_image_unit_is_regenerated_metadata_free_and_region_changed():
    from PIL import Image, PngImagePlugin
    from app.core.enums import EntityType
    from app.extraction.docx import sanitize_docx
    from app.transformation.sanitizer import ProtectionInstruction

    base = _docx_bytes()
    image = Image.new("RGB", (240, 120), "white")
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "Aarav Testperson")
    img = io.BytesIO()
    image.save(img, format="PNG", pnginfo=meta)

    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(base)) as zin, zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            raw = zin.read(name)
            if name == "[Content_Types].xml":
                raw = raw.replace(
                    b'<Default Extension="xml" ContentType="application/xml"/>',
                    b'<Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/>',
                )
            zout.writestr(name, raw)
        zout.writestr("word/media/image1.png", img.getvalue())
    source = out.getvalue()
    package = parse_docx(source)
    image_ref = next(ref for ref in package.page_refs if ref.kind == "IMAGE")
    protected, media_type, extension, report = sanitize_docx(
        source,
        [ProtectionInstruction(
            entity_id="visual-1",
            mention_id="visual-mention-1",
            entity_type=EntityType.FACE,
            page_index=image_ref.page_index,
            rect=(20.0, 20.0, 120.0, 100.0),
            replacement="[PROTECTED]",
        )],
        "embedded.docx",
    )
    assert media_type == DOCX_MEDIA_TYPE
    assert extension == "protected.docx"
    assert report["embedded_images_modified"] == ["word/media/image1.png"]
    assert docx_structure_signature(source) == docx_structure_signature(protected)
    with zipfile.ZipFile(io.BytesIO(protected)) as z:
        rebuilt = Image.open(io.BytesIO(z.read("word/media/image1.png")))
        assert rebuilt.getexif() == {}
        assert "Author" not in rebuilt.info
        # The protected region is no longer all-white.
        crop = rebuilt.convert("RGB").crop((20, 20, 120, 100))
        assert any(low != high for low, high in crop.getextrema())


def test_docx_acceptance_fixture_structural_context_preview_units_and_full_release(client):
    """Judge-fixture regression for the browser issues found during manual acceptance.

    This deliberately validates the DOCX adapter layer rather than changing the
    frozen Broad PII v3 benchmark path.
    """
    from pathlib import Path
    from app.extraction.document_processor import process_document

    source = Path(__file__).resolve().parent.parent.joinpath("test_docx_privacy_demo.docx").read_bytes()
    document = process_document(source, FileType.DOCX, "test_docx_privacy_demo.docx")
    assert [item["label"] for item in document.metadata["docx_page_map"]] == ["Body", "Header", "Footer"]

    body = document.pages[0]
    line_by_text = {line.text: line for line in body.lines}
    assert not any(line.text.startswith("\t") for line in body.lines)
    assert line_by_text["Field"].tokens[0].y0 == line_by_text["Value"].tokens[0].y0
    assert line_by_text["Name"].tokens[0].y0 == line_by_text["Siya Khanna"].tokens[0].y0
    assert len({token.y0 for token in line_by_text[next(text for text in line_by_text if text.startswith("Case note:"))].tokens}) >= 2

    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_docx_privacy_demo.docx", source, DOCX_MEDIA_TYPE)},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    payload = analysed.json()
    assert payload["file_type"] == "DOCX"
    assert payload["docx_text_parts"] == 3
    assert payload["docx_media_images"] == 0
    assert [unit["label"] for unit in payload["docx_units"]] == ["Body", "Header", "Footer"]
    # 3 e-mails + 3 phones + Dev twice + Siya + Aisha.
    assert payload["direct_identifier_mentions"] == 10
    # Bengaluru/Karnataka + Indore + age + two dates.
    assert payload["quasi_identifier_mentions"] == 5

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    context_mentions = [mention for item in entities for mention in item["mentions"] if mention.get("context_label")]
    contexts = {mention["context_label"] for mention in context_mentions}
    assert "docx-structural:primary-subject" in contexts
    assert "docx-structural:repeat-person-name" in contexts
    assert "docx-structural:location" in contexts
    assert "docx-structural:case-owner" in contexts
    assert payload["pending_reviews"] == 3

    _protect_pending(client, job_id, file_id)
    transformed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 4})
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()
    assert verified.json()["passed"] == 12

    protected = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").content
    visible = docx_visible_text(protected)
    for original in (
        "Dev Malhotra", "Siya Khanna", "Aisha Rao", "Bengaluru, Karnataka",
        "dev.malhotra@example.org", "siya.khanna@example.org", "ops@example.org",
        "+91 90000 10001", "+91 90000 10012", "+91 98888 70001",
    ):
        assert original not in visible

    # OPC package-control parts are emitted using the Office-compatible default
    # namespace form. Namespace-equivalent ``ns0:Types`` / ``ns0:Relationships``
    # files are rejected by LibreOffice even though python-docx can parse them.
    with zipfile.ZipFile(io.BytesIO(protected)) as archive:
        content_types = archive.read("[Content_Types].xml")
        root_rels = archive.read("_rels/.rels")
        document_rels = archive.read("word/_rels/document.xml.rels")
        assert b"ns0:" not in content_types
        assert b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' in content_types
        for rels in (root_rels, document_rels):
            assert b"ns0:" not in rels
            assert b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' in rels

    # Derived annotated-output previews must re-locate the replacement in the
    # protected document instead of reusing the source rectangle. In the footer
    # Contact C wraps to its own second visual row and must not claim the entire
    # surrounding footer sentence.
    from app.presentation.preview import _docx_protected_rects_for_annotation
    protected_document = process_document(protected, FileType.DOCX, "protected.docx")
    footer = next(
        protected_document.pages[int(item["page_index"])]
        for item in protected_document.metadata["docx_page_map"]
        if item["label"] == "Footer"
    )
    phone_rects = _docx_protected_rects_for_annotation(footer, {
        "replacement_preview": "Contact C",
        "rect": [54.0, 48.0, 788.0, 104.0],
    })
    assert len(phone_rects) == 1
    assert phone_rects[0][1] >= 78.0
    assert (phone_rects[0][2] - phone_rects[0][0]) < 180.0


def test_docx_preview_segments_wrapped_phone_and_uses_person_semantic_colour():
    """A wrapped footer identifier must never become one giant union box."""
    from pathlib import Path

    from app.core.enums import EntityType
    from app.extraction.document_processor import process_document
    from app.presentation.preview import _color_for, _docx_rects_for_char_span

    source = Path(__file__).resolve().parent.parent.joinpath("test_docx_privacy_demo.docx").read_bytes()
    document = process_document(source, FileType.DOCX, "test_docx_privacy_demo.docx")
    footer_index = next(
        int(item["page_index"])
        for item in document.metadata["docx_page_map"]
        if item["label"] == "Footer"
    )
    footer = document.pages[footer_index]
    line = next(line for line in footer.lines if "+91 98888 70001" in line.text)
    local_start = line.text.index("+91 98888 70001")
    char_start = line.page_char_start + local_start
    char_end = char_start + len("+91 98888 70001")

    rects = _docx_rects_for_char_span(footer, char_start, char_end)
    assert len(rects) == 2  # +91 on the first visual row; remaining digits on the second.
    assert all((x1 - x0) < 260 for x0, _y0, x1, _y1 in rects)
    assert rects[0][1] < rects[1][1]

    # Preview semantics now match the graph legend: person/subject is purple,
    # direct identifiers are red, quasi-identifiers are teal.
    assert _color_for(EntityType.PERSON_NAME) == (139, 121, 246)
    assert _color_for(EntityType.EMAIL) == (224, 103, 115)
    assert _color_for(EntityType.LOCALITY) == (72, 189, 168)


def test_docx_preview_routes_wrapped_entity_fragments_to_one_evidence_chip_in_source_order():
    """Footer email/phone labels must be visually attributable, even on one row."""
    from pathlib import Path

    from app.extraction.document_processor import process_document
    from app.presentation.preview import (
        _docx_connector_lines,
        _docx_mention_sort_key,
        _docx_rects_for_char_span,
    )

    source = Path(__file__).resolve().parent.parent.joinpath("test_docx_privacy_demo.docx").read_bytes()
    document = process_document(source, FileType.DOCX, "test_docx_privacy_demo.docx")
    footer = next(
        document.pages[int(item["page_index"])]
        for item in document.metadata["docx_page_map"]
        if item["label"] == "Footer"
    )
    line = next(line for line in footer.lines if "ops@example.org" in line.text and "+91 98888 70001" in line.text)

    email_local = line.text.index("ops@example.org")
    phone_local = line.text.index("+91 98888 70001")
    email_mention = {
        "page_char_start": line.page_char_start + email_local,
        "x0": 0.0,
        "y0": 0.0,
        "placeholder": "EMAIL_003",
    }
    phone_mention = {
        "page_char_start": line.page_char_start + phone_local,
        "x0": 0.0,
        "y0": 0.0,
        "placeholder": "PHONE_003",
    }
    ordered = sorted([phone_mention, email_mention], key=_docx_mention_sort_key)
    assert [item["placeholder"] for item in ordered] == ["EMAIL_003", "PHONE_003"]

    phone_start = line.page_char_start + phone_local
    phone_rects = _docx_rects_for_char_span(
        footer, phone_start, phone_start + len("+91 98888 70001")
    )
    assert len(phone_rects) == 2
    connectors = _docx_connector_lines(phone_rects, lane_x=797.0, label_x=820.0, target_y=120.0)
    # Two wrapped visual fragments converge on one routing lane, then one final
    # segment enters the single PHONE_003 chip.
    assert len(connectors) == 3
    assert connectors[0][2:] == (797.0, 120.0)
    assert connectors[1][2:] == (797.0, 120.0)
    assert connectors[2] == (797.0, 120.0, 816.0, 120.0)
    assert connectors[0][:2] != connectors[1][:2]


def test_docx_opc_control_parts_keep_office_compatible_default_namespaces():
    """Generated DOCX control parts must open in Word-compatible OPC consumers.

    xml.etree serializes these parts as ns0:Types / ns0:Relationships unless
    normalized. LibreOffice rejects that form even though python-docx accepts it.
    """
    from app.extraction.docx import sanitize_docx

    source = _docx_bytes(include_external_link=True)
    protected, media_type, extension, _report = sanitize_docx(source, [], "compat.docx")
    assert media_type == DOCX_MEDIA_TYPE
    assert extension == "protected.docx"
    with zipfile.ZipFile(io.BytesIO(protected)) as archive:
        content_types = archive.read("[Content_Types].xml")
        root_rels = archive.read("_rels/.rels")
        document_rels = archive.read("word/_rels/document.xml.rels")
    assert b"ns0:" not in content_types
    assert b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' in content_types
    for rels in (root_rels, document_rels):
        assert b"ns0:" not in rels
        assert b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' in rels
