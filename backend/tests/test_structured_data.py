from __future__ import annotations

import csv
import io
import json
import zipfile
from xml.etree import ElementTree as ET

import pytest

from app.core.enums import FileType
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.extraction.structured_data import (
    StructuredDataset,
    StructuredTable,
    export_xlsx,
    parse_structured_data,
    render_structured_record,
    schema_signature,
    structured_visible_text,
)
from app.ingestion.validator import ValidationError, validate_upload
from app.ir.privacy_ir import build_privacy_ir, privacy_ir_summary, to_processed_document


HEADERS = [
    "Name", "Mobile", "Email", "Date of birth", "Age", "Address", "City",
    "PIN code", "Employer", "Job title", "Case reference", "Purpose",
]
ROW_A = [
    "Aarav Testperson", "+91 98765 43210", "aarav.test@example.org", "11 June 2007", "19",
    "42 Test Road Bengaluru Karnataka", "Bengaluru", "560038", "Example Systems Private Limited",
    "Junior Security Analyst", "VG-TEST-2026-001", "Fictional privacy research record",
]
ROW_B = [
    "Meera Sampleperson", "+91 99887 76655", "meera.sample@example.org", "19 July 2004", "22",
    "81 Demo Street Bengaluru Karnataka", "Bengaluru", "560038", "Example Systems Private Limited",
    "Security Analyst", "VG-TEST-2026-002", "Fictional privacy research record",
]


def csv_bytes(rows=None) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(HEADERS)
    for row in rows or [ROW_A, ROW_B]:
        writer.writerow(row)
    return stream.getvalue().encode("utf-8")


def json_bytes() -> bytes:
    records = []
    for row in [ROW_A, ROW_B]:
        record = dict(zip(HEADERS, row))
        record["metadata"] = {"cohort": "training-demo", "approved": True}
        records.append(record)
    return json.dumps(records, ensure_ascii=False).encode("utf-8")


def xlsx_bytes() -> bytes:
    dataset = StructuredDataset(
        format="xlsx",
        tables=[StructuredTable("Citizens", list(HEADERS), [list(ROW_A), list(ROW_B)])],
    )
    return export_xlsx(dataset)


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
    assert uploaded.json()["file_type"] == "DATASET"
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    payload = analysed.json()
    assert payload["file_type"] == "DATASET"
    assert payload["privacy_ir_schema"] == "veilgraph.privacy-ir.v1"
    assert payload["structured_records"] == 2
    _protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": level},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["passed"] == 12
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0
    assert proof["proof_score"] == 100
    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    return job_id, file_id, output_id, payload, transformed.json(), downloaded


def test_validator_accepts_csv_json_xlsx_and_rejects_extension_spoofing():
    for filename, data, expected_media in (
        ("records.csv", csv_bytes(), "text/csv"),
        ("records.json", json_bytes(), "application/json"),
        ("records.xlsx", xlsx_bytes(), "spreadsheetml.sheet"),
    ):
        file_type, media_type, digest = validate_upload(data, filename)
        assert file_type == FileType.DATASET
        assert expected_media in media_type
        assert len(digest) == 64

    with pytest.raises(ValidationError):
        validate_upload(json_bytes(), "spoofed.xlsx")


def test_dataset_enters_table_privacy_ir_with_plaintext_free_summary():
    doc = process_document(csv_bytes(), FileType.DATASET, "records.csv")
    ir = build_privacy_ir(doc)
    summary = privacy_ir_summary(ir)
    assert ir.source_file_type == FileType.DATASET
    assert all(unit.kind == "TABLE" for unit in ir.units)
    assert summary["structured_format"] == "CSV"
    assert summary["structured_records"] == 2
    assert summary["structured_fields"] == len(HEADERS)
    assert summary["plaintext_persisted"] is False
    encoded = json.dumps(summary, sort_keys=True)
    assert "Aarav Testperson" not in encoded
    assert "aarav.test@example.org" not in encoded
    before = detect_all(doc)
    after = detect_all(to_processed_document(ir))
    signature = lambda items: sorted((item.entity_type.value, item.plaintext, item.page_index, item.page_char_start) for item in items)
    assert signature(before) == signature(after)


def test_csv_level4_end_to_end_uses_12_structured_release_gates(client):
    _job, _file, _output, analysis, transformed, downloaded = _end_to_end(
        client, "records.csv", csv_bytes(), "text/csv", 4
    )
    assert analysis["structured_format"] == "CSV"
    assert transformed["output_media_type"].startswith("text/csv")
    assert transformed["download_name"].endswith(".csv")
    text = downloaded.content.decode("utf-8")
    assert "Aarav Testperson" not in text
    assert "Meera Sampleperson" not in text
    assert "+91 98765 43210" not in text
    assert "aarav.test@example.org" not in text
    assert "Person A" in text and "Person B" in text
    assert "Fictional privacy research record" in text
    assert schema_signature(csv_bytes()) == schema_signature(downloaded.content)


def test_json_level4_preserves_nested_structure_and_values_not_targeted(client):
    _job, _file, _output, analysis, transformed, downloaded = _end_to_end(
        client, "records.json", json_bytes(), "application/json", 4
    )
    assert analysis["structured_format"] == "JSON"
    assert transformed["output_media_type"] == "application/json"
    protected = json.loads(downloaded.content)
    assert isinstance(protected, list) and len(protected) == 2
    assert protected[0]["Name"].startswith("Person ")
    assert protected[0]["metadata"] == {"approved": True, "cohort": "training-demo"}
    assert protected[0]["Purpose"] == "Fictional privacy research record"
    assert "Aarav Testperson" not in downloaded.content.decode("utf-8")
    assert schema_signature(json_bytes()) == schema_signature(downloaded.content)


def test_xlsx_level4_regenerates_clean_workbook_and_preserves_sheet_schema(client):
    source = xlsx_bytes()
    _job, _file, _output, analysis, transformed, downloaded = _end_to_end(
        client,
        "records.xlsx",
        source,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        4,
    )
    assert analysis["structured_format"] == "XLSX"
    assert transformed["download_name"].endswith(".xlsx")
    parsed = parse_structured_data(downloaded.content, "protected.xlsx")
    assert parsed.tables[0].name == "Citizens"
    assert parsed.tables[0].headers == HEADERS
    visible = structured_visible_text(downloaded.content, "protected.xlsx")
    assert "Aarav Testperson" not in visible
    assert "Person A" in visible
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        names = {name.casefold() for name in archive.namelist()}
        assert not any("docprops" in name or "externallinks" in name or "vbaproject" in name for name in names)


def test_dataset_graph_only_claims_cross_column_combo_when_same_record_contains_it(client):
    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("records.csv", csv_bytes(), "text/csv")},
    ).json()
    file_id = uploaded["id"]
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    graph = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=4").json()
    assert any("Same-record cross-column linkage" in path["reason"] for path in graph["high_risk_paths"])
    assert any(node["label"] == "Dataset record population" for node in graph["nodes"])
    assert not any("related person" in path["reason"].casefold() for path in graph["high_risk_paths"])


def test_dataset_graph_does_not_invent_same_record_combo_across_different_rows(client):
    headers = ["Age", "City", "Job title", "Purpose"]
    rows = [["19", "", "", "row one"], ["", "Bengaluru", "Security Analyst", "row two"]]
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    data = stream.getvalue().encode()
    job_id = _create_job(client, 4)
    file_id = client.post(f"/api/v1/jobs/{job_id}/files", files={"file": ("split.csv", data, "text/csv")}).json()["id"]
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    graph = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=4").json()
    assert not any("Age, locality and job title" in path["reason"] for path in graph["high_risk_paths"])


def test_formula_bearing_xlsx_is_rejected_fail_closed():
    source = xlsx_bytes()
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(source)) as zin, zipfile.ZipFile(out, "w") as zout:
        for info in zin.infolist():
            payload = zin.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                root = ET.fromstring(payload)
                first_data_cell = root.find(".//{*}sheetData/{*}row[@r='2']/{*}c")
                assert first_data_cell is not None
                ET.SubElement(first_data_cell, "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}f").text = 'CONCAT("Aarav"," Testperson")'
                payload = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            zout.writestr(info, payload)
    with pytest.raises(ValidationError, match="Formula-bearing XLSX"):
        validate_upload(out.getvalue(), "formula.xlsx")


def test_csv_formula_injection_is_neutralized_in_protected_export(client):
    rows = [list(ROW_A), list(ROW_B)]
    rows[0][-1] = "=HYPERLINK(\"https://invalid.example\",\"click\")"
    _job, _file, _output, _analysis, _transformed, downloaded = _end_to_end(
        client, "formula.csv", csv_bytes(rows), "text/csv", 4
    )
    parsed = list(csv.reader(io.StringIO(downloaded.content.decode("utf-8"))))
    assert parsed[1][-1].startswith("'=")


def test_structured_record_preview_uses_the_same_coordinate_space_as_detection():
    data = csv_bytes()
    document = process_document(data, FileType.DATASET, "records.csv")
    page = document.pages[0]
    preview = render_structured_record(data, 0, "records.csv")

    # Original-preview annotations use the detector's TABLE IR coordinates. The
    # lazy rendered record must therefore share the exact same canvas geometry;
    # otherwise correctly detected boxes appear shifted in the judge UI.
    assert preview.width == round(page.width)
    assert preview.height == round(page.height)
    for line in page.lines:
        for token in line.tokens:
            assert 0 <= token.x0 < token.x1 <= preview.width
            assert 0 <= token.y0 < token.y1 <= preview.height


def test_dataset_original_and_protected_previews_render_as_png(client):
    job_id, file_id, output_id, _analysis, _transformed, _downloaded = _end_to_end(
        client, "preview.csv", csv_bytes(), "text/csv", 4
    )
    original = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=0")
    protected = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/preview?page=0")
    for response in (original, protected):
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("image/png")
        assert response.content.startswith(b"\x89PNG")


def test_dataset_certificate_and_complete_proof_package_are_issued(client):
    job_id, _file_id, output_id, _analysis, _transformed, _downloaded = _end_to_end(
        client, "proof.json", json_bytes(), "application/json", 4
    )
    certificate = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate")
    assert certificate.status_code == 200
    assert certificate.json()["signature_valid"] is True
    package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert package.status_code == 200
    assert package.headers["content-type"].startswith("application/zip")
    assert len(package.headers["x-veilgraph-bundle-sha256"]) == 64


def test_repeated_identity_gets_same_level4_pseudonym_across_dataset_records(client):
    repeated = [list(ROW_A), list(ROW_A)]
    repeated[1][-2] = "VG-TEST-2026-009"
    _job, _file, _output, _analysis, _transformed, downloaded = _end_to_end(
        client, "repeat.csv", csv_bytes(repeated), "text/csv", 4
    )
    rows = list(csv.DictReader(io.StringIO(downloaded.content.decode("utf-8"))))
    assert rows[0]["Name"] == rows[1]["Name"] == "Person A"
    assert rows[0]["Employer"] == rows[1]["Employer"] == "Organisation A"
