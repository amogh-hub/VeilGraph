from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

from app.core.enums import EntityType
from app.security.signing import verify_payload
from app.transformation.synthetic_export import export_synthetic_representation
from app.verification.red_team import _value_present


def _csv() -> bytes:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["Name", "Email", "Phone", "Age", "City", "Score"])
    rows = [
        ["Aarav Testperson", "aarav@example.org", "+91 98765 43210", 24, "Bengaluru", 71],
        ["Meera Sampleperson", "meera@example.org", "+91 99887 76655", 31, "Mysuru", 83],
        ["Kabir Demoperson", "kabir@example.org", "+91 91234 56780", 45, "Pune", 92],
    ]
    writer.writerows(rows)
    return out.getvalue().encode("utf-8")


def _l5_verified(client):
    source = _csv()
    job = client.post("/api/v1/jobs", json={
        "purpose": "Synthetic research release",
        "recipient": "Research partner",
        "audience_profile": "RESEARCH_PARTNER",
        "privacy_level": 5,
    })
    assert job.status_code == 201, job.text
    job_id = job.json()["id"]
    upload = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("phase3-synthetic.csv", source, "text/csv")},
    )
    assert upload.status_code == 201, upload.text
    file_id = upload.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    for entity in entities:
        for mention in entity["mentions"]:
            if mention["review_status"] == "PENDING":
                reviewed = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert reviewed.status_code == 200, reviewed.text
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 5},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "VERIFIED_SAFE"
    return job_id, output_id


def test_synthetic_export_module_supports_csv_json_xlsx_docx_pdf():
    source = _csv()
    for target in ("csv", "json", "xlsx", "docx", "pdf"):
        artifact = export_synthetic_representation(source, "synthetic.csv", target)
        assert artifact.data
        assert artifact.extension == f".{target}"
        assert artifact.report["target_format"] == target
        assert artifact.report["source_synthetic_sha256"] == hashlib.sha256(source).hexdigest()
        assert artifact.report["export_sha256"] == hashlib.sha256(artifact.data).hexdigest()
        assert artifact.report["record_count"] == 3


def test_docx_synthetic_export_is_deterministic_valid_ooxml_without_extra_runtime_package():
    source = _csv()
    first = export_synthetic_representation(source, "synthetic.csv", "docx")
    second = export_synthetic_representation(source, "synthetic.csv", "docx")
    assert first.data == second.data
    with zipfile.ZipFile(io.BytesIO(first.data)) as archive:
        assert archive.testzip() is None
        assert set(archive.namelist()) == {
            "[Content_Types].xml",
            "_rels/.rels",
            "docProps/app.xml",
            "docProps/core.xml",
            "word/document.xml",
        }
        document_xml = archive.read("word/document.xml").decode("utf-8")
        assert "VeilGraph Synthetic Twin Export" in document_xml
        assert first.report["source_synthetic_sha256"] in document_xml


def test_verified_level5_output_can_be_exported_to_all_supported_formats_with_signed_receipt(client):
    job_id, output_id = _l5_verified(client)
    for target in ("csv", "json", "xlsx", "docx", "pdf"):
        response = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/synthetic-export?format={target}")
        assert response.status_code == 200, response.text
        assert response.content
        assert response.headers["x-veilgraph-synthetic-export-sha256"] == hashlib.sha256(response.content).hexdigest()
        receipt = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/synthetic-export-receipt?format={target}")
        assert receipt.status_code == 200, receipt.text
        signed = receipt.json()
        assert signed["payload"]["target_format"] == target
        assert signed["payload"]["export_sha256"] == hashlib.sha256(response.content).hexdigest()
        assert verify_payload(signed["payload"], signed["signature_b64"], signed["payload"]["signer"]["public_key_b64"])


def test_synthetic_export_is_fail_closed_before_verification(client):
    source = _csv()
    job = client.post("/api/v1/jobs", json={"purpose": "Synthetic release", "recipient": "Research", "audience_profile": "RESEARCH_PARTNER", "privacy_level": 5}).json()
    upload = client.post(f"/api/v1/jobs/{job['id']}/files", files={"file": ("source.csv", source, "text/csv")}).json()
    client.post(f"/api/v1/jobs/{job['id']}/files/{upload['id']}/analyse")
    for entity in client.get(f"/api/v1/jobs/{job['id']}/files/{upload['id']}/entities").json():
        for mention in entity["mentions"]:
            if mention["review_status"] == "PENDING":
                client.post(f"/api/v1/jobs/{job['id']}/mentions/{mention['id']}/review", json={"action": "PROTECT"})
    transformed = client.post(f"/api/v1/jobs/{job['id']}/files/{upload['id']}/transform", json={"privacy_level": 5}).json()
    blocked = client.get(f"/api/v1/jobs/{job['id']}/outputs/{transformed['output_id']}/synthetic-export?format=pdf")
    assert blocked.status_code == 423


def test_age_leak_check_distinguishes_exact_age_from_generalized_range_and_numeric_substrings():
    assert _value_present("Age: 24", EntityType.AGE, "24") is True
    assert _value_present("Age 18-24", EntityType.AGE, "24") is False
    assert _value_present("postcode 560024", EntityType.AGE, "24") is False
    assert _value_present("phone +91 90000 12400", EntityType.AGE, "24") is False
