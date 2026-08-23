from __future__ import annotations

import io

import fitz
from PIL import Image

from generate_scanned_test_document import build_scanned_pdf, build_scanned_png


def create_job(client):
    response = client.post(
        "/api/v1/jobs",
        json={"purpose": "Public release", "recipient": "Citizen portal", "privacy_level": 1},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def upload(client, job_id: str, filename: str, data: bytes, media_type: str):
    response = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": (filename, data, media_type)},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def resolve_pending_reviews(client, job_id: str, file_id: str, *, ignore_names: bool = False) -> int:
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities")
    assert entities.status_code == 200
    pending: list[tuple[str, str, float]] = [
        (item["entity"]["entity_type"], mention["id"], mention["confidence"])
        for item in entities.json()
        for mention in item["mentions"]
        if mention["review_status"] == "PENDING"
    ]
    for entity_type, mention_id, confidence in pending:
        # Geometry-only QR polygons are preserved as utility unless a reviewer
        # explicitly confirms them. Real decoded QR codes are never pending.
        action = "IGNORE" if entity_type == "QR_CODE" and confidence <= 0.55 else "PROTECT"
        if ignore_names and entity_type == "PERSON_NAME":
            action = "IGNORE"
        response = client.post(
            f"/api/v1/jobs/{job_id}/mentions/{mention_id}/review",
            json={"action": action},
        )
        assert response.status_code == 200, response.text
    return len(pending)


def test_slice_b_scanned_pdf_complete_fail_closed_pipeline(client):
    job_id = create_job(client)
    file_id = upload(client, job_id, "fictional-scan.pdf", build_scanned_pdf(), "application/pdf")

    analysis = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysis.status_code == 200, analysis.text
    body = analysis.json()
    assert body["file_type"] == "PDF"
    assert body["scanned_pages"] == 2
    assert body["direct_identifier_mentions"] >= 6
    assert body["visual_mentions"] >= 2
    assert body["pending_reviews"] >= 2  # person name plus signature, and possibly an undecoded QR candidate

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    name_entities = [item for item in entities if item["entity"]["entity_type"] == "PERSON_NAME"]
    assert len(name_entities) == 1
    assert name_entities[0]["mentions"][0]["review_status"] == "PENDING"

    original_preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=0")
    assert original_preview.status_code == 200
    assert original_preview.headers["content-type"].startswith("image/png")

    blocked_transform = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    )
    assert blocked_transform.status_code == 409

    assert resolve_pending_reviews(client, job_id, file_id) >= 2
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    assert transformed.json()["transformations_applied"] >= 8
    protected_preview = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/preview?page=0")
    assert protected_preview.status_code == 200
    assert protected_preview.headers["content-type"].startswith("image/png")

    assert client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").status_code == 423

    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    verification = verified.json()
    assert verification["status"] == "VERIFIED_SAFE", verification
    assert verification["passed"] == 12
    assert verification["failed"] == 0
    assert verification["inconclusive"] == 0

    download = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert download.status_code == 200, download.text
    document = fitz.open(stream=download.content, filetype="pdf")
    text = "".join(page.get_text("text", sort=True) for page in document)
    metadata = {key: value for key, value in document.metadata.items() if value and key not in {"format", "encryption"}}
    document.close()
    assert "aarav testperson" not in text.casefold()
    assert "aarav.test@example.org" not in text.casefold()
    assert "ABCDE1234F" not in text.upper()
    assert "9876543210" not in "".join(character for character in text if character.isdigit())
    assert metadata == {}

    destroyed = client.delete(f"/api/v1/jobs/{job_id}/destroy")
    assert destroyed.status_code == 200
    assert destroyed.json()["destroyed_outputs"] == 1
    assert client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").status_code in {404, 410}


def test_reviewed_false_positive_name_can_be_ignored_without_poisoning_verification(client):
    job_id = create_job(client)
    file_id = upload(client, job_id, "fictional-scan.png", build_scanned_png(), "image/png")
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    resolve_pending_reviews(client, job_id, file_id, ignore_names=True)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    )
    assert transformed.status_code == 200, transformed.text
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{transformed.json()['output_id']}/verify")
    assert verified.status_code == 200
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()


def test_slice_b_standalone_image_pipeline(client):
    job_id = create_job(client)
    file_id = upload(client, job_id, "fictional-scan.png", build_scanned_png(), "image/png")
    analysis = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["file_type"] == "IMAGE"
    resolve_pending_reviews(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()
    download = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("image/png")
    image = Image.open(io.BytesIO(download.content))
    assert image.format == "PNG"
    assert not image.getexif()


def test_wrong_job_cannot_access_output(client):
    job_id = create_job(client)
    file_id = upload(client, job_id, "fictional-scan.png", build_scanned_png(), "image/png")
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    resolve_pending_reviews(client, job_id, file_id)
    output = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    ).json()
    other_job = create_job(client)
    assert client.get(f"/api/v1/jobs/{other_job}/outputs/{output['output_id']}/download").status_code == 404


def test_mandatory_ocr_verification_is_fail_closed(client, monkeypatch):
    import app.verification.red_team as red_team

    job_id = create_job(client)
    file_id = upload(client, job_id, "fictional-scan.png", build_scanned_png(), "image/png")
    assert client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse").status_code == 200
    resolve_pending_reviews(client, job_id, file_id)
    output_id = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform", json={"privacy_level": 1}
    ).json()["output_id"]

    original_which = red_team.shutil.which

    def unavailable(command: str):
        if command == "tesseract":
            return None
        return original_which(command)

    monkeypatch.setattr(red_team.shutil, "which", unavailable)
    verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verification.status_code == 200
    payload = verification.json()
    assert payload["status"] == "RELEASE_BLOCKED"
    assert payload["inconclusive"] >= 1
    assert client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").status_code == 423
