from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from app.extraction.video import probe_video


QR_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "test_video_visual_qr_demo.mp4"
QR_VIDEO = QR_FIXTURE_PATH.read_bytes()


def _create_job(client) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public video evidence release",
            "recipient": "Citizen information portal",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_video_annotated_export_renders_every_committed_physical_frame(client):
    """Video annotation evidence must not be clipped by representative page_count."""
    info = probe_video(QR_VIDEO, "test_video_visual_qr_demo.mp4")
    assert info.total_frames == 8

    job_id = _create_job(client)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_video_visual_qr_demo.mp4", QR_VIDEO, "video/mp4")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]

    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    analysis = analysed.json()
    assert analysis["page_count"] == 4
    assert analysis["video_total_frames"] == 8

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities")
    assert entities.status_code == 200, entities.text
    qr_mentions = [
        mention
        for item in entities.json()
        if item["entity"]["entity_type"] == "QR_CODE"
        for mention in item["mentions"]
    ]
    committed_frame_indexes = sorted({int(mention["page_index"]) for mention in qr_mentions})
    assert committed_frame_indexes == [0, 3, 6, 7]

    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]

    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["passed"] == 13
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0

    exported = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/annotated-export")
    assert exported.status_code == 200, exported.text

    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("veilgraph-annotation-manifest.json"))
        readme = archive.read("README.txt").decode("utf-8")

        manifest_qr_frames = sorted(
            {
                int(entry["page_index"])
                for entry in manifest["entries"]
                if entry["entity_type"] == "QR_CODE"
            }
        )
        assert manifest_qr_frames == committed_frame_indexes

        expected_previews = {
            f"annotated-previews/unit-{frame_index + 1:04d}.png"
            for frame_index in committed_frame_indexes
        }
        assert expected_previews <= names
        assert len([name for name in names if name.startswith("annotated-previews/")]) == 4
        for name in expected_previews:
            data = archive.read(name)
            assert data[:8] == bytes.fromhex("89504e470d0a1a0a")

        assert "Rendered annotated previews: 4 of 4 modified physical-frame units." in readme
        assert "The JSON manifest always contains every transformation." in readme
