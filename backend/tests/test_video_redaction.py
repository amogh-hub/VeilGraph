from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import cv2
import numpy as np
import pytest

from app.core.enums import EntityType, FileType
from app.extraction.document_processor import process_document
from app.extraction.video import VIDEO_MEDIA_TYPES, evidence_frame, physical_frame, probe_video
from app.ingestion.validator import ValidationError, validate_upload
from app.ir.privacy_ir import build_privacy_ir, privacy_ir_summary
from app.proof.package import verify_proof_package_bytes
from app.transformation.sanitizer import ProtectionInstruction, sanitize_video
from app.verification.red_team import independent_extraction, video_visual_identifier_rescan


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "test_video_privacy_demo.mp4"
TRANSIENT_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "test_video_transient_pii.mp4"
AUDIO_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "test_video_privacy_demo_with_audio.mp4"
QR_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "test_video_visual_qr_demo.mp4"
VIDEO = FIXTURE_PATH.read_bytes()
TRANSIENT_VIDEO = TRANSIENT_FIXTURE_PATH.read_bytes()
AUDIO_VIDEO = AUDIO_FIXTURE_PATH.read_bytes()
QR_VIDEO = QR_FIXTURE_PATH.read_bytes()


def _create_job(client, level: int = 4) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public video evidence release",
            "recipient": "Citizen information portal",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": level,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _protect_pending(client, job_id: str, file_id: str) -> int:
    count = 0
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    for item in entities:
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                response = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert response.status_code == 200, response.text
                count += 1
    return count


def test_video_validator_accepts_mp4_mov_and_rejects_spoof():
    file_type, media_type, digest = validate_upload(VIDEO, "timeline.mp4")
    assert file_type == FileType.VIDEO
    assert media_type == VIDEO_MEDIA_TYPES[".mp4"]
    assert len(digest) == 64
    info = probe_video(VIDEO, "timeline.mp4")
    assert info.width == 960 and info.height == 540
    assert info.total_frames == 30
    assert info.sampled_frames >= 5
    assert info.has_audio is False

    mov_type, mov_media_type, _mov_digest = validate_upload(VIDEO, "timeline.mov")
    assert mov_type == FileType.VIDEO
    assert mov_media_type == VIDEO_MEDIA_TYPES[".mov"]

    with pytest.raises(ValidationError):
        validate_upload(b"not-an-mp4", "spoof.mp4")


def test_video_enters_privacy_ir_as_timestamped_video_frames():
    document = process_document(VIDEO, FileType.VIDEO, "test_video_privacy_demo.mp4")
    ir = build_privacy_ir(document)
    summary = privacy_ir_summary(ir)
    assert ir.source_file_type == FileType.VIDEO
    assert summary["unit_kind_breakdown"]["VIDEO_FRAME"] == document.page_count
    assert summary["video_total_frames"] == 30
    assert 11 <= document.page_count <= 30
    assert summary["video_sampled_frames"] == 11
    assert summary["video_security_detection_frames"] == document.page_count
    assert summary["video_security_frames_analyzed"] == 30
    assert summary["video_security_coverage_percent"] == 100.0
    assert sum(1 for item in summary["video_frame_map"] if item["is_evidence"]) == 11
    assert all(item["security_scanned"] for item in summary["video_frame_map"])
    assert summary["video_audio_policy"] == "STRIP_ALL_AUDIO_ON_PROTECTED_EXPORT"
    assert summary["plaintext_persisted"] is False
    assert all(item["timestamp_seconds"] >= 0 for item in summary["video_frame_map"])
    assert "Dev Malhotra" not in json.dumps(summary, sort_keys=True)


def test_video_level4_end_to_end_passes_13_video_gates_and_proof_package(client):
    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_video_privacy_demo.mp4", VIDEO, "video/mp4")},
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["file_type"] == "VIDEO"
    file_id = uploaded.json()["id"]

    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    analysis = analysed.json()
    assert analysis["file_type"] == "VIDEO"
    assert analysis["video_total_frames"] == 30
    assert 11 <= analysis["page_count"] <= 30
    assert analysis["video_sampled_frames"] == 11
    assert analysis["video_security_frames_analyzed"] == 30
    assert analysis["video_security_detection_frames"] == analysis["page_count"]
    assert analysis["video_security_coverage_percent"] == 100.0
    assert sum(1 for item in analysis["video_units"] if item["is_evidence"]) == 11
    assert all(item["security_scanned"] for item in analysis["video_units"])
    assert analysis["video_has_audio"] is False
    assert analysis["visual_mentions"] == 0
    # Same person across all evidence frames should require one fail-closed
    # human decision, not one repetitive click per timestamp.
    assert analysis["pending_reviews"] == 1
    assert analysis["direct_identifier_mentions"] >= 40
    assert analysis["quasi_identifier_mentions"] >= 10

    preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=0")
    assert preview.status_code == 200
    assert preview.content.startswith(b"\x89PNG")

    assert _protect_pending(client, job_id, file_id) == 1
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    transform = transformed.json()
    assert transform["output_media_type"] == "video/mp4"
    assert transform["download_name"].endswith(".mp4")
    assert transform["transformations_applied"] >= 40

    output_id = transform["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["proof_score"] == 100
    assert proof["attack_coverage"] == 13
    assert proof["passed"] == 13
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0
    names = {item["name"] for item in proof["tests"]}
    assert {"video_frame_ocr_rescan", "video_visual_identifier_rescan", "video_audio_absence", "video_temporal_integrity", "video_structure_preservation"} <= names

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("video/mp4")
    protected = downloaded.content
    assert hashlib.sha256(protected).hexdigest() != hashlib.sha256(VIDEO).hexdigest()
    protected_info = probe_video(protected, "protected.mp4")
    assert protected_info.has_audio is False
    assert protected_info.total_frames == 30

    package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert package.status_code == 200, package.text
    package_result = verify_proof_package_bytes(package.content)
    assert package_result["valid"] is True, package_result

    annotated = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/annotated-export")
    assert annotated.status_code == 200, annotated.text
    with zipfile.ZipFile(io.BytesIO(annotated.content)) as archive:
        manifest = json.loads(archive.read("veilgraph-annotation-manifest.json"))
        assert manifest["source_plaintext_included"] is False
        assert manifest["protected_output_sha256"] == hashlib.sha256(protected).hexdigest()
        assert any(name.startswith("annotated-previews/") for name in archive.namelist())


def test_video_temporal_sanitizer_changes_intermediate_frames_and_strips_audio():
    # Anchor the same synthetic region at the first and last evidence frame.
    # The middle physical frame must also change, proving interpolation is not
    # limited to sampled screenshots.
    info = probe_video(VIDEO, "test_video_privacy_demo.mp4")
    rect = (140.0, 140.0, 500.0, 320.0)
    instructions = [
        ProtectionInstruction(
            entity_id="entity-1",
            mention_id="mention-1",
            entity_type=EntityType.EMAIL,
            page_index=0,
            rect=rect,
            replacement="Email alias A",
        ),
        ProtectionInstruction(
            entity_id="entity-1",
            mention_id="mention-2",
            entity_type=EntityType.EMAIL,
            page_index=info.total_frames - 1,
            rect=rect,
            replacement="Email alias A",
        ),
    ]
    protected, media_type, name, report = sanitize_video(
        VIDEO, instructions, "test_video_privacy_demo.mp4"
    )
    assert media_type == "video/mp4"
    assert name == "protected.mp4"
    assert report["audio_stripped"] is True
    after_info = probe_video(protected, "protected.mp4")
    assert after_info.has_audio is False
    assert after_info.total_frames == info.total_frames
    assert (after_info.width, after_info.height) == (info.width, info.height)

    # Compare a middle physical frame directly with OpenCV.
    def frame_at(blob: bytes, frame_index: int) -> np.ndarray:
        import os, tempfile
        path = None
        cap = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as handle:
                handle.write(blob)
                path = handle.name
            cap = cv2.VideoCapture(path)
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
            ok, frame = cap.read()
            assert ok and frame is not None
            return frame
        finally:
            if cap is not None:
                cap.release()
            if path:
                os.unlink(path)

    middle = info.total_frames // 2
    before = frame_at(VIDEO, middle)
    after = frame_at(protected, middle)
    x0, y0, x1, y1 = (int(value) for value in rect)
    delta = np.abs(before[y0:y1, x0:x1].astype(np.int16) - after[y0:y1, x0:x1].astype(np.int16))
    assert float(delta.mean()) > 10.0


def test_video_transient_identifier_on_unsampled_frame_is_detected_transformed_and_full_frame_verified(client):
    info = probe_video(TRANSIENT_VIDEO, "test_video_transient_pii.mp4")
    assert 4 not in info.sampled_frame_indices, "fixture must place PII between representative evidence samples"

    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_video_transient_pii.mp4", TRANSIENT_VIDEO, "video/mp4")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    analysis = analysed.json()
    assert analysis["video_security_frames_analyzed"] == info.total_frames == 12
    assert analysis["video_security_coverage_percent"] == 100.0
    assert analysis["video_sampled_frames"] < analysis["video_total_frames"]
    assert analysis["video_sampled_frames"] == 5
    assert analysis["video_security_detection_frames"] == 6
    assert analysis["video_novel_security_frames"] == 1
    promoted = [item for item in analysis["video_units"] if item["security_promoted"]]
    assert len(promoted) == 1
    assert promoted[0]["frame_index"] == 4
    assert promoted[0]["page_index"] == 4
    assert promoted[0]["label"] == "00:00.7"
    assert promoted[0]["full_ocr_selected"] is True
    assert promoted[0]["is_evidence"] is False

    # The promoted security frame must be judge-inspectable through the normal
    # preview endpoint even though it is not a representative evidence sample.
    promoted_preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=4")
    assert promoted_preview.status_code == 200, promoted_preview.text
    assert promoted_preview.content.startswith(b"\x89PNG")

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    emails = [item for item in entities if item["entity"]["entity_type"] == "EMAIL"]
    assert len(emails) == 1
    assert any(mention["page_index"] == 4 for mention in emails[0]["mentions"])

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
    assert proof["passed"] == 13 and proof["failed"] == 0 and proof["inconclusive"] == 0
    full_frame_gate = next(item for item in proof["tests"] if item["name"] == "video_frame_ocr_rescan")
    assert "Full OCR across" in full_frame_gate["detail"]
    assert "security-selected protected frame(s)" in full_frame_gate["detail"]
    assert "complete-timeline change screening" in full_frame_gate["detail"]

    protected = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").content
    frame4, _info, _idx = physical_frame(protected, 4, "protected.mp4")
    import pytesseract
    text = pytesseract.image_to_string(frame4, lang="eng", config="--psm 6").casefold()
    assert "transient.secret@example.org" not in text


def test_video_promoted_security_frame_is_exposed_for_judge_preview(client):
    """A novel between-sample frame must be visible, not only internally detected."""
    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_video_transient_pii.mp4", TRANSIENT_VIDEO, "video/mp4")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]

    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    analysis = analysed.json()
    assert analysis["video_sampled_frames"] == 5
    assert analysis["video_novel_security_frames"] == 1
    assert analysis["video_security_detection_frames"] == 6

    promoted = [unit for unit in analysis["video_units"] if unit["security_promoted"]]
    assert len(promoted) == 1
    unit = promoted[0]
    assert unit["page_index"] == 4
    assert unit["frame_index"] == 4
    assert unit["timestamp_seconds"] == pytest.approx(4 / 6, abs=0.001)
    assert unit["label"] == "00:00.7"
    assert unit["is_evidence"] is False
    assert unit["security_scanned"] is True
    assert unit["full_ocr_selected"] is True
    assert unit["security_promoted"] is True

    preview = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/preview?page=4")
    assert preview.status_code == 200, preview.text
    assert preview.content.startswith(b"\x89PNG")

    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    email_mentions = [
        mention
        for item in entities
        if item["entity"]["entity_type"] == "EMAIL"
        for mention in item["mentions"]
    ]
    assert len(email_mentions) == 1
    assert email_mentions[0]["page_index"] == 4


def test_video_independent_extraction_scans_all_physical_frames_not_only_evidence_samples():
    result = independent_extraction(
        TRANSIENT_VIDEO,
        FileType.VIDEO,
        [(EntityType.EMAIL, "transient.secret@example.org")],
    )
    assert result.status.value == "FAIL"
    assert "full-timeline" in result.detail.casefold()


def test_video_audio_present_fixture_is_detected_and_protected_export_strips_audio():
    info = probe_video(AUDIO_VIDEO, "test_video_privacy_demo_with_audio.mp4")
    assert info.has_audio is True
    instructions = [ProtectionInstruction(
        entity_id="audio-test-entity", mention_id="audio-test-mention",
        entity_type=EntityType.PERSON_NAME, page_index=0,
        rect=(170.0, 135.0, 350.0, 180.0), replacement="Person A",
    )]
    protected, media_type, _name, report = sanitize_video(
        AUDIO_VIDEO, instructions, "test_video_privacy_demo_with_audio.mp4"
    )
    assert media_type == "video/mp4"
    assert report["audio_present_in_source"] is True
    assert report["audio_stripped"] is True
    assert probe_video(protected, "protected.mp4").has_audio is False


def test_video_decoded_qr_is_a_real_non_text_visual_region():
    document = process_document(QR_VIDEO, FileType.VIDEO, "test_video_visual_qr_demo.mp4")
    from app.detection.pipeline import detect_all
    detections = detect_all(document)
    qr = [item for item in detections if item.entity_type == EntityType.QR_CODE]
    assert len(qr) == document.page_count
    assert all(item.plaintext == "VG-PRIVATE-QR-2026" for item in qr)
    assert all(item.source.value == "VISUAL" for item in qr)


def test_video_independent_qr_decoder_attack_fails_source_and_passes_protected_release(client):
    source_attack = video_visual_identifier_rescan(QR_VIDEO)
    assert source_attack.status.value == "FAIL"
    assert "VG-PRIVATE-QR-2026" in source_attack.detail

    job_id = _create_job(client, 4)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("test_video_visual_qr_demo.mp4", QR_VIDEO, "video/mp4")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    assert analysed.json()["visual_mentions"] > 0

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
    assert proof["attack_coverage"] == 13
    assert proof["passed"] == 13 and proof["failed"] == 0 and proof["inconclusive"] == 0
    visual_gate = next(item for item in proof["tests"] if item["name"] == "video_visual_identifier_rescan")
    assert visual_gate["status"] == "PASS"
    assert "physical frames" in visual_gate["detail"]
    assert "no qr payload" in visual_gate["detail"].casefold()

    protected = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download").content
    direct_attack = video_visual_identifier_rescan(protected)
    assert direct_attack.status.value == "PASS"
