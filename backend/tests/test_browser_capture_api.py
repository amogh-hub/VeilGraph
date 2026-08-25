from __future__ import annotations

import io
import json
from datetime import datetime, timezone

from PIL import Image
import pytest

from app.browser.models import BrowserLocalCaptureMetadata


def _png() -> bytes:
    image = Image.new("RGB", (800, 600), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def _metadata() -> dict:
    return {
        "schema": "veilgraph.browser-local-capture.v1",
        "capture_id": "VGC-00112233445566778899AABB",
        "captured_at": datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc).isoformat(),
        "tab_id": 1,
        "task": "Open the account settings",
        "audience_profile": "PUBLIC_RELEASE",
        "requested_privacy_level": 4,
        "expected_frame_count": 1,
        "captured_frame_count": 1,
        "failed_frame_ids": [],
        "capture_timings": {
            "frame_dom_ms": 4,
            "screenshot_capture_ms": 7,
            "visual_perception_ms": 12,
            "total_local_ms": 25,
        },
        "coverage": [
            {"name": "DOM", "status": "READY", "required": True, "detail": "1/1 frame DOM captures"},
            {"name": "ACCESSIBILITY", "status": "READY", "required": True, "detail": "role/name semantics captured"},
            {"name": "VISUAL", "status": "UNAVAILABLE", "required": True, "detail": "browser-native visual fallback unavailable"},
        ],
        "visual_perception_status": "UNAVAILABLE",
        "visual_findings": [],
        "frames": [
            {
                "frame_id": 0,
                "is_top_frame": True,
                "origin": "https://example.test",
                "href": "https://example.test/settings?email=local@example.test",
                "title": "Settings",
                "viewport_width": 800,
                "viewport_height": 600,
                "device_pixel_ratio_basis_points": 20000,
                "scroll_x": 0,
                "scroll_y": 200,
                "document_width": 800,
                "document_height": 1800,
                "eligible_element_count": 2,
                "captured_element_count": 2,
                "capture_truncated": False,
                "shadow_root_count": 0,
                "capture_elapsed_ms": 3,
                "inaccessible_descendant_frames": 0,
                "elements": [
                    {
                        "local_id": "vg_email_field_001",
                        "tag": "input",
                        "role": "textbox",
                        "accessible_name": "Email",
                        "visible_text": "",
                        "input_type": "email",
                        "raw_value": "local@example.test",
                        "disabled": False,
                        "bbox": [1000, 1000, 6000, 1800],
                        "privacy_hints": ["email"],
                    },
                    {
                        "local_id": "vg_settings_button_002",
                        "tag": "button",
                        "role": "button",
                        "accessible_name": "Account settings",
                        "visible_text": "Account settings",
                        "disabled": False,
                        "bbox": [1000, 2500, 4000, 3300],
                        "privacy_hints": [],
                    },
                ],
            }
        ],
    }


def test_browser_capture_api_is_local_analysis_only(client):
    response = client.post(
        "/api/v1/browser/analyse-capture",
        data={"metadata": json.dumps(_metadata())},
        files={"screenshot": ("capture.png", _png(), "image/png")},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema"] == "veilgraph.browser-local-analysis.v1"
    assert payload["browser_visual_perception_status"] == "UNAVAILABLE"
    assert payload["local_companion_visual_status"] == "READY"
    assert payload["visual_perception_status"] == "READY"
    assert payload["readiness"] in {"READY_FOR_SANITIZATION", "NEEDS_REVIEW"}
    assert payload["ocr_lines"] >= 0
    assert payload["capture_id"] == "VGC-00112233445566778899AABB"
    assert payload["expected_frames"] == 1
    assert payload["captured_frames"] == 1
    assert payload["failed_frames"] == 0
    assert payload["capture_timings"]["total_local_ms"] == 25
    assert any(item["name"] == "DOM" and item["status"] == "READY" for item in payload["browser_capture_coverage"])
    assert any(item["backend"] == "local-companion-tesseract" for item in payload["visual_capabilities"])
    assert any(item["entity_type"] == "EMAIL" for item in payload["detections"])
    assert "does not authorize external transmission" in payload["note"]
    assert "local@example.test" not in response.text


def test_browser_capture_api_rejects_non_image_screenshot(client):
    response = client.post(
        "/api/v1/browser/analyse-capture",
        data={"metadata": json.dumps(_metadata())},
        files={"screenshot": ("capture.txt", b"not-an-image", "text/plain")},
    )
    assert response.status_code == 415


def test_browser_capture_metadata_rejects_impossible_frame_accounting():
    raw = _metadata()
    raw["failed_frame_ids"] = [7]
    with pytest.raises(ValueError, match="accounting exceeds"):
        BrowserLocalCaptureMetadata.model_validate(raw)


def test_browser_capture_metadata_accepts_packaged_learned_model_evidence():
    raw = _metadata()
    raw["visual_perception_status"] = "READY"
    raw["visual_perception_report"] = {
        "status": "READY",
        "model_id": "veilgraph-hybrid-local-perception-v3",
        "backend": "hybrid-local",
        "elapsed_ms": 17,
        "image_width": 800,
        "image_height": 600,
        "finding_count": 1,
        "stage_timings_ms": {
            "screenshot_decode_ms": 1,
            "dom_projection_ms": 1,
            "learned_face_ms": 9,
            "face_detection_ms": 0,
            "qr_detection_ms": 2,
            "text_region_ms": 2,
            "fusion_ms": 2,
        },
        "fusion_summary": {
            "total_findings": 1,
            "corroborated_findings": 1,
            "single_source_findings": 0,
            "learned_native_face_agreements": 1,
        },
        "learned_model": {
            "model_id": "ultraface-rfb-320",
            "model_sha256": "34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017",
            "runtime": "onnxruntime-web@1.27.0",
            "execution_provider": "wasm",
            "model_load_ms": 4,
            "inference_ms": 5,
            "input_width": 320,
            "input_height": 240,
            "detection_count": 1,
            "fallback_used": True,
            "fallback_reason": "WebGPU unavailable in test context",
        },
        "capabilities": [
            {
                "name": "LEARNED_FACE_DETECTION",
                "status": "READY",
                "backend": "onnxruntime-web@1.27.0:wasm",
                "required": True,
                "detail": "Packaged model executed locally",
            }
        ],
    }
    parsed = BrowserLocalCaptureMetadata.model_validate(raw)
    assert parsed.visual_perception_report is not None
    assert parsed.visual_perception_report.learned_model is not None
    assert parsed.visual_perception_report.learned_model.model_id == "ultraface-rfb-320"
    assert parsed.visual_perception_report.stage_timings_ms.learned_face_ms == 9


def test_browser_visual_finding_accepts_corroborated_provider_evidence():
    from app.browser.models import BrowserLocalVisualFinding

    finding = BrowserLocalVisualFinding.model_validate({
        "finding_id": "face-fused-1",
        "type": "FACE",
        "confidence_basis_points": 9800,
        "bbox": [1000, 1000, 3000, 3500],
        "provider": "onnx:ultraface-rfb-320",
        "modalities": ["VISUAL"],
        "supporting_providers": ["onnx:ultraface-rfb-320", "shape-detection-api"],
        "support_count": 2,
        "consensus": "CORROBORATED",
    })
    assert finding.support_count == 2
    assert finding.consensus == "CORROBORATED"


def test_browser_visual_finding_rejects_false_corroboration():
    from app.browser.models import BrowserLocalVisualFinding

    with pytest.raises(ValueError, match="CORROBORATED"):
        BrowserLocalVisualFinding.model_validate({
            "finding_id": "face-invalid",
            "type": "FACE",
            "confidence_basis_points": 9000,
            "bbox": [1000, 1000, 3000, 3500],
            "supporting_providers": ["onnx:ultraface-rfb-320"],
            "support_count": 1,
            "consensus": "CORROBORATED",
        })


def test_browser_visual_fusion_summary_rejects_impossible_agreement_count():
    from app.browser.models import BrowserVisualFusionSummary

    with pytest.raises(ValueError, match="cannot exceed corroborated"):
        BrowserVisualFusionSummary.model_validate({
            "total_findings": 2,
            "corroborated_findings": 0,
            "single_source_findings": 2,
            "learned_native_face_agreements": 1,
        })


def test_browser_workflow_heading_false_positive_is_scoped_to_browser_adapter():
    from app.browser import local_analysis
    from app.core.enums import (
        DetectionSource,
        EntityType,
        FileType,
        ReviewStatus,
        SensitivityLevel,
        TransformationType,
    )
    from app.detection.models import DetectedMention
    from app.extraction.document_processor import (
        PageFrame,
        ProcessedDocument,
    )

    raw = _metadata()

    raw["frames"][0]["eligible_element_count"] = 2
    raw["frames"][0]["captured_element_count"] = 2

    raw["frames"][0]["elements"] = [
        {
            "local_id": "vg_demo_followup_heading",
            "tag": "h1",
            "role": "heading",
            "accessible_name": "Patient Follow-Up",
            "visible_text": "Patient Follow-Up",
            "disabled": False,
            "bbox": [1000, 1000, 6000, 1800],
            "privacy_hints": [],
        },
        {
            "local_id": "vg_real_patient_heading",
            "tag": "h2",
            "role": "heading",
            "accessible_name": "Patient Alice Brown",
            "visible_text": "Patient Alice Brown",
            "disabled": False,
            "bbox": [1000, 2500, 6000, 3300],
            "privacy_hints": [],
        },
    ]

    metadata = BrowserLocalCaptureMetadata.model_validate(raw)

    page = PageFrame(
        page_index=0,
        width=800.0,
        height=600.0,
        image=Image.new(
            "RGB",
            (800, 600),
            "white",
        ),
        lines=(),
        used_ocr=True,
    )

    document = ProcessedDocument(
        file_type=FileType.IMAGE,
        pages=(page,),
        page_count=1,
        scanned_pages=1,
    )

    def mention(
        value,
        rect,
        source,
    ):
        return DetectedMention(
            entity_type=EntityType.PERSON_NAME,
            plaintext=value,
            page_index=0,
            page_char_start=0,
            page_char_end=len(value),
            rect=rect,
            confidence=0.9,
            source=source,
            sensitivity=SensitivityLevel.HIGH,
            transformation=TransformationType.PSEUDONYMIZE,
            review_status=ReviewStatus.NOT_REQUIRED,
        )

    follow_rect = local_analysis._pixel_bbox(
        (1000, 1000, 6000, 1800),
        800,
        600,
    )

    name_rect = local_analysis._pixel_bbox(
        (1000, 2500, 6000, 3300),
        800,
        600,
    )

    false_dom = mention(
        "Follow-Up",
        follow_rect,
        DetectionSource.TEXT_LAYER,
    )

    false_ocr = mention(
        "Follow",
        follow_rect,
        DetectionSource.OCR,
    )

    real_name = mention(
        "Alice Brown",
        name_rect,
        DetectionSource.TEXT_LAYER,
    )

    filtered = (
        local_analysis._filter_browser_label_false_positives(
            [
                false_dom,
                false_ocr,
                real_name,
            ],
            metadata,
            document,
        )
    )

    assert false_dom not in filtered
    assert false_ocr not in filtered

    # Browser precision hardening must never suppress a genuine person name.
    assert real_name in filtered
