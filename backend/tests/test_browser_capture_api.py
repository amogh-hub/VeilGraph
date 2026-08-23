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
