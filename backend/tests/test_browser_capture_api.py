from __future__ import annotations

import io
import json
from datetime import datetime, timezone

from PIL import Image


def _png() -> bytes:
    image = Image.new("RGB", (800, 600), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def _metadata() -> dict:
    return {
        "schema": "veilgraph.browser-local-capture.v1",
        "captured_at": datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc).isoformat(),
        "tab_id": 1,
        "task": "Open the account settings",
        "audience_profile": "PUBLIC_RELEASE",
        "requested_privacy_level": 4,
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
    assert payload["visual_perception_status"] == "UNAVAILABLE"
    assert payload["readiness"] == "VISUAL_COVERAGE_INCOMPLETE"
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
