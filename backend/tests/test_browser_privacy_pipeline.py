from __future__ import annotations

import base64
import hashlib
import io
import json
from datetime import datetime, timezone

import pytest
from PIL import Image

from app.browser.models import BrowserLocalCaptureMetadata
from app.browser.privacy_pipeline import BrowserPreparationError, prepare_browser_release
from app.browser.release_gate import verify_network_authorization


def _png() -> bytes:
    image = Image.new("RGB", (800, 600), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def _metadata(*, requested_privacy_level: int = 1, visual_status: str = "UNAVAILABLE") -> dict:
    return {
        "schema": "veilgraph.browser-local-capture.v1",
        "captured_at": datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc).isoformat(),
        "tab_id": 1,
        "task": "Open the account settings for local@example.test",
        "audience_profile": "PUBLIC_RELEASE",
        "requested_privacy_level": requested_privacy_level,
        "visual_perception_status": visual_status,
        "visual_findings": [],
        "frames": [
            {
                "frame_id": 0,
                "is_top_frame": True,
                "origin": "https://example.test",
                "href": "https://example.test/settings?email=local@example.test#private",
                "title": "Settings for local@example.test",
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
                        "local_id": "vg_password_field_002",
                        "tag": "input",
                        "role": "textbox",
                        "accessible_name": "Password",
                        "visible_text": "",
                        "input_type": "password",
                        "raw_value": "NeverTransmitThisSecret",
                        "disabled": False,
                        "bbox": [1000, 1900, 6000, 2600],
                        "privacy_hints": ["credential"],
                    },
                    {
                        "local_id": "vg_settings_button_003",
                        "tag": "button",
                        "role": "button",
                        "accessible_name": "Account settings",
                        "visible_text": "Account settings",
                        "disabled": False,
                        "bbox": [1000, 3000, 4000, 3800],
                        "privacy_hints": [],
                    },
                ],
            }
        ],
    }


def _parsed(**kwargs) -> BrowserLocalCaptureMetadata:
    return BrowserLocalCaptureMetadata.model_validate(_metadata(**kwargs))


def test_prepare_release_builds_sanitized_payload_runs_all_gates_and_authorizes_exact_payload():
    result = prepare_browser_release(_parsed(requested_privacy_level=1), _png())

    assert result.schema_id == "veilgraph.browser-release-preparation.v1"
    assert result.payload.privacy_level == 4
    assert result.payload.network_privacy_floor == 4
    assert result.verification.proof_score == 100
    assert result.verification.critical_failures == 0
    assert len(result.verification.tests) == 12
    assert all(test.status.value == "PASS" for test in result.verification.tests)
    assert result.authorization.payload.decision == "ALLOW_NETWORK_RELEASE"
    assert result.authorization.payload.mandatory_gates == 12
    assert result.authorization.payload.mandatory_passed == 12
    assert verify_network_authorization(result.authorization, result.payload)

    serialized = result.model_dump_json()
    assert "local@example.test" not in serialized
    assert "NeverTransmitThisSecret" not in serialized
    assert "settings?email" not in serialized
    assert result.payload.page.origin == "https://example.test"
    assert result.payload.task != _metadata()["task"]
    assert "@" not in result.payload.task
    assert result.payload.page.visual_context is not None
    visual = result.payload.page.visual_context
    decoded = base64.b64decode(visual.image_base64, validate=True)
    assert hashlib.sha256(decoded).hexdigest() == visual.sanitized_sha256
    assert visual.redacted_regions >= 1


def test_prepare_release_endpoint_never_returns_raw_email_or_credential(client):
    response = client.post(
        "/api/v1/browser/prepare-release",
        data={"metadata": json.dumps(_metadata())},
        files={"screenshot": ("capture.png", _png(), "image/png")},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["authorization"]["payload"]["decision"] == "ALLOW_NETWORK_RELEASE"
    assert body["verification"]["proof_score"] == 100
    assert body["payload"]["privacy_level"] == 4
    assert body["payload"]["network_privacy_floor"] == 4
    assert "local@example.test" not in response.text
    assert "NeverTransmitThisSecret" not in response.text
    assert "settings?email" not in response.text


def test_network_privacy_floor_cannot_be_downgraded_by_l1_request():
    result = prepare_browser_release(_parsed(requested_privacy_level=1), _png())
    assert result.payload.privacy_level == 4
    assert result.payload.network_privacy_floor == 4
    assert result.verification.policy_floor_satisfied is True


def test_l5_synthetic_twin_is_rejected_for_live_browser_release():
    with pytest.raises(BrowserPreparationError, match="structured datasets"):
        prepare_browser_release(_parsed(requested_privacy_level=5), _png())


def test_incomplete_browser_and_companion_visual_coverage_is_inconclusive_and_denied(monkeypatch):
    import app.browser.local_analysis as local_analysis

    monkeypatch.setattr(local_analysis, "_companion_visual_capabilities", lambda _document: ("UNAVAILABLE", []))
    result = prepare_browser_release(_parsed(visual_status="UNAVAILABLE"), _png())

    visual_gate = next(test for test in result.verification.tests if test.name == "visual_sensitive_rescan")
    assert visual_gate.status.value == "INCONCLUSIVE"
    assert result.verification.proof_score < 100
    assert result.verification.critical_failures >= 1
    assert result.authorization.payload.decision == "DENY_NETWORK_RELEASE"
    assert not verify_network_authorization(result.authorization, result.payload)


def test_signed_authorization_fails_after_payload_tampering():
    result = prepare_browser_release(_parsed(), _png())
    assert result.authorization.payload.decision == "ALLOW_NETWORK_RELEASE"
    assert verify_network_authorization(result.authorization, result.payload)

    tampered = result.payload.model_copy(update={"task": "Open billing settings"})
    assert not verify_network_authorization(result.authorization, tampered)


def test_capture_metadata_rejects_ambiguous_top_frame_geometry():
    raw = _metadata()
    top = raw["frames"][0]
    child = dict(top)
    child["frame_id"] = 2
    child["is_top_frame"] = False
    raw["frames"] = [child, top]
    with pytest.raises(ValueError, match="top frame must be first"):
        BrowserLocalCaptureMetadata.model_validate(raw)


def test_sanitized_visual_flattens_sensitive_dom_region_into_new_raster():
    result = prepare_browser_release(_parsed(), _png())
    visual = result.payload.page.visual_context
    assert visual is not None
    sanitized = Image.open(io.BytesIO(base64.b64decode(visual.image_base64))).convert("RGB")

    # Email field bbox [1000,1000,6000,1800] maps to x=80..480, y=60..108.
    # The sanitizer adds padding and paints an opaque region before creating a
    # completely new flattened raster; a center pixel must therefore no longer
    # match the original white screenshot.
    r, g, b = sanitized.getpixel((280, 84))
    assert max(r, g, b) < 40


def test_prepare_release_endpoint_rejects_l5_for_live_browser(client):
    response = client.post(
        "/api/v1/browser/prepare-release",
        data={"metadata": json.dumps(_metadata(requested_privacy_level=5))},
        files={"screenshot": ("capture.png", _png(), "image/png")},
    )
    assert response.status_code == 422
    assert "structured datasets" in response.text
