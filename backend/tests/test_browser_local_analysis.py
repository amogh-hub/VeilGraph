from __future__ import annotations

import io
from datetime import datetime, timezone

from PIL import Image

from app.browser.local_analysis import analyse_browser_capture
from app.browser.models import BrowserLocalCaptureMetadata, BrowserLocalElement, BrowserLocalFrame


def _screenshot() -> bytes:
    image = Image.new("RGB", (1200, 800), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def _metadata(*, visual_status: str = "READY") -> BrowserLocalCaptureMetadata:
    return BrowserLocalCaptureMetadata(
        captured_at=datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc),
        tab_id=7,
        task="Book the follow-up appointment",
        audience_profile="PUBLIC_RELEASE",
        requested_privacy_level=4,
        visual_perception_status=visual_status,
        frames=[
            BrowserLocalFrame(
                frame_id=0,
                is_top_frame=True,
                origin="https://health.example",
                href="https://health.example/patient?record=local-only",
                title="Patient profile",
                viewport_width=1200,
                viewport_height=800,
                elements=[
                    BrowserLocalElement(
                        local_id="vg_name_0001",
                        tag="input",
                        role="textbox",
                        accessible_name="Patient name",
                        raw_value="Priya Sharma",
                        bbox=(800, 1000, 4200, 1600),
                        privacy_hints=["person_name", "health"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_email_0002",
                        tag="input",
                        role="textbox",
                        accessible_name="Email",
                        input_type="email",
                        raw_value="priya.sharma@example.com",
                        bbox=(800, 1800, 4200, 2400),
                        privacy_hints=["email"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_job_0003",
                        tag="div",
                        role="text",
                        accessible_name="Profession",
                        visible_text="Cardiologist",
                        bbox=(800, 2600, 4200, 3200),
                        privacy_hints=["quasi_identifier"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_loc_0004",
                        tag="div",
                        role="text",
                        accessible_name="Location",
                        visible_text="Bengaluru",
                        bbox=(800, 3400, 4200, 4000),
                        privacy_hints=["location"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_age_0005",
                        tag="div",
                        role="text",
                        accessible_name="Age",
                        visible_text="31",
                        bbox=(800, 4200, 4200, 4800),
                        privacy_hints=["quasi_identifier"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_password_0006",
                        tag="input",
                        role="textbox",
                        accessible_name="Password",
                        input_type="password",
                        raw_value="NeverTransmitThis",
                        bbox=(800, 5000, 4200, 5600),
                        privacy_hints=["credential"],
                    ),
                    BrowserLocalElement(
                        local_id="vg_button_0007",
                        tag="button",
                        role="button",
                        accessible_name="Book follow-up",
                        visible_text="Book follow-up",
                        bbox=(6500, 7600, 9000, 8400),
                    ),
                ],
            )
        ],
    )


def test_browser_local_analysis_reuses_identity_exposure_engine_without_external_release():
    result = analyse_browser_capture(_metadata(), _screenshot())

    assert result.semantic_elements == 7
    assert result.credential_fields == 1
    assert result.risk_before >= result.residual_risk_preview
    assert result.identity_exposure_graph["graph_version"] == "ieg-0.3"
    types = {item.entity_type for item in result.detections}
    assert "EMAIL" in types
    assert result.readiness in {"READY_FOR_SANITIZATION", "NEEDS_REVIEW"}
    assert "does not authorize external transmission" in result.note


def test_browser_native_visual_gap_is_completed_only_by_local_companion_coverage():
    result = analyse_browser_capture(_metadata(visual_status="UNAVAILABLE"), _screenshot())
    assert result.browser_visual_perception_status == "UNAVAILABLE"
    assert result.local_companion_visual_status == "READY"
    assert result.visual_perception_status == "READY"
    assert result.readiness in {"READY_FOR_SANITIZATION", "NEEDS_REVIEW"}


def test_visual_coverage_remains_fail_closed_if_browser_and_companion_are_unavailable(monkeypatch):
    import app.browser.local_analysis as module

    monkeypatch.setattr(module, "_companion_visual_capabilities", lambda _document: ("UNAVAILABLE", []))
    result = analyse_browser_capture(_metadata(visual_status="UNAVAILABLE"), _screenshot())
    assert result.visual_perception_status == "UNAVAILABLE"
    assert result.readiness == "VISUAL_COVERAGE_INCOMPLETE"
