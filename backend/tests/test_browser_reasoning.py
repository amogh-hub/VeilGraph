from __future__ import annotations

import json

import pytest

from app.browser import reasoning
from app.browser.models import (
    BrowserGateResult,
    BrowserPublicElement,
    BrowserPublicPage,
    BrowserPublicVisualContext,
    BrowserReasoningRequest,
    BrowserReleasePayload,
    BrowserVerificationSummary,
)
from app.browser.release_gate import authorize_network_release
from app.core.config import settings
from app.core.enums import TestStatus


MANDATORY_GATES = (
    "direct_identifier_rescan",
    "visual_sensitive_rescan",
    "dom_attribute_leakage",
    "accessibility_leakage",
    "url_referrer_leakage",
    "serialized_state_leakage",
    "policy_coverage",
    "relationship_reconstruction",
    "identifier_fragment_attack",
    "task_minimization",
    "payload_commitment_integrity",
    "task_utility_anchor_preservation",
)


def _payload(*, task: str = "Open account settings", label: str = "Account settings", role: str = "button") -> BrowserReleasePayload:
    return BrowserReleasePayload(
        session_id="session_0123456789abcdef",
        task_id="task_0123456789abcdef",
        task=task,
        page=BrowserPublicPage(
            origin="https://example.test",
            title="Account",
            elements=[
                BrowserPublicElement(
                    element_id="vg_settings_button",
                    role=role,
                    label=label,
                    text=label if role != "textbox" else "",
                    disabled=False,
                    bbox=(1000, 1000, 3000, 1800),
                )
            ],
        ),
        privacy_level=4,
        network_privacy_floor=4,
        identity_exposure_before=86,
        residual_identity_exposure=8,
        task_utility_score=94,
        minimization_basis_points=8600,
    )


def _summary(*, proof_score: int = 100) -> BrowserVerificationSummary:
    tests = [
        BrowserGateResult(
            name=name,
            status=TestStatus.PASS,
            detail=f"{name} passed",
            attack_class="browser_network_release",
            severity="critical" if name != "task_utility_anchor_preservation" else "high",
        )
        for name in MANDATORY_GATES
    ]
    return BrowserVerificationSummary(
        tests=tests,
        proof_score=proof_score,
        critical_failures=0,
        policy_floor_satisfied=True,
        forbidden_raw_fields_present=False,
        payload_commitment_valid=True,
        critical_exposure_present=False,
    )


@pytest.fixture(autouse=True)
def isolated_reasoning(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "signing_key_path", tmp_path / "device-ed25519.key")
    monkeypatch.setattr(settings, "reasoning_enabled", True)
    monkeypatch.setattr(settings, "reasoning_ollama_model", "contract-test-vlm")
    monkeypatch.setattr(settings, "reasoning_ollama_base_url", "http://127.0.0.1:11434")
    monkeypatch.setattr(settings, "reasoning_timeout_seconds", 5.0)
    monkeypatch.setattr(settings, "reasoning_max_actions", 8)
    monkeypatch.setattr(settings, "reasoning_trusted_signer_sha256", None)
    reasoning.reset_reasoning_replay_cache_for_tests()
    yield
    reasoning.reset_reasoning_replay_cache_for_tests()


def _request(monkeypatch, *, payload: BrowserReleasePayload | None = None, proof_score: int = 100) -> BrowserReasoningRequest:
    payload = payload or _payload()
    authorization = authorize_network_release(payload, _summary(proof_score=proof_score))
    monkeypatch.setattr(settings, "reasoning_trusted_signer_sha256", authorization.payload.signer.public_key_sha256)
    return BrowserReasoningRequest(payload=payload, authorization=authorization)


def _plan_json(payload: BrowserReleasePayload, *, target: str = "vg_settings_button", value: str | None = None, confirmation: bool = False) -> str:
    action = {
        "action": "CLICK" if value is None else "TYPE",
        "target_id": target,
        "confidence_basis_points": 9500,
        "reason": "Use the task-relevant released control",
        "requires_confirmation": confirmation,
    }
    if value is not None:
        action["value"] = value
    return json.dumps({
        "schema": "veilgraph.browser-action-plan.v1",
        "session_id": payload.session_id,
        "task_id": payload.task_id,
        "actions": [action],
        "complete": False,
        "summary": "Next safe action",
    })


def test_reasoning_endpoint_accepts_signed_sanitized_release_and_returns_typed_plan(client, monkeypatch):
    request = _request(monkeypatch)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda payload: _plan_json(payload))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema"] == "veilgraph.browser-reasoning-response.v1"
    assert body["plan"]["schema"] == "veilgraph.browser-action-plan.v1"
    assert body["plan"]["actions"][0]["target_id"] == "vg_settings_button"
    assert body["evidence"]["authorization_verified"] is True
    assert body["evidence"]["signer_trusted"] is True
    assert body["evidence"]["replay_protected"] is True


def test_reasoning_rejects_denied_or_nonperfect_authorization(client, monkeypatch):
    request = _request(monkeypatch, proof_score=99)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda payload: _plan_json(payload))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 403


def test_reasoning_rejects_untrusted_signer(client, monkeypatch):
    request = _request(monkeypatch)
    monkeypatch.setattr(settings, "reasoning_trusted_signer_sha256", "0" * 64)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda payload: _plan_json(payload))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 403
    assert "not trusted" in response.text


def test_reasoning_authorization_is_single_use(client, monkeypatch):
    request = _request(monkeypatch)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda payload: _plan_json(payload))
    body = request.model_dump(mode="json", by_alias=True)
    first = client.post("/api/v1/browser/reason", json=body)
    second = client.post("/api/v1/browser/reason", json=body)
    assert first.status_code == 200
    assert second.status_code == 409


def test_reasoning_rejects_hallucinated_target_id(client, monkeypatch):
    request = _request(monkeypatch)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda payload: _plan_json(payload, target="vg_hallucinated_target"))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 502
    assert "invented unavailable target_id" in response.text


def test_reasoning_rejects_model_generated_direct_identifier_value(client, monkeypatch):
    payload = _payload(role="textbox", label="Search")
    request = _request(monkeypatch, payload=payload)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda candidate: _plan_json(candidate, value="person@example.test"))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 502
    assert "direct-identifier-like" in response.text


def test_high_impact_plan_is_forced_to_require_confirmation(client, monkeypatch):
    payload = _payload(task="Confirm booking", label="Confirm booking")
    request = _request(monkeypatch, payload=payload)
    monkeypatch.setattr(reasoning, "_call_ollama", lambda candidate: _plan_json(candidate, confirmation=False))
    response = client.post("/api/v1/browser/reason", json=request.model_dump(mode="json", by_alias=True))
    assert response.status_code == 200, response.text
    assert response.json()["plan"]["actions"][0]["requires_confirmation"] is True


def test_reasoning_request_structurally_rejects_raw_capture_fields(client, monkeypatch):
    request = _request(monkeypatch)
    body = request.model_dump(mode="json", by_alias=True)
    body["payload"]["page"]["elements"][0]["raw_value"] = "must-never-enter-server-schema"
    response = client.post("/api/v1/browser/reason", json=body)
    assert response.status_code == 422
    assert "raw_value" in response.text


def _payload_with_visual(payload: BrowserReleasePayload) -> BrowserReleasePayload:
    visual = BrowserPublicVisualContext(
        mime_type="image/png",
        width=1084,
        height=907,
        image_base64="QUJDREVGR0hJSg==",
        sanitized_sha256="0" * 64,
        redacted_regions=1,
    )
    return payload.model_copy(
        update={
            "page": payload.page.model_copy(
                update={"visual_context": visual}
            )
        }
    )


def test_semantic_fast_path_accepts_single_exact_low_impact_target():
    base = _payload(
        task="open account settings",
        label="Account settings",
        role="link",
    ).model_copy(
        update={
            "minimization_basis_points": 9964,
            "task_utility_score": 94,
        }
    )

    payload = _payload_with_visual(base)

    assert reasoning._semantic_fast_path_eligible(payload) is True
    assert reasoning._reasoning_uses_visual(payload) is False


def test_semantic_fast_path_keeps_visual_for_multiple_targets():
    payload = _payload_with_visual(_payload())

    second = BrowserPublicElement(
        element_id="vg_other_button",
        role="button",
        label="Other",
        text="Other",
        disabled=False,
        bbox=(4000, 1000, 5000, 1800),
    )

    payload = payload.model_copy(
        update={
            "page": payload.page.model_copy(
                update={"elements": [*payload.page.elements, second]}
            )
        }
    )

    assert reasoning._semantic_fast_path_eligible(payload) is False
    assert reasoning._reasoning_uses_visual(payload) is True


def test_semantic_fast_path_keeps_visual_for_spatial_task():
    payload = _payload_with_visual(
        _payload(
            task="click the settings icon on the right",
            label="Settings",
            role="button",
        )
    )

    assert reasoning._semantic_fast_path_eligible(payload) is False
    assert reasoning._reasoning_uses_visual(payload) is True


def test_semantic_fast_path_keeps_visual_for_high_impact_task():
    payload = _payload_with_visual(
        _payload(
            task="confirm booking",
            label="Confirm booking",
            role="button",
        )
    )

    assert reasoning._semantic_fast_path_eligible(payload) is False
    assert reasoning._reasoning_uses_visual(payload) is True
