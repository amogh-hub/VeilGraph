from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.browser.models import (
    BrowserGateResult,
    BrowserPublicElement,
    BrowserPublicPage,
    BrowserReleasePayload,
    BrowserVerificationSummary,
)
from app.browser.release_gate import authorize_network_release, release_payload_sha256, verify_network_authorization
from app.core.config import settings
from app.core.enums import TestStatus as GateStatus


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


def _payload(*, privacy_level: int = 4, floor: int = 4) -> BrowserReleasePayload:
    return BrowserReleasePayload(
        session_id="session_0123456789abcdef",
        task_id="task_0123456789abcdef",
        task="Book a follow-up appointment",
        page=BrowserPublicPage(
            origin="https://example.test",
            title="Appointment portal",
            elements=[
                BrowserPublicElement(
                    element_id="vg_followup_btn",
                    role="button",
                    label="Book follow-up",
                    text="Book follow-up",
                    bbox=(1000, 2000, 3000, 2800),
                )
            ],
        ),
        privacy_level=privacy_level,
        network_privacy_floor=floor,
        identity_exposure_before=91,
        residual_identity_exposure=9,
        task_utility_score=96,
        minimization_basis_points=8700,
    )


def _summary(**updates) -> BrowserVerificationSummary:
    tests = [
        BrowserGateResult(
            name=name,
            status=GateStatus.PASS,
            detail=f"{name} passed",
            attack_class="browser_network_release",
            severity="critical" if name != "task_utility_anchor_preservation" else "high",
        )
        for name in MANDATORY_GATES
    ]
    base = BrowserVerificationSummary(
        tests=tests,
        proof_score=100,
        critical_failures=0,
        policy_floor_satisfied=True,
        forbidden_raw_fields_present=False,
        payload_commitment_valid=True,
        critical_exposure_present=False,
    )
    return base.model_copy(update=updates)


@pytest.fixture(autouse=True)
def isolated_signer(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "signing_key_path", tmp_path / "device-ed25519.key")


def test_all_mandatory_gates_required_for_network_release():
    payload = _payload()
    summary = _summary()
    now = datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc)

    authorization = authorize_network_release(payload, summary, now=now)

    assert authorization.payload.decision == "ALLOW_NETWORK_RELEASE"
    assert authorization.payload.mandatory_gates == len(MANDATORY_GATES)
    assert authorization.payload.mandatory_passed == len(MANDATORY_GATES)
    assert authorization.payload.payload_sha256 == release_payload_sha256(payload)
    assert verify_network_authorization(authorization, payload, now=now + timedelta(seconds=1))


@pytest.mark.parametrize("status", [GateStatus.FAIL, GateStatus.INCONCLUSIVE])
def test_fail_or_inconclusive_mandatory_gate_denies_release(status: GateStatus):
    payload = _payload()
    summary = _summary()
    tests = list(summary.tests)
    tests[0] = tests[0].model_copy(update={"status": status})
    summary = summary.model_copy(update={"tests": tests})

    authorization = authorize_network_release(payload, summary)

    assert authorization.payload.decision == "DENY_NETWORK_RELEASE"
    assert not verify_network_authorization(authorization, payload)


@pytest.mark.parametrize(
    "updates",
    [
        {"proof_score": 99},
        {"critical_failures": 1},
        {"policy_floor_satisfied": False},
        {"forbidden_raw_fields_present": True},
        {"payload_commitment_valid": False},
        {"critical_exposure_present": True},
    ],
)
def test_release_invariants_are_fail_closed(updates):
    authorization = authorize_network_release(_payload(), _summary(**updates))
    assert authorization.payload.decision == "DENY_NETWORK_RELEASE"


def test_caller_cannot_bypass_network_privacy_floor():
    authorization = authorize_network_release(_payload(privacy_level=2, floor=4), _summary())
    assert authorization.payload.decision == "DENY_NETWORK_RELEASE"


def test_authorization_is_bound_to_exact_payload():
    payload = _payload()
    now = datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc)
    authorization = authorize_network_release(payload, _summary(), now=now)
    modified = payload.model_copy(update={"task": "Read the account balance"})

    assert not verify_network_authorization(authorization, modified, now=now + timedelta(seconds=1))


def test_authorization_expires():
    payload = _payload()
    now = datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc)
    authorization = authorize_network_release(payload, _summary(), now=now, ttl_seconds=5)

    assert verify_network_authorization(authorization, payload, now=now + timedelta(seconds=4))
    assert not verify_network_authorization(authorization, payload, now=now + timedelta(seconds=6))


def test_release_payload_forbids_internal_raw_fields():
    with pytest.raises(Exception):
        BrowserPublicElement.model_validate(
            {
                "element_id": "vg_sensitive_field",
                "role": "textbox",
                "label": "Protected",
                "text": "[PROTECTED]",
                "raw_value": "do-not-serialize-me",
            }
        )


def test_terminal_evidence_is_cryptographically_bound_to_release_authorization():
    payload = _payload().model_copy(
        update={
            "terminal_evidence": "POSITIVE_COMPLETION",
        }
    )

    authorization = authorize_network_release(
        payload,
        _summary(),
    )

    assert verify_network_authorization(
        authorization,
        payload,
    )

    tampered = payload.model_copy(
        update={
            "terminal_evidence": "NONE",
        }
    )

    assert not verify_network_authorization(
        authorization,
        tampered,
    )
