from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.browser.models import (
    BrowserNetworkAuthorization,
    BrowserNetworkAuthorizationPayload,
    BrowserReleasePayload,
    BrowserSigner,
    BrowserVerificationSummary,
)
from app.core.enums import TestStatus
from app.security.signing import (
    canonical_json_bytes,
    public_key_b64,
    sign_payload,
    signer_fingerprint,
    verify_payload,
)


DEFAULT_AUTHORIZATION_TTL_SECONDS = 30


def release_payload_sha256(payload: BrowserReleasePayload) -> str:
    serialized = payload.model_dump(mode="json", by_alias=True)
    return hashlib.sha256(canonical_json_bytes(serialized)).hexdigest()


def _decision(summary: BrowserVerificationSummary) -> tuple[str, int, int]:
    mandatory = [test for test in summary.tests if test.mandatory]
    mandatory_passed = sum(test.status == TestStatus.PASS for test in mandatory)
    all_mandatory_pass = bool(mandatory) and mandatory_passed == len(mandatory)

    allow = (
        all_mandatory_pass
        and summary.proof_score == 100
        and summary.critical_failures == 0
        and summary.policy_floor_satisfied
        and not summary.forbidden_raw_fields_present
        and summary.payload_commitment_valid
        and not summary.critical_exposure_present
    )
    return ("ALLOW_NETWORK_RELEASE" if allow else "DENY_NETWORK_RELEASE", len(mandatory), mandatory_passed)


def authorize_network_release(
    payload: BrowserReleasePayload,
    verification: BrowserVerificationSummary,
    *,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_AUTHORIZATION_TTL_SECONDS,
) -> BrowserNetworkAuthorization:
    """Issue a signed decision bound to the exact externally transmissible payload.

    This function consumes *trusted local verifier output*. It is intentionally
    not exposed as an API that accepts caller-asserted verification results.
    """

    if ttl_seconds < 1 or ttl_seconds > 300:
        raise ValueError("network authorization TTL must be between 1 and 300 seconds")

    if payload.privacy_level < payload.network_privacy_floor:
        # The compiler/network policy is authoritative even if a caller marks
        # policy_floor_satisfied incorrectly.
        verification = verification.model_copy(update={"policy_floor_satisfied": False})

    decision, mandatory_count, mandatory_passed = _decision(verification)
    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    payload_sha = release_payload_sha256(payload)
    authorization_short = hashlib.sha256(
        f"{payload_sha}:{payload.session_id}:{payload.task_id}:{issued_at.isoformat()}".encode("utf-8")
    ).hexdigest()[:20].upper()

    auth_payload = BrowserNetworkAuthorizationPayload(
        authorization_id=f"VGN-{authorization_short}",
        decision=decision,
        payload_sha256=payload_sha,
        session_id=payload.session_id,
        task_id=payload.task_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=secrets.token_urlsafe(24),
        proof_score=verification.proof_score,
        mandatory_gates=mandatory_count,
        mandatory_passed=mandatory_passed,
        critical_failures=verification.critical_failures,
        identity_exposure_before=payload.identity_exposure_before,
        residual_identity_exposure=payload.residual_identity_exposure,
        task_utility_score=payload.task_utility_score,
        signer=BrowserSigner(
            public_key_b64=public_key_b64(),
            public_key_sha256=signer_fingerprint(),
        ),
        disclaimer=(
            "This authorization proves that the exact payload commitment passed the recorded local VeilGraph "
            "browser-network release checks. It is not a universal guarantee of anonymity or future non-reidentification."
        ),
    )
    signature = sign_payload(auth_payload.model_dump(mode="json", by_alias=True))
    return BrowserNetworkAuthorization(payload=auth_payload, signature_b64=signature)


def verify_network_authorization(
    authorization: BrowserNetworkAuthorization,
    payload: BrowserReleasePayload,
    *,
    now: datetime | None = None,
    require_allow: bool = True,
) -> bool:
    auth = authorization.payload
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current < auth.issued_at or current > auth.expires_at:
        return False
    if auth.session_id != payload.session_id or auth.task_id != payload.task_id:
        return False
    if auth.payload_sha256 != release_payload_sha256(payload):
        return False
    if require_allow and auth.decision != "ALLOW_NETWORK_RELEASE":
        return False
    if authorization.signature_algorithm != "Ed25519":
        return False
    return verify_payload(
        auth.model_dump(mode="json", by_alias=True),
        authorization.signature_b64,
        auth.signer.public_key_b64,
    )
