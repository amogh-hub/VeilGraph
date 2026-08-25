from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.browser.pairing import (
    consume_transport_ciphertext,
    create_transport_session,
)
from app.security.signing import verify_payload


NOW = datetime(
    2026,
    8,
    25,
    12,
    0,
    tzinfo=timezone.utc,
)

CHALLENGE = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGH123456"
)


def _client_material(endpoint: str):
    private = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_raw = (
        private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    )

    public_b64 = base64.b64encode(
        public_raw
    ).decode("ascii")

    attestation = create_transport_session(
        challenge=CHALLENGE,
        client_public_key_b64=public_b64,
        endpoint=endpoint,
        now=NOW,
    )

    companion_raw = base64.b64decode(
        attestation.payload
        .companion_ephemeral_public_key_b64,
        validate=True,
    )

    companion_public = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            companion_raw,
        )
    )

    shared = private.exchange(
        ec.ECDH(),
        companion_public,
    )

    salt = hashes.Hash(
        hashes.SHA256()
    )
    salt.update(
        (
            f"{attestation.payload.session_id}"
            f"|{CHALLENGE}"
        ).encode("utf-8")
    )
    salt_bytes = salt.finalize()

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        info=(
            b"veilgraph.browser-local-transport.v1|"
            + endpoint.encode("ascii")
        ),
    ).derive(shared)

    return attestation, key


def _aad(
    session_id: str,
    endpoint: str,
) -> bytes:
    return (
        "veilgraph.browser-local-transport.v1"
        f"|{session_id}|{endpoint}"
    ).encode("ascii")


def _iv_b64url(iv: bytes) -> str:
    return (
        base64.urlsafe_b64encode(iv)
        .decode("ascii")
        .rstrip("=")
    )


def test_transport_attestation_is_signed_by_pinned_device_identity():
    attestation, _ = _client_material(
        "prepare-release"
    )

    assert (
        attestation.payload.schema_id
        == "veilgraph.browser-companion-transport.v1"
    )
    assert (
        attestation.payload.purpose
        == "PROTECT_RAW_BROWSER_CAPTURE"
    )
    assert (
        attestation.payload.endpoint
        == "prepare-release"
    )
    assert (
        attestation.payload.expires_at
        - attestation.payload.issued_at
    ).total_seconds() == 30

    assert verify_payload(
        attestation.payload.model_dump(
            mode="json",
            by_alias=True,
        ),
        attestation.signature_b64,
        attestation.payload.signer.public_key_b64,
    )


def test_raw_canary_is_ciphertext_before_local_http_delivery():
    endpoint = "prepare-release"
    attestation, key = _client_material(
        endpoint
    )

    canary = (
        b"VG-CANARY-RAW-IDENTITY-"
        b"AARAV-MEHTA-482917"
    )

    plaintext = (
        b"\x00\x00\x00\x02"
        b"\x01"
        b"{}"
        + canary
    )

    iv = bytes(range(12))

    ciphertext = AESGCM(key).encrypt(
        iv,
        plaintext,
        _aad(
            attestation.payload.session_id,
            endpoint,
        ),
    )

    # The actual localhost HTTP body contains ciphertext only.
    assert canary not in ciphertext
    assert b"AARAV" not in ciphertext
    assert b"482917" not in ciphertext

    recovered = consume_transport_ciphertext(
        session_id=attestation.payload.session_id,
        endpoint=endpoint,
        iv_b64url=_iv_b64url(iv),
        ciphertext=ciphertext,
        now=NOW,
    )

    assert recovered == plaintext


def test_transport_session_is_one_time_and_replay_fails_closed():
    endpoint = "analyse-capture"
    attestation, key = _client_material(
        endpoint
    )

    plaintext = b"one-time-capture"
    iv = b"\x11" * 12

    ciphertext = AESGCM(key).encrypt(
        iv,
        plaintext,
        _aad(
            attestation.payload.session_id,
            endpoint,
        ),
    )

    recovered = consume_transport_ciphertext(
        session_id=attestation.payload.session_id,
        endpoint=endpoint,
        iv_b64url=_iv_b64url(iv),
        ciphertext=ciphertext,
        now=NOW,
    )

    assert recovered == plaintext

    with pytest.raises(
        ValueError,
        match="missing, expired, or already consumed",
    ):
        consume_transport_ciphertext(
            session_id=attestation.payload.session_id,
            endpoint=endpoint,
            iv_b64url=_iv_b64url(iv),
            ciphertext=ciphertext,
            now=NOW,
        )


def test_transport_session_is_bound_to_exact_endpoint():
    attestation, key = _client_material(
        "prepare-release"
    )

    iv = b"\x22" * 12
    plaintext = b"endpoint-bound"

    ciphertext = AESGCM(key).encrypt(
        iv,
        plaintext,
        _aad(
            attestation.payload.session_id,
            "prepare-release",
        ),
    )

    with pytest.raises(
        ValueError,
        match="endpoint binding mismatch",
    ):
        consume_transport_ciphertext(
            session_id=attestation.payload.session_id,
            endpoint="analyse-capture",
            iv_b64url=_iv_b64url(iv),
            ciphertext=ciphertext,
            now=NOW,
        )


def test_transport_session_endpoint_rejects_invalid_ecdh_key(client):
    response = client.post(
        "/api/v1/browser/transport-session",
        json={
            "challenge": CHALLENGE,
            "client_public_key_b64":
                base64.b64encode(
                    b"not-a-p256-point"
                ).decode("ascii"),
            "endpoint": "prepare-release",
        },
    )

    assert response.status_code == 422


def test_transport_session_endpoint_returns_signed_ephemeral_binding(client):
    private = ec.generate_private_key(
        ec.SECP256R1()
    )
    public_raw = (
        private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    )

    public_b64 = base64.b64encode(
        public_raw
    ).decode("ascii")

    response = client.post(
        "/api/v1/browser/transport-session",
        json={
            "challenge": CHALLENGE,
            "client_public_key_b64":
                public_b64,
            "endpoint": "prepare-release",
        },
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert (
        body["payload"]["schema"]
        == "veilgraph.browser-companion-transport.v1"
    )
    assert (
        body["payload"]["challenge"]
        == CHALLENGE
    )
    assert (
        body["payload"]["client_public_key_b64"]
        == public_b64
    )
    assert (
        body["payload"]["purpose"]
        == "PROTECT_RAW_BROWSER_CAPTURE"
    )
    assert body["signature_algorithm"] == "Ed25519"
    assert body["signature_b64"]
