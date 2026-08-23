from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from app.browser.pairing import create_pairing_attestation
from app.security.signing import verify_payload


def test_pairing_attestation_binds_fresh_challenge_to_device_key():
    challenge = "abcdefghijklmnopqrstuvwxyzABCDEFGH123456"
    attestation = create_pairing_attestation(
        challenge,
        now=datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc),
    )

    assert attestation.payload.challenge == challenge
    assert attestation.payload.purpose == "PAIR_LOCAL_VEILGRAPH_COMPANION"
    assert (attestation.payload.expires_at - attestation.payload.issued_at).total_seconds() == 60
    public_raw = base64.b64decode(attestation.payload.signer.public_key_b64, validate=True)
    assert hashlib.sha256(public_raw).hexdigest() == attestation.payload.signer.public_key_sha256
    assert verify_payload(
        attestation.payload.model_dump(mode="json", by_alias=True),
        attestation.signature_b64,
        attestation.payload.signer.public_key_b64,
    )


def test_pairing_endpoint_returns_signed_attestation(client):
    challenge = "0123456789abcdefghijklmnopqrstuvwxyzAB"
    response = client.post("/api/v1/browser/pair", json={"challenge": challenge})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["payload"]["schema"] == "veilgraph.browser-companion-pairing.v1"
    assert body["payload"]["challenge"] == challenge
    assert body["signature_algorithm"] == "Ed25519"
    assert body["signature_b64"]


def test_pairing_endpoint_rejects_short_or_non_urlsafe_challenge(client):
    assert client.post("/api/v1/browser/pair", json={"challenge": "short"}).status_code == 422
    assert client.post("/api/v1/browser/pair", json={"challenge": "x" * 31 + "+"}).status_code == 422
