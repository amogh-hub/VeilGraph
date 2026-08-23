from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.browser.models import BrowserPairingAttestation, BrowserPairingPayload, BrowserSigner
from app.security.signing import public_key_b64, sign_payload, signer_fingerprint


PAIRING_TTL_SECONDS = 60


def create_pairing_attestation(challenge: str, *, now: datetime | None = None) -> BrowserPairingAttestation:
    """Prove possession of the local companion's persistent Ed25519 device key.

    The browser supplies a fresh challenge. The attestation is short-lived and
    intended for explicit trust-on-first-use pairing. Once paired, the extension
    pins both the public key and its SHA-256 fingerprint and rejects key changes.
    """

    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload = BrowserPairingPayload(
        challenge=challenge,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=PAIRING_TTL_SECONDS),
        signer=BrowserSigner(public_key_b64=public_key_b64(), public_key_sha256=signer_fingerprint()),
    )
    return BrowserPairingAttestation(
        payload=payload,
        signature_b64=sign_payload(payload.model_dump(mode="json", by_alias=True)),
    )
