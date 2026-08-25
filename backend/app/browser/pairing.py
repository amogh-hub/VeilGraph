from __future__ import annotations

import base64
import hashlib
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.browser.models import (
    BrowserPairingAttestation,
    BrowserPairingPayload,
    BrowserSigner,
    BrowserTransportSessionAttestation,
    BrowserTransportSessionPayload,
)
from app.security.signing import (
    public_key_b64,
    sign_payload,
    signer_fingerprint,
)


PAIRING_TTL_SECONDS = 60
TRANSPORT_TTL_SECONDS = 30

_TRANSPORT_INFO_PREFIX = b"veilgraph.browser-local-transport.v1|"


@dataclass
class _TransportSession:
    key: bytearray
    endpoint: str
    expires_at: float


_transport_lock = threading.Lock()
_transport_sessions: dict[str, _TransportSession] = {}


def _utc(value: datetime | None = None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _signer() -> BrowserSigner:
    return BrowserSigner(
        public_key_b64=public_key_b64(),
        public_key_sha256=signer_fingerprint(),
    )


def create_pairing_attestation(
    challenge: str,
    *,
    now: datetime | None = None,
) -> BrowserPairingAttestation:
    """Prove possession of the persistent Ed25519 device identity."""

    issued_at = _utc(now)
    payload = BrowserPairingPayload(
        challenge=challenge,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(
            seconds=PAIRING_TTL_SECONDS
        ),
        signer=_signer(),
    )
    return BrowserPairingAttestation(
        payload=payload,
        signature_b64=sign_payload(
            payload.model_dump(
                mode="json",
                by_alias=True,
            )
        ),
    )


def _derive_transport_key(
    *,
    shared_secret: bytes,
    session_id: str,
    challenge: str,
    endpoint: str,
) -> bytes:
    salt = hashlib.sha256(
        f"{session_id}|{challenge}".encode("utf-8")
    ).digest()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_TRANSPORT_INFO_PREFIX
        + endpoint.encode("ascii"),
    ).derive(shared_secret)


def _zero_key(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _prune_transport_sessions_locked(
    now_timestamp: float,
) -> None:
    expired = [
        session_id
        for session_id, session
        in _transport_sessions.items()
        if session.expires_at < now_timestamp
    ]
    for session_id in expired:
        session = _transport_sessions.pop(session_id)
        _zero_key(session.key)


def create_transport_session(
    *,
    challenge: str,
    client_public_key_b64: str,
    endpoint: str,
    now: datetime | None = None,
) -> BrowserTransportSessionAttestation:
    """Create an Ed25519-authenticated one-time ECDH transport channel.

    The raw browser capture is never required to trust an unauthenticated
    localhost listener. The extension verifies this signed ephemeral key
    against its already-pinned companion Ed25519 identity before encrypting
    any DOM/screenshot material.
    """

    if endpoint not in {
        "analyse-capture",
        "prepare-release",
    }:
        raise ValueError("unsupported browser transport endpoint")

    try:
        client_raw = base64.b64decode(
            client_public_key_b64,
            validate=True,
        )
        client_public_key = (
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                client_raw,
            )
        )
    except Exception as exc:
        raise ValueError(
            "invalid browser transport ECDH public key"
        ) from exc

    companion_private = ec.generate_private_key(
        ec.SECP256R1()
    )
    companion_public_raw = (
        companion_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    )

    shared_secret = companion_private.exchange(
        ec.ECDH(),
        client_public_key,
    )

    session_id = (
        "VGT-"
        + secrets.token_hex(10).upper()
    )

    key = _derive_transport_key(
        shared_secret=shared_secret,
        session_id=session_id,
        challenge=challenge,
        endpoint=endpoint,
    )

    issued_at = _utc(now)
    expires_at = issued_at + timedelta(
        seconds=TRANSPORT_TTL_SECONDS
    )

    with _transport_lock:
        _prune_transport_sessions_locked(
            issued_at.timestamp()
        )
        _transport_sessions[session_id] = _TransportSession(
            key=bytearray(key),
            endpoint=endpoint,
            expires_at=expires_at.timestamp(),
        )

    payload = BrowserTransportSessionPayload(
        session_id=session_id,
        challenge=challenge,
        endpoint=endpoint,
        client_public_key_b64=client_public_key_b64,
        companion_ephemeral_public_key_b64=(
            base64.b64encode(
                companion_public_raw
            ).decode("ascii")
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        signer=_signer(),
    )

    return BrowserTransportSessionAttestation(
        payload=payload,
        signature_b64=sign_payload(
            payload.model_dump(
                mode="json",
                by_alias=True,
            )
        ),
    )


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(
            value + padding
        )
    except Exception as exc:
        raise ValueError(
            "invalid browser transport IV"
        ) from exc


def _transport_aad(
    session_id: str,
    endpoint: str,
) -> bytes:
    return (
        "veilgraph.browser-local-transport.v1"
        f"|{session_id}|{endpoint}"
    ).encode("ascii")


def consume_transport_ciphertext(
    *,
    session_id: str,
    endpoint: str,
    iv_b64url: str,
    ciphertext: bytes,
    now: datetime | None = None,
) -> bytes:
    """Consume exactly one encrypted capture session.

    Sessions are removed before decryption so replay, malformed ciphertext,
    or authentication failure cannot reuse a transport authorization.
    """

    current = _utc(now)

    with _transport_lock:
        _prune_transport_sessions_locked(
            current.timestamp()
        )
        session = _transport_sessions.pop(
            session_id,
            None,
        )

    if session is None:
        raise ValueError(
            "browser transport session is missing, expired, or already consumed"
        )

    key = bytes(session.key)
    _zero_key(session.key)

    if session.expires_at < current.timestamp():
        raise ValueError(
            "browser transport session expired"
        )

    if session.endpoint != endpoint:
        raise ValueError(
            "browser transport endpoint binding mismatch"
        )

    iv = _b64url_decode(iv_b64url)
    if len(iv) != 12:
        raise ValueError(
            "browser transport IV must be 96 bits"
        )

    if len(ciphertext) < 16:
        raise ValueError(
            "browser transport ciphertext is truncated"
        )

    try:
        return AESGCM(key).decrypt(
            iv,
            ciphertext,
            _transport_aad(
                session_id,
                endpoint,
            ),
        )
    except InvalidTag as exc:
        raise ValueError(
            "browser transport authentication failed"
        ) from exc
