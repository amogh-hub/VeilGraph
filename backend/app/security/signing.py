from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.config import settings


class SigningError(RuntimeError):
    pass


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key_path() -> Path:
    path = Path(settings.signing_key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _private_key() -> Ed25519PrivateKey:
    path = _key_path()
    if not path.exists():
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Exclusive creation prevents accidental overwrite of an established device identity.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
        except FileExistsError:
            pass
    try:
        raw = path.read_bytes()
        if len(raw) != 32:
            raise SigningError("Device Ed25519 key is malformed")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return Ed25519PrivateKey.from_private_bytes(raw)
    except OSError as exc:
        raise SigningError(f"Unable to read device signing key: {exc}") from exc


def public_key_bytes() -> bytes:
    return _private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_b64() -> str:
    return base64.b64encode(public_key_bytes()).decode("ascii")


def signer_fingerprint() -> str:
    return hashlib.sha256(public_key_bytes()).hexdigest()


def sign_payload(payload: Any) -> str:
    signature = _private_key().sign(canonical_json_bytes(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_payload(payload: Any, signature_b64: str, public_key_b64_value: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_raw = base64.b64decode(public_key_b64_value, validate=True)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, canonical_json_bytes(payload))
        return True
    except Exception:
        return False
