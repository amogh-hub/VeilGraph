from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import tempfile
import threading
import unicodedata
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings


class WorkspaceError(RuntimeError):
    pass


class JobWorkspace:
    """In-process key custody plus AES-256-GCM encrypted job blobs.

    Keys are generated randomly per job. Separate encryption and entity-fingerprint
    keys are derived using HKDF. Sensitive plaintext may exist temporarily in
    process memory, but is never intentionally persisted by this class.
    """

    _HKDF_SALT: Final[bytes] = b"veilgraph-workspace-hkdf-v1"

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.path = settings.workspace_root / job_id
        self.path.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.path.chmod(0o700)
        self._master_key = bytearray(os.urandom(32))
        self._encryption_key = bytearray(self._derive_key(b"workspace-encryption"))
        self._fingerprint_key = bytearray(self._derive_key(b"entity-fingerprints"))
        self._aes = AESGCM(bytes(self._encryption_key))
        self._destroyed = False
        self._lock = threading.RLock()
        self.plaintext_entities: dict[str, str] = {}

    def _derive_key(self, info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._HKDF_SALT,
            info=info + self.job_id.encode("utf-8"),
        ).derive(bytes(self._master_key))

    @staticmethod
    def _safe_name(name: str) -> str:
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise WorkspaceError("Unsafe workspace filename")
        return name

    def _aad(self, filename: str) -> bytes:
        return f"veilgraph:{self.job_id}:{filename}".encode("utf-8")

    def write_encrypted(self, filename: str, data: bytes) -> None:
        with self._lock:
            self._ensure_active()
            filename = self._safe_name(filename)
            nonce = os.urandom(12)
            encrypted = self._aes.encrypt(nonce, data, self._aad(filename))
            destination = self.path / filename
            temp_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile(dir=self.path, prefix=".vg-", delete=False) as handle:
                    temp_name = handle.name
                    os.chmod(temp_name, 0o600)
                    handle.write(nonce + encrypted)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, destination)
                destination.chmod(0o600)
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)

    def read_encrypted(self, filename: str) -> bytes:
        with self._lock:
            self._ensure_active()
            filename = self._safe_name(filename)
            source = self.path / filename
            if source.is_symlink() or not source.is_file():
                raise WorkspaceError("Encrypted workspace blob is not a regular file")
            raw = source.read_bytes()
            if len(raw) < 13:
                raise WorkspaceError("Encrypted blob is truncated")
            return self._aes.decrypt(raw[:12], raw[12:], self._aad(filename))

    def fingerprint(self, value: str) -> str:
        self._ensure_active()
        normalized = unicodedata.normalize("NFKC", value).strip().casefold()
        normalized = " ".join(normalized.split())
        return hmac.new(bytes(self._fingerprint_key), normalized.encode("utf-8"), hashlib.sha256).hexdigest()

    def remember_plaintext(self, entity_id: str, value: str) -> None:
        self._ensure_active()
        self.plaintext_entities[entity_id] = value

    def get_plaintext(self, entity_id: str) -> str | None:
        self._ensure_active()
        return self.plaintext_entities.get(entity_id)

    def _ensure_active(self) -> None:
        if self._destroyed:
            raise WorkspaceError("Workspace has been destroyed")

    @staticmethod
    def _zero(byte_array: bytearray) -> None:
        for index in range(len(byte_array)):
            byte_array[index] = 0

    def destroy(self) -> dict[str, int | str | bool]:
        with self._lock:
            if self._destroyed:
                return {
                    "destroyed": True,
                    "deleted_workspace_files": 0,
                    "cleared_plaintext_entities": 0,
                    "note": "Workspace was already destroyed.",
                }

            file_count = sum(1 for p in self.path.iterdir() if p.is_file()) if self.path.exists() else 0
            plaintext_count = len(self.plaintext_entities)
            self.plaintext_entities.clear()

            # Best-effort zeroing of Python-owned bytearrays. Python/runtime copies
            # cannot be forensically guaranteed, so the product claim is limited to
            # application-level cryptographic erasure.
            self._zero(self._fingerprint_key)
            self._zero(self._encryption_key)
            self._zero(self._master_key)
            del self._aes

            shutil.rmtree(self.path, ignore_errors=True)
            self._destroyed = True
            return {
                "destroyed": True,
                "deleted_workspace_files": file_count,
                "cleared_plaintext_entities": plaintext_count,
                "note": (
                    "Encrypted job blobs were deleted and the in-process job keys were destroyed. "
                    "VeilGraph does not claim forensic overwriting of SSD flash cells."
                ),
            }


_registry: dict[str, JobWorkspace] = {}
_registry_lock = threading.RLock()


def create_workspace(job_id: str) -> JobWorkspace:
    with _registry_lock:
        if job_id in _registry:
            raise WorkspaceError("Workspace already exists")
        workspace = JobWorkspace(job_id)
        _registry[job_id] = workspace
        return workspace


def get_workspace(job_id: str) -> JobWorkspace:
    with _registry_lock:
        workspace = _registry.get(job_id)
        if workspace is None:
            raise WorkspaceError(
                "Active workspace key is unavailable. The process may have restarted or the job was destroyed."
            )
        return workspace


def destroy_workspace(job_id: str) -> dict[str, int | str | bool]:
    with _registry_lock:
        workspace = _registry.pop(job_id, None)
    if workspace is not None:
        return workspace.destroy()

    # After a process restart, RAM-only keys are intentionally unrecoverable but
    # encrypted blobs may still exist on disk until their retention deadline.
    # Destruction must therefore remove orphaned encrypted directories even when
    # no in-process workspace object/key survives.
    orphan_path = settings.workspace_root / job_id
    file_count = 0
    if orphan_path.exists():
        file_count = sum(1 for p in orphan_path.rglob("*") if p.is_file())
        shutil.rmtree(orphan_path, ignore_errors=True)
    return {
        "destroyed": True,
        "deleted_workspace_files": file_count,
        "cleared_plaintext_entities": 0,
        "note": (
            "No active in-process key existed; any orphaned encrypted job blobs were deleted. "
            "RAM-only keys were already unavailable."
        ),
    }
