from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

FORBIDDEN_PARTS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".veilgraph", ".veilgraph-hotfix-backups",
    "dist", "build", ".idea", ".vscode",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".log"}
FORBIDDEN_NAMES = {".env", ".env.local", ".env.production", ".DS_Store"}
PRIVATE_KEY_BLOCK_RE = re.compile(
    br"(?:^|\n)-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{20,}",
    re.MULTILINE,
)


class ReleasePackageError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_rel(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    if not rel or rel.startswith("/") or ".." in PurePosixPath(rel).parts:
        raise ReleasePackageError(f"Unsafe release path: {rel}")
    return rel


def should_exclude(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    if any(part in FORBIDDEN_PARTS for part in parts):
        return True
    name = parts[-1] if parts else rel
    if name in FORBIDDEN_NAMES or name.startswith(".env."):
        return True
    if Path(name).suffix.lower() in FORBIDDEN_SUFFIXES:
        return True
    # Never recursively package prior generated ZIPs or phase release output.
    if rel.startswith("competition/releases/") and rel.lower().endswith(".zip"):
        return True
    return False


def iter_release_files(root: Path) -> Iterable[tuple[str, Path]]:
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        rel = _safe_rel(path, root)
        if should_exclude(rel):
            continue
        yield rel, path


def _scan_bytes(rel: str, data: bytes) -> None:
    # Match an actual PEM-style private-key block rather than documentation/source
    # code which merely names the marker string. Private-key filename extensions
    # and `.veilgraph/` are excluded separately before this content scan.
    if PRIVATE_KEY_BLOCK_RE.search(data):
        raise ReleasePackageError(f"Private-key material detected in release candidate: {rel}")


def build_release_package(root: Path, *, phase: str = "phase2") -> tuple[bytes, dict[str, Any]]:
    root = root.resolve()
    entries: dict[str, str] = {}
    payloads: list[tuple[str, bytes]] = []
    for rel, path in iter_release_files(root):
        data = path.read_bytes()
        _scan_bytes(rel, data)
        entries[rel] = sha256_bytes(data)
        payloads.append((rel, data))

    manifest = {
        "schema": "veilgraph.sanitized-release.v1",
        "phase": phase,
        "entries": entries,
        "entry_count": len(entries),
        "forbidden_private_key_material": True,
        "forbidden_runtime_databases": True,
        "forbidden_workspaces": True,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel, data in payloads:
            info = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        info = zipfile.ZipInfo("veilgraph-release-manifest.json", date_time=(2026, 1, 1, 0, 0, 0))
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest_bytes)
    return output.getvalue(), manifest


def verify_release_package_bytes(package: bytes) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def record(name: str, valid: bool, detail: str) -> None:
        checks.append({"name": name, "valid": bool(valid), "detail": detail})

    try:
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ReleasePackageError("Duplicate ZIP member names")
            for name in names:
                normalized = name.replace("\\", "/")
                parts = PurePosixPath(normalized).parts
                if normalized.startswith("/") or ".." in parts:
                    raise ReleasePackageError(f"Unsafe ZIP path: {name}")
                if name != "veilgraph-release-manifest.json" and should_exclude(name):
                    raise ReleasePackageError(f"Forbidden release member: {name}")
                info = archive.getinfo(name)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise ReleasePackageError(f"Symlink member is forbidden: {name}")
                data = archive.read(name)
                _scan_bytes(name, data)
            manifest_name = "veilgraph-release-manifest.json"
            if manifest_name not in names:
                raise ReleasePackageError("Release manifest is missing")
            manifest = json.loads(archive.read(manifest_name))
            entries = manifest.get("entries", {})
            if not isinstance(entries, dict):
                raise ReleasePackageError("Release manifest entries are missing")
            if manifest_name in entries:
                raise ReleasePackageError("Release manifest may not recursively list itself")
            entry_count = manifest.get("entry_count")
            if not isinstance(entry_count, int) or entry_count != len(entries):
                raise ReleasePackageError("Release manifest entry_count does not match entries")
            actual_payload_names = set(names) - {manifest_name}
            manifest_names = set(entries)
            if actual_payload_names != manifest_names:
                missing = sorted(manifest_names - actual_payload_names)
                extra = sorted(actual_payload_names - manifest_names)
                raise ReleasePackageError(
                    f"Release member set does not exactly match manifest; missing={missing[:5]} extra={extra[:5]}"
                )
            for name, expected in entries.items():
                if not isinstance(expected, str) or len(expected) != 64:
                    raise ReleasePackageError(f"Invalid manifest SHA-256 for member: {name}")
                if sha256_bytes(archive.read(name)) != expected:
                    raise ReleasePackageError(f"Release member hash mismatch: {name}")
    except Exception as exc:
        record("release_package", False, str(exc))
        return {"valid": False, "checks": checks}

    record("release_package", True, "Sanitized release package paths, exclusions and hashes are valid")
    return {"valid": True, "checks": checks, "entry_count": int(manifest.get("entry_count", 0))}
