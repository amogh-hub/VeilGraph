#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import socket
import stat
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.core.config import settings
from app.core.database import db
from app.ops.status import database_quick_check
from app.proof.package import verify_proof_package_bytes
from app.security.deployment import authorize_request, validate_online_configuration
from app.security.network_guard import disable_egress_guard_for_tests, install_egress_guard
from app.security.release_package import build_release_package, verify_release_package_bytes
from app.security.workspace import create_workspace, destroy_workspace


def result(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def main() -> int:
    checks: list[dict] = []

    try:
        token = "A" * 40
        validate_online_configuration(offline_mode=False, api_token=token, require_https=True)
        denied = authorize_request(
            offline_mode=False, client_host="10.0.0.2", headers={}, url_scheme="https",
            configured_token=token, require_https=True,
        )
        checks.append(result("secure_online_auth_fail_closed", not denied.allowed and denied.status_code == 401, denied.detail))

        spoofed = authorize_request(
            offline_mode=False,
            client_host="203.0.113.22",
            headers={"authorization": f"Bearer {token}", "x-forwarded-proto": "https"},
            url_scheme="http",
            configured_token=token,
            require_https=True,
            trust_proxy_headers=True,
            trusted_proxy_networks=("10.20.0.0/16",),
        )
        checks.append(result(
            "forwarded_https_untrusted_peer_rejected",
            not spoofed.allowed and spoofed.status_code == 426,
            spoofed.detail,
        ))

        trusted = authorize_request(
            offline_mode=False,
            client_host="10.20.4.8",
            headers={"authorization": f"Bearer {token}", "x-forwarded-proto": "https"},
            url_scheme="http",
            configured_token=token,
            require_https=True,
            trust_proxy_headers=True,
            trusted_proxy_networks=("10.20.0.0/16",),
        )
        checks.append(result("forwarded_https_trusted_proxy_only", trusted.allowed, trusted.detail))
    except Exception as exc:
        checks.append(result("secure_online_boundary", False, str(exc)))

    disable_egress_guard_for_tests()
    install_egress_guard()
    try:
        try:
            socket.create_connection(("example.invalid", 443), timeout=0.01)
            blocked = False
            detail = "unexpected connection attempt allowed"
        except OSError as exc:
            blocked = "blocked" in str(exc).lower()
            detail = str(exc)
        checks.append(result("offline_python_egress_guard", blocked, detail))
    finally:
        disable_egress_guard_for_tests()

    db.init_schema()
    quick = database_quick_check()
    checks.append(result("sqlite_quick_check", bool(quick["ok"]), str(quick["detail"])))

    previous_root = settings.workspace_root
    with tempfile.TemporaryDirectory(prefix="veilgraph-phase2-workspace-") as tmp:
        settings.workspace_root = Path(tmp)
        job_id = f"phase2-{uuid.uuid4()}"
        ws = create_workspace(job_id)
        try:
            ws.write_encrypted("blob.vgenc", b"phase2-sensitive")
            root_mode = stat.S_IMODE(ws.path.stat().st_mode)
            file_mode = stat.S_IMODE((ws.path / "blob.vgenc").stat().st_mode)
            checks.append(result(
                "workspace_permissions",
                root_mode == 0o700 and file_mode == 0o600,
                f"workspace={oct(root_mode)} blob={oct(file_mode)}",
            ))
        finally:
            destroy_workspace(job_id)
            settings.workspace_root = previous_root

    malicious = io.BytesIO()
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../escape", b"x")
        archive.writestr("veilgraph-bundle-receipt.json", "{}")
        archive.writestr("veilgraph-export-audit-ledger.json", "{}")
    proof = verify_proof_package_bytes(malicious.getvalue())
    checks.append(result("proof_zip_path_traversal", not proof.get("valid", True), str(proof.get("checks", [])[:2])))

    with tempfile.TemporaryDirectory(prefix="veilgraph-phase2-release-") as tmp:
        fake = Path(tmp)
        (fake / "backend").mkdir()
        (fake / "backend/app.py").write_text("print('ok')\n")
        (fake / ".veilgraph").mkdir()
        (fake / ".veilgraph/device-ed25519.key").write_bytes(b"private")
        (fake / "runtime.db").write_bytes(b"db")
        package, manifest = build_release_package(fake, phase="selftest")
        verified = verify_release_package_bytes(package)
        checks.append(result(
            "release_secret_exclusion",
            verified.get("valid") is True and manifest.get("entry_count") == 1,
            f"entries={manifest.get('entry_count')} verify={verified.get('valid')}",
        ))

        source = io.BytesIO(package)
        modified = io.BytesIO()
        with zipfile.ZipFile(source, "r") as original, zipfile.ZipFile(modified, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for info in original.infolist():
                archive.writestr(info, original.read(info.filename))
            archive.writestr("unmanifested-extra.txt", b"extra")
        extra_check = verify_release_package_bytes(modified.getvalue())
        detail = extra_check.get("checks", [{}])[0].get("detail", "")
        checks.append(result(
            "release_exact_member_set",
            extra_check.get("valid") is False and "exactly match manifest" in detail,
            detail,
        ))

    payload = {
        "schema": "veilgraph.phase2-security-selftest.v2",
        "checks": checks,
        "passed": sum(1 for item in checks if item["passed"]),
        "total": len(checks),
        "all_passed": all(item["passed"] for item in checks),
    }
    out = ROOT / "competition/phase2/PHASE2_SECURITY_RESULTS.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"Wrote {out}")
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
