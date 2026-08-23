from __future__ import annotations

import asyncio
import io
import json
import os
import socket
import stat
import uuid
import zipfile
from pathlib import Path

import pytest

from app.ops.admission import AdmissionController, is_heavy_request
from app.ops.metrics import RuntimeMetrics, normalize_metric_path, percentile, runtime_metrics
from app.proof.package import verify_proof_package_bytes
from app.security.deployment import authorize_request, validate_online_configuration
from app.security.network_guard import (
    disable_egress_guard_for_tests,
    install_egress_guard,
)
from app.security.release_package import build_release_package, verify_release_package_bytes
from app.security.workspace import WorkspaceError, create_workspace, destroy_workspace


def test_metrics_remove_high_cardinality_job_ids_and_do_not_store_payloads():
    job_id = "123e4567-e89b-12d3-a456-426614174000"
    normalized = normalize_metric_path(f"/api/v1/jobs/{job_id}/files/{job_id}/analyse")
    assert job_id not in normalized
    assert "{id}" in normalized
    metrics = RuntimeMetrics(window=64)
    token = metrics.begin(normalized)
    metrics.end(token, 200)
    snap = metrics.snapshot()
    assert snap["requests_total"] == 1
    assert snap["privacy"]["stores_request_bodies"] is False
    assert snap["privacy"]["stores_job_ids"] is False
    assert snap["latency_ms"]["window_capacity"] == 64


def test_global_runtime_metrics_honors_configured_window():
    from app.core.config import settings
    assert runtime_metrics.snapshot()["latency_ms"]["window_capacity"] == max(64, settings.ops_metrics_window)


def test_percentile_is_deterministic():
    values = [1, 2, 3, 4, 5]
    assert percentile(values, 0.5) == 3
    assert percentile(values, 0.95) == 5


def test_heavy_operation_classifier_is_narrow():
    assert is_heavy_request("POST", "/api/v1/jobs/x/files/y/analyse")
    assert is_heavy_request("POST", "/api/v1/jobs/x/files/y/transform")
    assert is_heavy_request("POST", "/api/v1/jobs/x/outputs/y/verify")
    assert is_heavy_request("POST", "/api/v1/jobs/x/files")
    assert not is_heavy_request("GET", "/api/v1/ops/status")


def test_admission_controller_never_exceeds_configured_limit():
    async def scenario():
        controller = AdmissionController(2, 1.0)
        active = 0
        peak = 0
        lock = asyncio.Lock()

        async def worker():
            nonlocal active, peak
            async with controller.slot():
                async with lock:
                    active += 1
                    peak = max(peak, active)
                await asyncio.sleep(0.02)
                async with lock:
                    active -= 1

        await asyncio.gather(*(worker() for _ in range(6)))
        assert peak <= 2
        assert controller.snapshot()["max_active"] <= 2

    asyncio.run(scenario())


def test_secure_online_configuration_fails_closed_without_long_token_https_or_proxy_allowlist():
    with pytest.raises(RuntimeError):
        validate_online_configuration(offline_mode=False, api_token=None, require_https=True)
    with pytest.raises(RuntimeError):
        validate_online_configuration(offline_mode=False, api_token="x" * 40, require_https=False)
    with pytest.raises(RuntimeError):
        validate_online_configuration(
            offline_mode=False, api_token="x" * 40, require_https=True,
            trust_proxy_headers=True, trusted_proxy_networks=(),
        )
    with pytest.raises(RuntimeError):
        validate_online_configuration(
            offline_mode=False, api_token="x" * 40, require_https=True,
            trust_proxy_headers=True, trusted_proxy_networks=("0.0.0.0/0",),
        )
    validate_online_configuration(offline_mode=False, api_token="x" * 40, require_https=True)
    validate_online_configuration(
        offline_mode=False, api_token="x" * 40, require_https=True,
        trust_proxy_headers=True, trusted_proxy_networks=("10.0.0.0/24",),
    )


def test_offline_and_secure_online_request_boundary():
    assert authorize_request(
        offline_mode=True, client_host="127.0.0.1", headers={}, url_scheme="http",
        configured_token=None, require_https=True,
    ).allowed
    assert not authorize_request(
        offline_mode=True, client_host="10.0.0.8", headers={}, url_scheme="http",
        configured_token=None, require_https=True,
    ).allowed
    token = "A" * 40
    assert not authorize_request(
        offline_mode=False, client_host="10.0.0.8", headers={"authorization": f"Bearer {token}"},
        url_scheme="http", configured_token=token, require_https=True,
    ).allowed
    # A direct client may not upgrade itself to HTTPS by spoofing a proxy header.
    spoofed = authorize_request(
        offline_mode=False, client_host="10.0.0.8",
        headers={"authorization": f"Bearer {token}", "x-forwarded-proto": "https"},
        url_scheme="http", configured_token=token, require_https=True,
    )
    assert not spoofed.allowed and spoofed.status_code == 426
    # Forwarded HTTPS is accepted only when proxy-header trust is explicitly enabled
    # and the immediate peer is inside an explicit trusted proxy network.
    trusted = authorize_request(
        offline_mode=False, client_host="10.0.0.8",
        headers={"authorization": f"Bearer {token}", "x-forwarded-proto": "https"},
        url_scheme="http", configured_token=token, require_https=True,
        trust_proxy_headers=True, trusted_proxy_networks=("10.0.0.0/24",),
    )
    assert trusted.allowed
    untrusted = authorize_request(
        offline_mode=False, client_host="10.0.1.8",
        headers={"authorization": f"Bearer {token}", "x-forwarded-proto": "https"},
        url_scheme="http", configured_token=token, require_https=True,
        trust_proxy_headers=True, trusted_proxy_networks=("10.0.0.0/24",),
    )
    assert not untrusted.allowed and untrusted.status_code == 426


def test_offline_egress_guard_blocks_external_hostname_before_dns():
    disable_egress_guard_for_tests()
    install_egress_guard()
    try:
        with pytest.raises(OSError, match="blocked"):
            socket.create_connection(("example.invalid", 443), timeout=0.01)
    finally:
        disable_egress_guard_for_tests()


def test_workspace_permissions_and_symlink_read_fail_closed(tmp_path, monkeypatch):
    from app.core.config import settings
    previous = settings.workspace_root
    settings.workspace_root = tmp_path
    job_id = f"phase2-{uuid.uuid4()}"
    workspace = create_workspace(job_id)
    try:
        workspace.write_encrypted("blob.vgenc", b"sensitive")
        assert stat.S_IMODE(workspace.path.stat().st_mode) == 0o700
        blob = workspace.path / "blob.vgenc"
        assert stat.S_IMODE(blob.stat().st_mode) == 0o600
        blob.unlink()
        target = tmp_path / "outside.bin"
        target.write_bytes(b"not encrypted")
        blob.symlink_to(target)
        with pytest.raises(WorkspaceError):
            workspace.read_encrypted("blob.vgenc")
    finally:
        destroy_workspace(job_id)
        settings.workspace_root = previous


def test_proof_package_verifier_rejects_path_traversal_member():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escape", b"x")
        archive.writestr("veilgraph-bundle-receipt.json", "{}")
        archive.writestr("veilgraph-export-audit-ledger.json", "{}")
    result = verify_proof_package_bytes(buffer.getvalue())
    assert result["valid"] is False
    assert any("unsafe member path" in item["detail"] for item in result["checks"])


def test_sanitized_release_excludes_runtime_secrets_and_database(tmp_path):
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend/app.py").write_text("print('ok')\n")
    (tmp_path / ".veilgraph").mkdir()
    (tmp_path / ".veilgraph/device-ed25519.key").write_bytes(b"PRIVATE")
    (tmp_path / "state.db").write_bytes(b"sqlite")
    (tmp_path / ".env").write_text("TOKEN=secret")
    package, manifest = build_release_package(tmp_path, phase="test")
    assert manifest["entry_count"] == 1
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        names = archive.namelist()
        assert "backend/app.py" in names
        assert not any(".veilgraph" in name for name in names)
        assert "state.db" not in names
        assert ".env" not in names
    assert verify_release_package_bytes(package)["valid"] is True


def test_sanitized_release_verifier_rejects_unmanifested_extra_member():
    package, _ = build_release_package(Path(__file__).resolve().parents[1], phase="test")
    source = io.BytesIO(package)
    rewritten = io.BytesIO()
    with zipfile.ZipFile(source, "r") as original, zipfile.ZipFile(rewritten, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for info in original.infolist():
            archive.writestr(info, original.read(info.filename))
        archive.writestr("unmanifested-extra.txt", b"not listed in release manifest")
    result = verify_release_package_bytes(rewritten.getvalue())
    assert result["valid"] is False
    assert "exactly match manifest" in result["checks"][0]["detail"]


def test_sanitized_release_verifier_rejects_private_key_marker():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("oops.txt", b"-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        archive.writestr("veilgraph-release-manifest.json", json.dumps({"entries": {}, "entry_count": 0}))
    assert verify_release_package_bytes(buffer.getvalue())["valid"] is False


def test_ops_status_is_pii_free_and_security_headers_are_present(client):
    response = client.get("/api/v1/ops/status")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["deployment"]["external_model_calls"] is False
    assert payload["metrics"]["privacy"]["stores_request_bodies"] is False
    assert payload["metrics"]["privacy"]["stores_query_strings"] is False
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "camera=()" in response.headers["permissions-policy"]
    assert response.headers["cache-control"] == "no-store"
