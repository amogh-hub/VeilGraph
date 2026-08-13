from __future__ import annotations

import io
import json
import zipfile

from app.proof.package import verify_proof_package_bytes
from generate_identity_graph_document import build_identity_graph_pdf


def _verified_package(client) -> bytes:
    created = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Final hardening proof",
            "recipient": "Offline verifier",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
        },
    )
    assert created.status_code == 201, created.text
    job_id = created.json()["id"]
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("identity-graph.pdf", build_identity_graph_pdf(), "application/pdf")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    for item in client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json():
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                reviewed = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert reviewed.status_code == 200, reviewed.text
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verification.status_code == 200, verification.text
    assert verification.json()["status"] == "VERIFIED_SAFE", verification.json()
    package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert package.status_code == 200, package.text
    assert package.headers["content-type"].startswith("application/zip")
    assert len(package.headers["x-veilgraph-bundle-sha256"]) == 64
    assert package.headers["x-veilgraph-receipt-id"].startswith("VGBR-")
    return package.content


def _rewrite_zip(source: bytes, mutate) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(source), "r") as original, zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED
    ) as changed:
        for name in original.namelist():
            data = original.read(name)
            changed.writestr(name, mutate(name, data))
    return output.getvalue()


def _tamper_inner(package: bytes, mutate_inner) -> bytes:
    return _rewrite_zip(
        package,
        lambda name, data: _rewrite_zip(data, mutate_inner) if name.endswith("-proof-bundle.zip") else data,
    )


def test_complete_proof_package_recomputes_and_rejects_tamper_matrix(client):
    package = _verified_package(client)
    valid = verify_proof_package_bytes(package)
    assert valid["valid"] is True, valid
    assert all(check["valid"] for check in valid["checks"]), valid

    with zipfile.ZipFile(io.BytesIO(package)) as outer:
        inner_name = next(name for name in outer.namelist() if name.endswith("-proof-bundle.zip"))
        receipt = json.loads(outer.read("veilgraph-bundle-receipt.json"))
        assert receipt["payload"]["scope_note"].startswith("This signed receipt commits")
        with zipfile.ZipFile(io.BytesIO(outer.read(inner_name))) as inner:
            names = set(inner.namelist())
            assert {"veilgraph-manifest.json", "identity-exposure-graph.json", "veilgraph-bundle-index.json"}.issubset(names)
            manifest = json.loads(inner.read("veilgraph-manifest.json"))
            graph = json.loads(inner.read("identity-exposure-graph.json"))
            assert manifest["identity_exposure_graph"] == graph

    tampered_artifact = _tamper_inner(
        package,
        lambda name, data: data + b"TAMPERED-PROTECTED-ARTIFACT" if name.endswith("-protected.pdf") else data,
    )
    assert verify_proof_package_bytes(tampered_artifact)["valid"] is False

    def tamper_certificate(name: str, data: bytes) -> bytes:
        if name != "veilgraph-certificate.json":
            return data
        cert = json.loads(data)
        cert["payload"]["proof_score"] = 99
        return json.dumps(cert, indent=2, sort_keys=True).encode()

    assert verify_proof_package_bytes(_tamper_inner(package, tamper_certificate))["valid"] is False

    def tamper_manifest(name: str, data: bytes) -> bytes:
        if name != "veilgraph-manifest.json":
            return data
        manifest = json.loads(data)
        manifest["privacy_level"] = 1
        return json.dumps(manifest, indent=2, sort_keys=True).encode()

    assert verify_proof_package_bytes(_tamper_inner(package, tamper_manifest))["valid"] is False

    def tamper_graph(name: str, data: bytes) -> bytes:
        if name != "identity-exposure-graph.json":
            return data
        graph = json.loads(data)
        graph["risk"]["after"] = 0
        return json.dumps(graph, indent=2, sort_keys=True).encode()

    assert verify_proof_package_bytes(_tamper_inner(package, tamper_graph))["valid"] is False

    def tamper_export_ledger(name: str, data: bytes) -> bytes:
        if name != "veilgraph-export-audit-ledger.json":
            return data
        ledger = json.loads(data)
        ledger["events"][-1]["details"]["bundle_sha256"] = "0" * 64
        return json.dumps(ledger, indent=2, sort_keys=True).encode()

    audit_result = verify_proof_package_bytes(_rewrite_zip(package, tamper_export_ledger))
    assert audit_result["valid"] is False
    assert any(check["name"] == "export_audit_ledger" and not check["valid"] for check in audit_result["checks"])

    def tamper_receipt(name: str, data: bytes) -> bytes:
        if name != "veilgraph-bundle-receipt.json":
            return data
        receipt_value = json.loads(data)
        receipt_value["payload"]["bundle_size_bytes"] += 1
        return json.dumps(receipt_value, indent=2, sort_keys=True).encode()

    receipt_result = verify_proof_package_bytes(_rewrite_zip(package, tamper_receipt))
    assert receipt_result["valid"] is False
    assert any(check["name"] == "bundle_receipt_signature" and not check["valid"] for check in receipt_result["checks"])
