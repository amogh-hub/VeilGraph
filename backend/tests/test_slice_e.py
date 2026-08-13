from __future__ import annotations

import hashlib
import io
import json
import zipfile

from app.audit.ledger import append_event, verify_ledger
from app.core.database import db
from app.proof.certificate import issue_certificate, verify_certificate
from app.security.signing import public_key_b64, sign_payload, signer_fingerprint, verify_payload
from generate_identity_graph_document import build_identity_graph_pdf


def _create_level4_job(client) -> tuple[str, str]:
    created = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public research release",
            "recipient": "Evidence portal",
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
                review = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert review.status_code == 200, review.text
    return job_id, file_id


def _transform_level4(client, job_id: str, file_id: str) -> str:
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    return transformed.json()["output_id"]


def test_ed25519_device_signing_round_trip_and_tamper_detection():
    payload = {"proof": "veilgraph", "score": 100}
    signature = sign_payload(payload)
    assert verify_payload(payload, signature, public_key_b64())
    assert not verify_payload({"proof": "veilgraph", "score": 99}, signature, public_key_b64())
    assert len(signer_fingerprint()) == 64


def test_audit_ledger_hash_chain_detects_tampering(client):
    created = client.post(
        "/api/v1/jobs",
        json={"purpose": "Audit test", "recipient": "Local", "privacy_level": 4},
    )
    job_id = created.json()["id"]
    append_event(job_id, "TEST_EVENT", {"safe": True})
    assert verify_ledger(job_id)["valid"] is True
    db.execute(
        "UPDATE audit_events SET details_json=? WHERE job_id=? AND sequence=2",
        (json.dumps({"safe": False}), job_id),
    )
    checked = verify_ledger(job_id)
    assert checked["valid"] is False
    assert "hash" in (checked["error"] or "").casefold()


def test_certificate_is_unavailable_before_proof_gate(client):
    job_id, file_id = _create_level4_job(client)
    output_id = _transform_level4(client, job_id, file_id)
    response = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate")
    assert response.status_code == 423


def test_slice_e_verified_output_gets_signed_certificate_bundle_and_audit(client):
    job_id, file_id = _create_level4_job(client)
    output_id = _transform_level4(client, job_id, file_id)

    verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verification.status_code == 200, verification.text
    proof = verification.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["proof_score"] == 100
    assert proof["passed"] == 12

    cert_response = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate")
    assert cert_response.status_code == 200, cert_response.text
    certificate = cert_response.json()
    assert certificate["signature_valid"] is True
    assert certificate["payload"]["release_decision"] == "ALLOW_RELEASE"
    assert certificate["payload"]["proof_score"] == 100
    assert certificate["payload"]["signer"]["public_key_sha256"] == signer_fingerprint()
    assert verify_certificate({
        "payload": certificate["payload"],
        "signature_algorithm": certificate["signature_algorithm"],
        "signature_b64": certificate["signature_b64"],
    })

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    assert hashlib.sha256(downloaded.content).hexdigest() == certificate["payload"]["output_sha256"]

    pdf = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate.pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")

    bundle_response = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-bundle")
    assert bundle_response.status_code == 200, bundle_response.text
    with zipfile.ZipFile(io.BytesIO(bundle_response.content)) as archive:
        names = set(archive.namelist())
        assert "veilgraph-certificate.json" in names
        assert "veilgraph-certificate.pdf" in names
        assert "veilgraph-audit-ledger.json" in names
        assert "veilgraph-verification.json" in names
        embedded_cert = json.loads(archive.read("veilgraph-certificate.json"))
        assert verify_certificate(embedded_cert)
        artifact_name = next(name for name in names if name.endswith("-protected.pdf"))
        assert hashlib.sha256(archive.read(artifact_name)).hexdigest() == embedded_cert["payload"]["output_sha256"]

    audit = client.get(f"/api/v1/jobs/{job_id}/audit")
    assert audit.status_code == 200
    ledger = audit.json()
    assert ledger["valid"] is True
    event_types = [event["event_type"] for event in ledger["events"]]
    assert "VERIFICATION_COMPLETED" in event_types
    assert "PROOF_CERTIFICATE_ISSUED" in event_types
    assert "PROTECTED_ARTIFACT_DOWNLOADED" in event_types
    assert "PROOF_BUNDLE_EXPORTED" in event_types


def test_certificate_signature_detects_modified_certificate_payload():
    certificate = issue_certificate(
        job_id="job-test",
        output={"sha256": "a" * 64},
        manifest={
            "input_sha256": "b" * 64,
            "privacy_level": 4,
            "audience_profile": "PUBLIC_RELEASE",
            "identity_exposure_graph": {"graph_sha256": "c" * 64},
        },
        verification={
            "proof_score": 100,
            "attack_coverage": 12,
            "critical_failures": 0,
            "release_decision": "ALLOW_RELEASE",
            "risk_before": 100,
            "residual_risk": 37,
            "utility_score": 66,
        },
        verified_at="2026-08-07T00:00:00+00:00",
        audit_snapshot={"chain_head": "d" * 64, "event_count": 7},
    )
    assert verify_certificate(certificate)
    certificate["payload"]["proof_score"] = 99
    assert not verify_certificate(certificate)


def test_destroy_returns_signed_receipt_and_erases_audit_and_cert_rows(client):
    job_id, file_id = _create_level4_job(client)
    output_id = _transform_level4(client, job_id, file_id)
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.json()["status"] == "VERIFIED_SAFE"

    destroyed = client.delete(f"/api/v1/jobs/{job_id}/destroy")
    assert destroyed.status_code == 200, destroyed.text
    payload = destroyed.json()
    receipt = payload["destruction_receipt"]
    assert receipt["signature_valid"] is True
    assert verify_payload(
        receipt["payload"],
        receipt["signature_b64"],
        receipt["payload"]["signer"]["public_key_b64"],
    )
    assert receipt["payload"]["final_audit_event_count"] >= 8
    assert payload["deleted_database_rows"]["audit_events"] >= 1
    assert payload["deleted_database_rows"]["proof_certificates"] == 1
    assert db.fetchone("SELECT * FROM audit_events WHERE job_id=?", (job_id,)) is None
    assert db.fetchone("SELECT * FROM proof_certificates WHERE job_id=?", (job_id,)) is None
