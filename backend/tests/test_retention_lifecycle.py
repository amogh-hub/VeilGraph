from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from app.audit.ledger import append_event
from app.core.config import settings
from app.core.database import db, utc_now
from app.security.retention import destroy_unrecoverable_jobs_after_restart, sweep_expired_jobs
from app.security.signing import verify_payload


def _create_job(client, *, retention_seconds: int = 60) -> dict:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Short-lived judge evidence",
            "recipient": "NTRO evaluator",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
            "retention_seconds": retention_seconds,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _expire_job(job_id: str, *, seconds_ago: int = 120) -> None:
    created = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    db.execute("UPDATE jobs SET created_at=?, updated_at=? WHERE id=?", (created, created, job_id))


def test_job_exposes_absolute_retention_deadline(client):
    job = _create_job(client, retention_seconds=300)
    created = datetime.fromisoformat(job["created_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(job["expires_at"].replace("Z", "+00:00"))
    assert job["retention_seconds"] == 300
    assert int((expires - created).total_seconds()) == 300


def test_expired_job_is_automatically_erased_and_receipt_is_retrievable(client):
    job = _create_job(client, retention_seconds=60)
    job_id = job["id"]
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("secret.txt", b"Contact alice@example.org", "text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.text
    assert (settings.workspace_root / job_id).exists()

    _expire_job(job_id)
    expired = sweep_expired_jobs(now=datetime.now(timezone.utc))
    assert expired == [job_id]
    assert not (settings.workspace_root / job_id).exists()

    tombstone = client.get(f"/api/v1/jobs/{job_id}")
    assert tombstone.status_code == 200, tombstone.text
    assert tombstone.json()["status"] == "DESTROYED"
    assert tombstone.json()["purpose"] == "[ERASED]"
    assert tombstone.json()["recipient"] == "[ERASED]"

    receipt_response = client.get(f"/api/v1/jobs/{job_id}/destruction-receipt")
    assert receipt_response.status_code == 200, receipt_response.text
    destruction = receipt_response.json()
    assert destruction["trigger"] == "RETENTION_EXPIRED"
    receipt = destruction["destruction_receipt"]
    assert receipt["signature_valid"] is True
    assert receipt["payload"]["trigger"] == "RETENTION_EXPIRED"
    assert receipt["payload"]["audit_integrity_valid"] is True
    assert receipt["payload"]["retention_deadline"]
    assert destruction["deleted_database_rows"]["files"] == 1

    blocked = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("again.txt", b"should fail", "text/plain")},
    )
    assert blocked.status_code == 410


def test_retention_erasure_is_fail_safe_when_audit_is_tampered(client):
    job = _create_job(client, retention_seconds=60)
    job_id = job["id"]
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("secret.txt", b"Private 9000010001", "text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.text

    db.execute(
        "UPDATE audit_events SET details_json=? WHERE job_id=? AND sequence=1",
        ('{"tampered":true}', job_id),
    )
    _expire_job(job_id)
    expired = sweep_expired_jobs(now=datetime.now(timezone.utc))
    assert expired == [job_id]
    assert not (settings.workspace_root / job_id).exists()

    destruction = client.get(f"/api/v1/jobs/{job_id}/destruction-receipt").json()
    assert destruction["destruction_receipt"]["signature_valid"] is True
    assert destruction["destruction_receipt"]["payload"]["audit_integrity_valid"] is False
    assert "erasure proceeded fail-safe" in destruction["note"]


def test_restart_key_loss_erases_orphaned_ciphertext_and_persists_receipt(client):
    job_id = "restart-orphan-job"
    created = utc_now()
    db.insert_job(
        {
            "id": job_id,
            "purpose": "Restart test",
            "recipient": "Local",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
            "retention_seconds": 3600,
            "status": "CREATED",
            "created_at": created,
            "updated_at": created,
        }
    )
    append_event(job_id, "JOB_CREATED", {"test": True})
    orphan = settings.workspace_root / job_id
    orphan.mkdir(parents=True, exist_ok=False)
    (orphan / "cipher.bin").write_bytes(b"not-plaintext-ciphertext")

    destroyed = destroy_unrecoverable_jobs_after_restart()
    assert job_id in destroyed
    assert not orphan.exists()

    response = client.get(f"/api/v1/jobs/{job_id}/destruction-receipt")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["trigger"] == "PROCESS_RESTART_KEY_LOSS"
    assert payload["deleted_workspace_files"] == 1
    assert payload["destruction_receipt"]["signature_valid"] is True


def test_manual_destruction_receipt_is_persisted_and_idempotent(client):
    job = _create_job(client, retention_seconds=3600)
    job_id = job["id"]
    first = client.delete(f"/api/v1/jobs/{job_id}/destroy")
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["trigger"] == "MANUAL"
    assert first_body["destruction_receipt"]["signature_valid"] is True

    second = client.delete(f"/api/v1/jobs/{job_id}/destroy")
    assert second.status_code == 200, second.text
    assert second.json()["destruction_receipt"]["signature_b64"] == first_body["destruction_receipt"]["signature_b64"]

    persisted = client.get(f"/api/v1/jobs/{job_id}/destruction-receipt")
    assert persisted.status_code == 200
    assert persisted.json()["destruction_receipt"]["signature_b64"] == first_body["destruction_receipt"]["signature_b64"]


def test_lifespan_worker_executes_expiry_without_manual_sweep():
    import time
    from fastapi.testclient import TestClient
    from main import app

    previous_interval = settings.retention_sweep_seconds
    settings.retention_sweep_seconds = 1.0
    try:
        with TestClient(app) as live_client:
            job = _create_job(live_client, retention_seconds=60)
            job_id = job["id"]
            _expire_job(job_id)

            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                state = live_client.get(f"/api/v1/jobs/{job_id}")
                assert state.status_code == 200, state.text
                if state.json()["status"] == "DESTROYED":
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Retention worker did not destroy the expired job within 3 seconds")

            receipt = live_client.get(f"/api/v1/jobs/{job_id}/destruction-receipt")
            assert receipt.status_code == 200, receipt.text
            assert receipt.json()["trigger"] == "RETENTION_EXPIRED"
    finally:
        settings.retention_sweep_seconds = previous_interval
