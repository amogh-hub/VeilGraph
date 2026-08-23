from __future__ import annotations

import asyncio
import json
import threading
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Any

from app.audit.ledger import GENESIS_HASH, append_event, verify_ledger
from app.core.config import settings
from app.core.database import db, utc_now
from app.core.enums import JobStatus
from app.proof.certificate import issue_destruction_receipt
from app.security.signing import canonical_json_bytes, verify_payload
from app.security.workspace import destroy_workspace

_TRIGGER_EVENTS = {
    "MANUAL": "DESTRUCTION_REQUESTED",
    "RETENTION_EXPIRED": "RETENTION_EXPIRED",
    "PROCESS_RESTART_KEY_LOSS": "PROCESS_RESTART_KEY_LOSS",
}
_destroy_lock = threading.RLock()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def retention_deadline(job: dict[str, Any]) -> datetime:
    return _parse_utc(str(job["created_at"])) + timedelta(seconds=int(job["retention_seconds"]))


def retention_deadline_iso(job: dict[str, Any]) -> str:
    return retention_deadline(job).isoformat()


def _response_from_receipt_row(row: dict[str, Any]) -> dict[str, Any]:
    receipt = json.loads(str(row["receipt_json"]))
    payload = receipt["payload"]
    return {
        "job_id": str(row["job_id"]),
        "status": JobStatus.DESTROYED.value,
        "trigger": str(payload.get("trigger", row.get("trigger", "UNKNOWN"))),
        "deleted_workspace_files": int(payload.get("deleted_workspace_files", 0)),
        "cleared_plaintext_entities": int(payload.get("cleared_plaintext_entities", 0)),
        "destroyed_outputs": int(payload.get("destroyed_outputs", 0)),
        "deleted_database_rows": dict(payload.get("deleted_database_rows", {})),
        "note": str(payload.get("scope_note", "")),
        "destruction_receipt": {
            **receipt,
            "signature_valid": verify_payload(
                receipt["payload"],
                receipt["signature_b64"],
                receipt["payload"]["signer"]["public_key_b64"],
            ),
        },
    }


def stored_destruction_response(job_id: str) -> dict[str, Any] | None:
    row = db.fetchone("SELECT * FROM destruction_receipts WHERE job_id=?", (job_id,))
    return _response_from_receipt_row(row) if row else None


def destroy_job_with_receipt(job_id: str, *, trigger: str = "MANUAL") -> dict[str, Any]:
    """Cryptographically erase one job and persist a signed destruction tombstone.

    Retention-triggered erasure is privacy-first: an invalid audit ledger must never
    prevent encrypted blobs and in-memory keys from being destroyed. The signed
    tombstone records whether the audit chain was valid at destruction time.
    """
    if trigger not in _TRIGGER_EVENTS:
        raise ValueError(f"Unsupported destruction trigger: {trigger}")

    with _destroy_lock:
        existing = stored_destruction_response(job_id)
        if existing is not None:
            return existing

        job = db.fetchone("SELECT * FROM jobs WHERE id=?", (job_id,))
        if job is None:
            raise KeyError(job_id)

        if str(job["status"]) == JobStatus.DESTROYED.value:
            raise RuntimeError("Destroyed job has no persisted destruction receipt")

        deadline = retention_deadline_iso(job)
        output_count_row = db.fetchone("SELECT COUNT(*) AS count FROM outputs WHERE job_id=?", (job_id,))
        output_count = int(output_count_row["count"] if output_count_row else 0)

        audit_valid = False
        audit_head = GENESIS_HASH
        audit_count = 0
        try:
            append_event(
                job_id,
                _TRIGGER_EVENTS[trigger],
                {
                    "trigger": trigger,
                    "outputs_present": output_count,
                    "retention_seconds": int(job["retention_seconds"]),
                    "retention_deadline": deadline,
                },
            )
            audit_snapshot = verify_ledger(job_id)
            audit_valid = bool(audit_snapshot["valid"])
            audit_head = str(audit_snapshot["chain_head"])
            audit_count = int(audit_snapshot["event_count"])
        except Exception:
            # Privacy erasure continues even when audit persistence/verification is
            # damaged. The resulting signed tombstone explicitly records false.
            audit_valid = False

        workspace_report = destroy_workspace(job_id)
        if not audit_valid:
            workspace_report = {
                **workspace_report,
                "note": (
                    f"{workspace_report.get('note', '')} Audit integrity was not valid at destruction time; "
                    "erasure proceeded fail-safe and the signed tombstone records that condition."
                ).strip(),
            }

        deleted_rows = db.destroy_job_rows(job_id)
        receipt = issue_destruction_receipt(
            job_id=job_id,
            final_audit_head=audit_head,
            final_event_count=audit_count,
            workspace_report=workspace_report,
            deleted_rows=deleted_rows,
            destroyed_outputs=output_count,
            trigger=trigger,
            audit_integrity_valid=audit_valid,
            retention_deadline=deadline,
        )
        receipt_valid = verify_payload(
            receipt["payload"], receipt["signature_b64"], receipt["payload"]["signer"]["public_key_b64"]
        )
        if not receipt_valid:
            raise RuntimeError("Generated destruction receipt failed Ed25519 self-verification")

        db.store_destruction_receipt(
            job_id=job_id,
            trigger=trigger,
            audit_integrity_valid=audit_valid,
            receipt=receipt,
        )
        response = stored_destruction_response(job_id)
        if response is None:
            raise RuntimeError("Destruction receipt persistence failed")
        return response


def sweep_expired_jobs(*, now: datetime | None = None) -> list[str]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expired: list[str] = []
    rows = db.fetchall("SELECT * FROM jobs WHERE status<>? ORDER BY created_at", (JobStatus.DESTROYED.value,))
    for job in rows:
        if retention_deadline(job) <= current:
            destroy_job_with_receipt(str(job["id"]), trigger="RETENTION_EXPIRED")
            expired.append(str(job["id"]))
    return expired


def destroy_unrecoverable_jobs_after_restart() -> list[str]:
    """Erase jobs left from a previous process because their RAM-only keys are gone."""
    destroyed: list[str] = []
    rows = db.fetchall("SELECT id FROM jobs WHERE status<>? ORDER BY created_at", (JobStatus.DESTROYED.value,))
    for row in rows:
        job_id = str(row["id"])
        destroy_job_with_receipt(job_id, trigger="PROCESS_RESTART_KEY_LOSS")
        destroyed.append(job_id)
    return destroyed


async def retention_worker() -> None:
    interval = max(1.0, float(settings.retention_sweep_seconds))
    while True:
        sweep_expired_jobs()
        await asyncio.sleep(interval)


async def stop_retention_worker(task: asyncio.Task[None] | None) -> None:
    if task is None:
        return
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
