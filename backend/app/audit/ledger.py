from __future__ import annotations

import hashlib
from typing import Any

from app.core.database import db, utc_now
from app.security.signing import canonical_json_bytes

GENESIS_HASH = "0" * 64


def _event_hash(sequence: int, event_type: str, timestamp: str, details: dict[str, Any], prev_hash: str) -> str:
    payload = {
        "sequence": sequence,
        "event_type": event_type,
        "timestamp": timestamp,
        "details": details,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def append_event(job_id: str, event_type: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    details = details or {}
    previous = db.fetchone(
        "SELECT sequence,event_hash FROM audit_events WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
        (job_id,),
    )
    sequence = int(previous["sequence"]) + 1 if previous else 1
    prev_hash = str(previous["event_hash"]) if previous else GENESIS_HASH
    timestamp = utc_now()
    event_hash = _event_hash(sequence, event_type, timestamp, details, prev_hash)
    row = {
        "job_id": job_id,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp": timestamp,
        "details": details,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
    }
    db.insert_audit_event(row)
    return row


def verify_ledger(job_id: str) -> dict[str, Any]:
    rows = db.fetchall("SELECT * FROM audit_events WHERE job_id=? ORDER BY sequence", (job_id,))
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    events: list[dict[str, Any]] = []
    valid = True
    error: str | None = None
    for row in rows:
        details = db.decode_json(row["details_json"])
        recomputed = _event_hash(
            int(row["sequence"]), str(row["event_type"]), str(row["timestamp"]), details, str(row["prev_hash"])
        )
        if int(row["sequence"]) != expected_sequence:
            valid = False
            error = f"Sequence discontinuity at event {row['sequence']}"
        elif str(row["prev_hash"]) != expected_prev:
            valid = False
            error = f"Previous-hash mismatch at event {row['sequence']}"
        elif recomputed != str(row["event_hash"]):
            valid = False
            error = f"Event-hash mismatch at event {row['sequence']}"
        events.append({
            "sequence": int(row["sequence"]),
            "event_type": str(row["event_type"]),
            "timestamp": str(row["timestamp"]),
            "details": details,
            "prev_hash": str(row["prev_hash"]),
            "event_hash": str(row["event_hash"]),
        })
        expected_prev = str(row["event_hash"])
        expected_sequence += 1
    return {
        "job_id": job_id,
        "valid": valid,
        "event_count": len(events),
        "chain_head": events[-1]["event_hash"] if events else GENESIS_HASH,
        "error": error,
        "events": events,
    }
