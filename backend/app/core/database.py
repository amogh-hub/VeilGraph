from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or settings.database_path)
        self._lock = threading.RLock()
        self.init_schema()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def init_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    audience_profile TEXT NOT NULL DEFAULT 'PUBLIC_RELEASE',
                    privacy_level INTEGER NOT NULL,
                    retention_seconds INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    original_filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    encrypted_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    page_count INTEGER NOT NULL DEFAULT 0,
                    scanned_pages INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS canonical_entities (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    entity_type TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    placeholder TEXT NOT NULL,
                    sensitivity TEXT NOT NULL,
                    transformation TEXT NOT NULL,
                    UNIQUE(job_id, file_id, fingerprint)
                );

                CREATE TABLE IF NOT EXISTS mentions (
                    id TEXT PRIMARY KEY,
                    canonical_entity_id TEXT NOT NULL REFERENCES canonical_entities(id) ON DELETE CASCADE,
                    page_index INTEGER NOT NULL,
                    page_char_start INTEGER NOT NULL,
                    page_char_end INTEGER NOT NULL,
                    x0 REAL NOT NULL,
                    y0 REAL NOT NULL,
                    x1 REAL NOT NULL,
                    y1 REAL NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    context_label TEXT,
                    UNIQUE(canonical_entity_id, page_index, x0, y0, x1, y1, source)
                );

                CREATE TABLE IF NOT EXISTS outputs (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    encrypted_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    download_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    verification_json TEXT,
                    created_at TEXT NOT NULL,
                    verified_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    UNIQUE(job_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS proof_certificates (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    output_id TEXT NOT NULL REFERENCES outputs(id) ON DELETE CASCADE,
                    certificate_json TEXT NOT NULL,
                    certificate_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(output_id)
                );

                CREATE TABLE IF NOT EXISTS destruction_receipts (
                    job_id TEXT PRIMARY KEY,
                    trigger TEXT NOT NULL,
                    audit_integrity_valid INTEGER NOT NULL,
                    receipt_json TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            # Safe in-place migration for users who point Slice C at a prior database.
            if "audience_profile" not in self._columns(conn, "jobs"):
                conn.execute("ALTER TABLE jobs ADD COLUMN audience_profile TEXT NOT NULL DEFAULT 'PUBLIC_RELEASE'")
            if "context_label" not in self._columns(conn, "mentions"):
                conn.execute("ALTER TABLE mentions ADD COLUMN context_label TEXT")

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.connection() as conn:
            conn.execute(sql, params)

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def insert_job(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO jobs
            (id,purpose,recipient,audience_profile,privacy_level,retention_seconds,status,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["purpose"], row["recipient"], row["audience_profile"],
                row["privacy_level"], row["retention_seconds"], row["status"], row["created_at"], row["updated_at"],
            ),
        )

    def update_job_status(self, job_id: str, status: str) -> None:
        self.execute("UPDATE jobs SET status=?, updated_at=? WHERE id=?", (status, utc_now(), job_id))

    def insert_file(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO files
            (id,job_id,original_filename,file_type,media_type,encrypted_name,sha256,page_count,scanned_pages,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["job_id"], row["original_filename"], row["file_type"],
                row["media_type"], row["encrypted_name"], row["sha256"], row["page_count"],
                row["scanned_pages"], row["status"], row["created_at"],
            ),
        )

    def insert_canonical_entity(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO canonical_entities
            (id,job_id,file_id,entity_type,fingerprint,placeholder,sensitivity,transformation)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["job_id"], row["file_id"], row["entity_type"], row["fingerprint"],
                row["placeholder"], row["sensitivity"], row["transformation"],
            ),
        )

    def insert_mention(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT OR IGNORE INTO mentions
            (id,canonical_entity_id,page_index,page_char_start,page_char_end,x0,y0,x1,y1,confidence,source,review_status,context_label)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["canonical_entity_id"], row["page_index"], row["page_char_start"],
                row["page_char_end"], row["x0"], row["y0"], row["x1"], row["y1"],
                row["confidence"], row["source"], row["review_status"], row.get("context_label"),
            ),
        )

    def insert_output(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO outputs
            (id,job_id,file_id,encrypted_name,sha256,media_type,download_name,status,manifest_json,verification_json,created_at,verified_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["job_id"], row["file_id"], row["encrypted_name"], row["sha256"],
                row["media_type"], row["download_name"], row["status"], json.dumps(row["manifest"], sort_keys=True),
                row.get("verification_json"), row["created_at"], row.get("verified_at"),
            ),
        )

    def update_output_verification(
        self, output_id: str, status: str, verification: dict[str, Any], verified_at: str | None = None
    ) -> None:
        self.execute(
            "UPDATE outputs SET status=?, verification_json=?, verified_at=? WHERE id=?",
            (status, json.dumps(verification, sort_keys=True), verified_at or utc_now(), output_id),
        )

    @staticmethod
    def decode_json(value: str) -> dict[str, Any]:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}

    def insert_audit_event(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO audit_events
            (job_id,sequence,event_type,timestamp,details_json,prev_hash,event_hash)
            VALUES (?,?,?,?,?,?,?)""",
            (
                row["job_id"], row["sequence"], row["event_type"], row["timestamp"],
                json.dumps(row["details"], sort_keys=True, separators=(",", ":")),
                row["prev_hash"], row["event_hash"],
            ),
        )

    def upsert_certificate(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO proof_certificates
            (id,job_id,output_id,certificate_json,certificate_sha256,created_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(output_id) DO UPDATE SET
              id=excluded.id, certificate_json=excluded.certificate_json,
              certificate_sha256=excluded.certificate_sha256, created_at=excluded.created_at""",
            (
                row["id"], row["job_id"], row["output_id"],
                json.dumps(row["certificate"], sort_keys=True), row["certificate_sha256"], row["created_at"],
            ),
        )

    def store_destruction_receipt(
        self,
        *,
        job_id: str,
        trigger: str,
        audit_integrity_valid: bool,
        receipt: dict[str, Any],
    ) -> None:
        canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        import hashlib
        receipt_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.execute(
            """INSERT INTO destruction_receipts
            (job_id,trigger,audit_integrity_valid,receipt_json,receipt_sha256,created_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(job_id) DO NOTHING""",
            (job_id, trigger, int(audit_integrity_valid), canonical, receipt_sha256, utc_now()),
        )

    def destroy_job_rows(self, job_id: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self.connection() as conn:
            for table, clause in [
                ("proof_certificates", "job_id=?"),
                ("audit_events", "job_id=?"),
                ("mentions", "canonical_entity_id IN (SELECT id FROM canonical_entities WHERE job_id=?)"),
                ("canonical_entities", "job_id=?"),
                ("outputs", "job_id=?"),
                ("files", "job_id=?"),
            ]:
                count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", (job_id,)).fetchone()[0]
                conn.execute(f"DELETE FROM {table} WHERE {clause}", (job_id,))
                counts[table] = count
            # Keep only a non-sensitive lifecycle tombstone. Purpose and recipient
            # are intentionally scrubbed after destruction so retention expiry does
            # not leave release-intent metadata behind in the persistent database.
            conn.execute(
                "UPDATE jobs SET purpose=?, recipient=?, status=?, updated_at=? WHERE id=?",
                ("[ERASED]", "[ERASED]", "DESTROYED", utc_now(), job_id),
            )
        return counts


db = Database()
