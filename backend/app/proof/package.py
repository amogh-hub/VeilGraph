from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.security.signing import (
    canonical_json_bytes,
    public_key_b64,
    sign_payload,
    signer_fingerprint,
    verify_payload,
)

BUNDLE_RECEIPT_SCHEMA = "veilgraph.bundle-receipt.v1"
GENESIS_HASH = "0" * 64


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _certificate_sha256(certificate: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(certificate)).hexdigest()


def issue_bundle_receipt(
    *,
    bundle_sha256: str,
    bundle_size_bytes: int,
    certificate: dict[str, Any],
    audit_snapshot: dict[str, Any],
) -> dict[str, Any]:
    cert_payload = certificate["payload"]
    issued_at = datetime.now(timezone.utc).isoformat()
    short = hashlib.sha256(
        f"{bundle_sha256}:{cert_payload['certificate_id']}:{issued_at}".encode("utf-8")
    ).hexdigest()[:16].upper()
    payload = {
        "schema": BUNDLE_RECEIPT_SCHEMA,
        "receipt_id": f"VGBR-{short}",
        "product": "VeilGraph",
        "product_version": settings.version,
        "issued_at": issued_at,
        "certificate_id": str(cert_payload["certificate_id"]),
        "certificate_sha256": _certificate_sha256(certificate),
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": int(bundle_size_bytes),
        "output_sha256": str(cert_payload["output_sha256"]),
        "manifest_sha256": str(cert_payload["manifest_sha256"]),
        "graph_sha256": str(cert_payload["graph_sha256"]),
        "verification_sha256": str(cert_payload["verification_sha256"]),
        "audit_head_after_export": str(audit_snapshot.get("chain_head", "")),
        "audit_events_after_export": int(audit_snapshot.get("event_count", 0)),
        "signer": {
            "algorithm": "Ed25519",
            "public_key_b64": public_key_b64(),
            "public_key_sha256": signer_fingerprint(),
        },
        "scope_note": (
            "This signed receipt commits to the exact inner proof-bundle ZIP bytes. "
            "It deliberately does not hash the outer proof package, avoiding circular self-reference."
        ),
    }
    return {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": sign_payload(payload),
    }


def verify_bundle_receipt(receipt: dict[str, Any]) -> bool:
    try:
        payload = receipt["payload"]
        if receipt.get("signature_algorithm") != "Ed25519":
            return False
        return verify_payload(payload, receipt["signature_b64"], payload["signer"]["public_key_b64"])
    except Exception:
        return False


def verify_audit_snapshot(ledger: dict[str, Any]) -> tuple[bool, str]:
    events = ledger.get("events")
    if not isinstance(events, list):
        return False, "Audit ledger events are missing"
    expected_prev = GENESIS_HASH
    expected_sequence = 1
    for event in events:
        try:
            sequence = int(event["sequence"])
            event_type = str(event["event_type"])
            timestamp = str(event["timestamp"])
            details = event["details"]
            prev_hash = str(event["prev_hash"])
            event_hash = str(event["event_hash"])
        except Exception:
            return False, "Audit ledger event is malformed"
        if sequence != expected_sequence:
            return False, f"Audit sequence discontinuity at {sequence}"
        if prev_hash != expected_prev:
            return False, f"Audit previous-hash mismatch at {sequence}"
        body = {
            "sequence": sequence,
            "event_type": event_type,
            "timestamp": timestamp,
            "details": details,
            "prev_hash": prev_hash,
        }
        recomputed = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        if recomputed != event_hash:
            return False, f"Audit event-hash mismatch at {sequence}"
        expected_prev = event_hash
        expected_sequence += 1
    head = events[-1]["event_hash"] if events else GENESIS_HASH
    if int(ledger.get("event_count", -1)) != len(events):
        return False, "Audit event_count does not match ledger length"
    if str(ledger.get("chain_head", "")) != head:
        return False, "Audit chain_head does not match final event"
    if ledger.get("valid") is False:
        return False, "Audit ledger marks itself invalid"
    return True, "Audit ledger hash chain is valid"


def verify_graph_hash(graph: dict[str, Any]) -> tuple[bool, str]:
    claimed = str(graph.get("graph_sha256", ""))
    if len(claimed) != 64:
        return False, "Graph SHA-256 is missing or malformed"
    payload = {key: value for key, value in graph.items() if key != "graph_sha256"}
    computed = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if computed != claimed:
        return False, "Identity Exposure Graph hash mismatch"
    return True, "Identity Exposure Graph hash is valid"


def build_proof_package(
    *,
    proof_bundle: bytes,
    certificate: dict[str, Any],
    bundle_receipt: dict[str, Any],
    export_audit_ledger: dict[str, Any],
) -> bytes:
    cert_id = certificate["payload"]["certificate_id"]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{cert_id}-proof-bundle.zip", proof_bundle)
        archive.writestr(
            "veilgraph-bundle-receipt.json",
            json.dumps(bundle_receipt, indent=2, sort_keys=True),
        )
        archive.writestr(
            "veilgraph-export-audit-ledger.json",
            json.dumps(export_audit_ledger, indent=2, sort_keys=True),
        )
        archive.writestr(
            "VERIFY_PACKAGE.txt",
            (
                f"VeilGraph complete proof package {cert_id}\n\n"
                "The signed bundle receipt hashes the exact inner proof-bundle ZIP.\n"
                "The export audit ledger includes the PROOF_BUNDLE_EXPORTED event whose bundle_sha256 must match the receipt.\n"
                "Run from the VeilGraph repository:\n"
                "  python3 scripts/verify_proof_package.py <this-proof-package.zip>\n\n"
                "A valid result independently checks the Ed25519 signatures, protected artifact, manifest, graph, "
                "verification payload, both audit snapshots, and exact inner bundle hash.\n"
            ),
        )
    return buffer.getvalue()




def _validate_zip_archive(archive: zipfile.ZipFile, *, label: str) -> tuple[bool, str]:
    infos = archive.infolist()
    if len(infos) > int(settings.max_proof_zip_entries):
        return False, f"{label} has too many entries ({len(infos)})"
    total_uncompressed = 0
    seen: set[str] = set()
    for info in infos:
        name = info.filename
        if not name or name in seen:
            return False, f"{label} contains an empty or duplicate member name"
        seen.add(name)
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if normalized.startswith("/") or any(part == ".." for part in parts) or "\x00" in normalized:
            return False, f"{label} contains an unsafe member path: {name}"
        # UNIX symlink bit inside external attributes. Proof archives should only
        # contain regular files/directories generated by VeilGraph.
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            return False, f"{label} contains a symbolic-link member: {name}"
        total_uncompressed += int(info.file_size)
        if total_uncompressed > int(settings.max_proof_uncompressed_bytes):
            return False, f"{label} exceeds the uncompressed-size safety limit"
        if info.compress_size > 0 and info.file_size > 1024 * 1024:
            ratio = info.file_size / info.compress_size
            if ratio > float(settings.max_proof_entry_compression_ratio):
                return False, f"{label} contains a suspicious compression ratio: {name}"
    return True, f"{label} archive limits and member paths are valid"

def _load_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    value = json.loads(archive.read(name))
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _check_index(inner: zipfile.ZipFile, index: dict[str, Any]) -> tuple[bool, str]:
    entries = index.get("entries")
    if not isinstance(entries, dict):
        return False, "Bundle index entries are missing"
    for name, expected in entries.items():
        if name not in inner.namelist():
            return False, f"Bundle index references missing file: {name}"
        actual = sha256_bytes(inner.read(name))
        if actual != expected:
            return False, f"Bundle index hash mismatch: {name}"
    return True, "Bundle index hashes are valid"


def verify_proof_package_bytes(package_bytes: bytes) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, valid: bool, detail: str) -> None:
        checks.append({"name": name, "valid": bool(valid), "detail": detail})

    if len(package_bytes) > int(settings.max_proof_package_bytes):
        record("package_size_limit", False, "Proof package exceeds configured compressed-size limit")
        return {"valid": False, "checks": checks}
    record("package_size_limit", True, "Proof package is within configured compressed-size limit")

    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes)) as outer:
            outer_ok, outer_detail = _validate_zip_archive(outer, label="Outer proof package")
            if not outer_ok:
                raise ValueError(outer_detail)
            receipt = _load_json(outer, "veilgraph-bundle-receipt.json")
            export_ledger = _load_json(outer, "veilgraph-export-audit-ledger.json")
            inner_names = [name for name in outer.namelist() if name.endswith("-proof-bundle.zip")]
            if len(inner_names) != 1:
                raise ValueError("Proof package must contain exactly one inner proof-bundle ZIP")
            inner_bytes = outer.read(inner_names[0])
    except Exception as exc:
        record("package_structure", False, str(exc))
        return {"valid": False, "checks": checks}

    record("package_structure", True, "Outer proof package structure is valid")
    receipt_valid = verify_bundle_receipt(receipt)
    record("bundle_receipt_signature", receipt_valid, "Signed bundle receipt is valid" if receipt_valid else "Signed bundle receipt is invalid")
    if not receipt_valid:
        return {"valid": False, "checks": checks}

    payload = receipt["payload"]
    actual_bundle_sha = sha256_bytes(inner_bytes)
    record(
        "bundle_sha256",
        actual_bundle_sha == payload.get("bundle_sha256"),
        "Inner proof-bundle hash matches signed receipt" if actual_bundle_sha == payload.get("bundle_sha256") else "Inner proof-bundle hash mismatch",
    )
    record(
        "bundle_size",
        len(inner_bytes) == int(payload.get("bundle_size_bytes", -1)),
        "Inner proof-bundle size matches signed receipt" if len(inner_bytes) == int(payload.get("bundle_size_bytes", -1)) else "Inner proof-bundle size mismatch",
    )

    ledger_ok, ledger_detail = verify_audit_snapshot(export_ledger)
    record("export_audit_ledger", ledger_ok, ledger_detail)
    if ledger_ok:
        record(
            "export_audit_receipt_binding",
            export_ledger.get("chain_head") == payload.get("audit_head_after_export")
            and int(export_ledger.get("event_count", -1)) == int(payload.get("audit_events_after_export", -2)),
            "Export audit checkpoint matches signed receipt",
        )
        matching_exports = [
            event for event in export_ledger.get("events", [])
            if event.get("event_type") == "PROOF_BUNDLE_EXPORTED"
            and event.get("details", {}).get("bundle_sha256") == actual_bundle_sha
            and event.get("details", {}).get("certificate_id") == payload.get("certificate_id")
        ]
        record(
            "export_event_binding",
            bool(matching_exports),
            "Export ledger commits to this exact bundle hash" if matching_exports else "No matching PROOF_BUNDLE_EXPORTED event",
        )

    try:
        with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
            inner_ok, inner_detail = _validate_zip_archive(inner, label="Inner proof bundle")
            if not inner_ok:
                raise ValueError(inner_detail)
            names = set(inner.namelist())
            required = {
                "veilgraph-certificate.json",
                "veilgraph-certificate.pdf",
                "veilgraph-audit-ledger.json",
                "veilgraph-verification.json",
                "veilgraph-manifest.json",
                "identity-exposure-graph.json",
                "veilgraph-bundle-index.json",
            }
            missing = sorted(required - names)
            if missing:
                raise ValueError("Inner proof bundle missing: " + ", ".join(missing))
            certificate = _load_json(inner, "veilgraph-certificate.json")
            manifest = _load_json(inner, "veilgraph-manifest.json")
            graph = _load_json(inner, "identity-exposure-graph.json")
            verification = _load_json(inner, "veilgraph-verification.json")
            cert_ledger = _load_json(inner, "veilgraph-audit-ledger.json")
            index = _load_json(inner, "veilgraph-bundle-index.json")
            annotation_manifest = (
                _load_json(inner, "veilgraph-annotation-manifest.json")
                if "veilgraph-annotation-manifest.json" in names
                else None
            )
            index_entries = index.get("entries")
            if not isinstance(index_entries, dict):
                raise ValueError("Bundle index entries are missing")
            output_sha256 = str(certificate.get("payload", {}).get("output_sha256", ""))
            if len(output_sha256) != 64:
                raise ValueError("Certificate output SHA-256 is missing or malformed")
            protected_names = [
                name
                for name, indexed_sha256 in index_entries.items()
                if name in names and str(indexed_sha256) == output_sha256
            ]
            if len(protected_names) != 1:
                raise ValueError(
                    "Inner proof bundle must contain exactly one output-hash-bound protected artifact"
                )
            protected_bytes = inner.read(protected_names[0])
            index_ok, index_detail = _check_index(inner, index)
    except Exception as exc:
        record("inner_bundle_structure", False, str(exc))
        return {"valid": False, "checks": checks}

    record("inner_bundle_structure", True, "Inner proof bundle contains all reproducibility artifacts")
    record("bundle_index", index_ok, index_detail)

    # Local import avoids a circular dependency during module import.
    from app.proof.certificate import verify_certificate

    cert_valid = verify_certificate(certificate)
    record("certificate_signature", cert_valid, "Ed25519 certificate signature is valid" if cert_valid else "Ed25519 certificate signature is invalid")
    cert_payload = certificate.get("payload", {})
    cert_sha = _certificate_sha256(certificate)
    record(
        "receipt_certificate_binding",
        cert_sha == payload.get("certificate_sha256") and cert_payload.get("certificate_id") == payload.get("certificate_id"),
        "Signed receipt matches embedded certificate",
    )
    artifact_sha = sha256_bytes(protected_bytes)
    record(
        "protected_artifact_hash",
        artifact_sha == cert_payload.get("output_sha256") == payload.get("output_sha256"),
        "Protected artifact SHA-256 matches certificate and receipt",
    )
    manifest_sha = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    record(
        "manifest_hash",
        manifest_sha == cert_payload.get("manifest_sha256") == payload.get("manifest_sha256"),
        "Manifest SHA-256 matches certificate and receipt",
    )
    if annotation_manifest is not None:
        from app.presentation.annotated_export import verify_annotation_evidence
        annotation_ok, annotation_detail = verify_annotation_evidence(
            annotation_manifest, str(cert_payload.get("output_sha256", ""))
        )
        record("annotation_manifest_integrity", annotation_ok, annotation_detail)
        record(
            "annotation_manifest_binding",
            manifest.get("annotation_evidence") == annotation_manifest,
            "Annotation manifest matches the certificate-bound release manifest"
            if manifest.get("annotation_evidence") == annotation_manifest
            else "Annotation manifest differs from the certificate-bound release manifest",
        )
    graph_ok, graph_detail = verify_graph_hash(graph)
    record("graph_internal_hash", graph_ok, graph_detail)
    record(
        "graph_certificate_binding",
        graph.get("graph_sha256") == cert_payload.get("graph_sha256") == payload.get("graph_sha256"),
        "Identity Exposure Graph hash matches certificate and receipt",
    )
    record(
        "manifest_graph_binding",
        manifest.get("identity_exposure_graph") == graph,
        "Manifest embeds the exact exported Identity Exposure Graph",
    )
    verification_sha = hashlib.sha256(canonical_json_bytes(verification)).hexdigest()
    record(
        "verification_hash",
        verification_sha == cert_payload.get("verification_sha256") == payload.get("verification_sha256"),
        "Verification payload SHA-256 matches certificate and receipt",
    )
    cert_ledger_ok, cert_ledger_detail = verify_audit_snapshot(cert_ledger)
    record("certification_audit_ledger", cert_ledger_ok, cert_ledger_detail)
    if cert_ledger_ok:
        cert_event_count = int(cert_payload.get("audit_events_at_certification", -1))
        cert_events = cert_ledger.get("events", [])
        checkpoint_ok = (
            cert_event_count >= 0
            and len(cert_events) >= cert_event_count
            and (
                (cert_event_count == 0 and cert_payload.get("audit_head_at_certification") == GENESIS_HASH)
                or (
                    cert_event_count > 0
                    and cert_events[cert_event_count - 1].get("event_hash")
                    == cert_payload.get("audit_head_at_certification")
                )
            )
        )
        record(
            "certificate_audit_binding",
            checkpoint_ok,
            "Certification checkpoint exists inside the exported audit chain"
            if checkpoint_ok else "Signed certification checkpoint is not present in exported audit chain",
        )

    valid = bool(checks) and all(item["valid"] for item in checks)
    return {
        "valid": valid,
        "certificate_id": cert_payload.get("certificate_id"),
        "bundle_sha256": actual_bundle_sha,
        "checks": checks,
    }
