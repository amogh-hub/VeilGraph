from __future__ import annotations

import hashlib
import io
import json
import textwrap
import zipfile
from datetime import datetime, timezone
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from app.core.config import settings
from app.security.signing import (
    canonical_json_bytes,
    public_key_b64,
    sign_payload,
    signer_fingerprint,
    verify_payload,
)

CERTIFICATE_SCHEMA = "veilgraph.proof-certificate.v1"
DESTRUCTION_SCHEMA = "veilgraph.destruction-receipt.v2"


def _sha(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def issue_certificate(
    *,
    job_id: str,
    output: dict[str, Any],
    manifest: dict[str, Any],
    verification: dict[str, Any],
    verified_at: str,
    audit_snapshot: dict[str, Any],
) -> dict[str, Any]:
    graph = manifest.get("identity_exposure_graph", {})
    graph_sha = str(graph.get("graph_sha256", ""))
    manifest_sha = _sha(manifest)
    verification_sha = _sha(verification)
    job_commitment = hashlib.sha256(job_id.encode("utf-8")).hexdigest()
    output_sha = str(output["sha256"])
    issued_at = datetime.now(timezone.utc).isoformat()
    cert_short = hashlib.sha256(f"{output_sha}:{verified_at}".encode("utf-8")).hexdigest()[:16].upper()
    payload = {
        "schema": CERTIFICATE_SCHEMA,
        "certificate_id": f"VG-{cert_short}",
        "product": "VeilGraph",
        "product_version": settings.version,
        "issued_at": issued_at,
        "verified_at": verified_at,
        "job_commitment_sha256": job_commitment,
        "output_sha256": output_sha,
        "input_sha256": str(manifest.get("input_sha256", "")),
        "manifest_sha256": manifest_sha,
        "graph_sha256": graph_sha,
        "verification_sha256": verification_sha,
        "privacy_level": int(manifest.get("privacy_level", 0)),
        "audience_profile": str(manifest.get("audience_profile", "")),
        "proof_score": int(verification.get("proof_score", 0)),
        "attack_coverage": int(verification.get("attack_coverage", 0)),
        "critical_failures": int(verification.get("critical_failures", 0)),
        "release_decision": str(verification.get("release_decision", "BLOCK_RELEASE")),
        "risk_before": int(verification.get("risk_before", 0)),
        "residual_risk": int(verification.get("residual_risk", 0)),
        "utility_score": int(verification.get("utility_score", 0)),
        "audit_head_at_certification": str(audit_snapshot.get("chain_head", "")),
        "audit_events_at_certification": int(audit_snapshot.get("event_count", 0)),
        "signer": {
            "algorithm": "Ed25519",
            "public_key_b64": public_key_b64(),
            "public_key_sha256": signer_fingerprint(),
        },
        "disclaimer": (
            "This certificate proves VeilGraph's listed local checks and artifact hashes for this output. "
            "It is not a legal or mathematical guarantee of anonymity against every external dataset or future attack."
        ),
    }
    signature = sign_payload(payload)
    return {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": signature,
    }


def verify_certificate(certificate: dict[str, Any]) -> bool:
    try:
        payload = certificate["payload"]
        return verify_payload(payload, certificate["signature_b64"], payload["signer"]["public_key_b64"])
    except Exception:
        return False


def certificate_pdf(certificate: dict[str, Any], verification: dict[str, Any]) -> bytes:
    payload = certificate["payload"]
    stream = io.BytesIO()
    pdf = canvas.Canvas(stream, pagesize=A4, pageCompression=1)
    width, height = A4

    def text_line(value: str, y: float, size: int = 9, bold: bool = False) -> float:
        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        pdf.drawString(20 * mm, y, value)
        return y - 5.2 * mm

    y = height - 22 * mm
    pdf.setFont("Helvetica-Bold", 21)
    pdf.drawString(20 * mm, y, "VeilGraph Privacy Proof Certificate")
    y -= 10 * mm
    pdf.setFont("Helvetica", 9)
    pdf.drawString(20 * mm, y, "Offline-signed evidence for a proof-gated protected artifact")
    y -= 10 * mm
    y = text_line(f"Certificate ID: {payload['certificate_id']}", y, 10, True)
    y = text_line(f"Release decision: {payload['release_decision']}", y, 10, True)
    y = text_line(f"Proof score: {payload['proof_score']}/100 · Attacks: {payload['attack_coverage']} · Critical blockers: {payload['critical_failures']}", y)
    y = text_line(f"Exposure: {payload['risk_before']} → {payload['residual_risk']} · Utility retained: {payload['utility_score']}", y)
    y -= 3 * mm
    for label, value in [
        ("Output SHA-256", payload["output_sha256"]),
        ("Input SHA-256", payload["input_sha256"]),
        ("Graph SHA-256", payload["graph_sha256"]),
        ("Manifest SHA-256", payload["manifest_sha256"]),
        ("Verification SHA-256", payload["verification_sha256"]),
        ("Audit head", payload["audit_head_at_certification"]),
        ("Signer fingerprint", payload["signer"]["public_key_sha256"]),
    ]:
        y = text_line(label + ":", y, 8, True)
        y = text_line(str(value), y, 7)
    y -= 3 * mm
    y = text_line("Mandatory Privacy Red Team results", y, 10, True)
    for test in verification.get("tests", []):
        if y < 25 * mm:
            pdf.showPage()
            y = height - 20 * mm
        label = f"{test.get('status')} · {test.get('name')} · {test.get('severity')} / {test.get('attack_class')}"
        y = text_line(label, y, 7, True)
    y -= 3 * mm
    pdf.setFont("Helvetica", 7)
    for line in textwrap.wrap(payload["disclaimer"], 110):
        pdf.drawString(20 * mm, y, line)
        y -= 4 * mm
    y -= 2 * mm
    y = text_line("Offline verification", y, 8, True)
    pdf.setFont("Helvetica", 6.5)
    for line in textwrap.wrap(
        "Verify the Ed25519 signature over canonical JSON of the certificate payload using the public key in the JSON certificate. "
        "The complete proof package also contains the manifest, Identity Exposure Graph, verification results and signed bundle receipt.",
        120,
    ):
        if y < 22 * mm:
            pdf.showPage()
            y = height - 20 * mm
        pdf.drawString(20 * mm, y, line)
        y -= 3.5 * mm
    y = text_line("Full Ed25519 signature (Base64):", y, 7, True)
    pdf.setFont("Courier", 6)
    for line in textwrap.wrap(certificate["signature_b64"], 96):
        pdf.drawString(20 * mm, y, line)
        y -= 3.4 * mm
    pdf.save()
    return stream.getvalue()


def build_proof_bundle(
    *,
    protected: bytes,
    protected_name: str,
    certificate: dict[str, Any],
    certificate_pdf_bytes: bytes,
    audit_ledger: dict[str, Any],
    verification: dict[str, Any],
    manifest: dict[str, Any],
    identity_exposure_graph: dict[str, Any],
) -> bytes:
    buffer = io.BytesIO()
    cert_id = certificate["payload"]["certificate_id"]
    entries: dict[str, bytes] = {
        protected_name: protected,
        "veilgraph-certificate.json": json.dumps(certificate, indent=2, sort_keys=True).encode("utf-8"),
        "veilgraph-certificate.pdf": certificate_pdf_bytes,
        "veilgraph-audit-ledger.json": json.dumps(audit_ledger, indent=2, sort_keys=True).encode("utf-8"),
        "veilgraph-verification.json": json.dumps(verification, indent=2, sort_keys=True).encode("utf-8"),
        "veilgraph-manifest.json": json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"),
        "identity-exposure-graph.json": json.dumps(identity_exposure_graph, indent=2, sort_keys=True).encode("utf-8"),
        "VERIFY_OFFLINE.txt": (
            f"VeilGraph proof bundle {cert_id}\n\n"
            "This bundle is independently recomputable: it contains the protected artifact, signed certificate, "
            "manifest, Identity Exposure Graph, verification payload and certification-time audit ledger.\n\n"
            "Recommended verification: download the complete proof package and run\n"
            "  python3 scripts/verify_proof_package.py <proof-package.zip>\n\n"
            "Certificate-only fallback:\n"
            "  python3 scripts/verify_certificate.py veilgraph-certificate.json <protected-file>\n"
        ).encode("utf-8"),
    }
    annotation = manifest.get("annotation_evidence")
    if isinstance(annotation, dict):
        entries["veilgraph-annotation-manifest.json"] = json.dumps(annotation, indent=2, sort_keys=True).encode("utf-8")
    index = {
        "schema": "veilgraph.proof-bundle-index.v1",
        "certificate_id": cert_id,
        "entries": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(entries.items())},
    }
    entries["veilgraph-bundle-index.json"] = json.dumps(index, indent=2, sort_keys=True).encode("utf-8")
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return buffer.getvalue()


def issue_destruction_receipt(
    *,
    job_id: str,
    final_audit_head: str,
    final_event_count: int,
    workspace_report: dict[str, Any],
    deleted_rows: dict[str, int],
    destroyed_outputs: int,
    trigger: str = "MANUAL",
    audit_integrity_valid: bool = True,
    retention_deadline: str = "",
) -> dict[str, Any]:
    payload = {
        "schema": DESTRUCTION_SCHEMA,
        "product": "VeilGraph",
        "product_version": settings.version,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "job_commitment_sha256": hashlib.sha256(job_id.encode("utf-8")).hexdigest(),
        "trigger": trigger,
        "audit_integrity_valid": bool(audit_integrity_valid),
        "retention_deadline": retention_deadline,
        "final_audit_head": final_audit_head,
        "final_audit_event_count": final_event_count,
        "deleted_workspace_files": int(workspace_report.get("deleted_workspace_files", 0)),
        "cleared_plaintext_entities": int(workspace_report.get("cleared_plaintext_entities", 0)),
        "destroyed_outputs": int(destroyed_outputs),
        "deleted_database_rows": deleted_rows,
        "signer": {
            "algorithm": "Ed25519",
            "public_key_b64": public_key_b64(),
            "public_key_sha256": signer_fingerprint(),
        },
        "scope_note": str(workspace_report.get("note", "")),
    }
    return {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": sign_payload(payload),
    }
