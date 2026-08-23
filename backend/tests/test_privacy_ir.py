from __future__ import annotations

import json

from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from app.ir.privacy_ir import build_privacy_ir, privacy_ir_summary, to_processed_document
from app.core.enums import FileType
from generate_identity_graph_document import build_identity_graph_pdf
from generate_test_pdf import build_test_pdf


def _signature(items):
    return sorted(
        (
            item.entity_type.value,
            item.plaintext,
            item.page_index,
            item.page_char_start,
            item.page_char_end,
        )
        for item in items
    )


def test_privacy_ir_round_trip_preserves_detection_semantics():
    processed = process_document(build_identity_graph_pdf(), FileType.PDF)
    before = detect_all(processed)
    ir = build_privacy_ir(processed)
    after = detect_all(to_processed_document(ir))
    assert _signature(after) == _signature(before)
    assert ir.schema == "veilgraph.privacy-ir.v1"
    assert ir.unit_count == processed.page_count
    assert ir.scanned_units == processed.scanned_pages


def test_privacy_ir_commitment_is_deterministic_and_content_bound():
    first = build_privacy_ir(process_document(build_identity_graph_pdf(), FileType.PDF))
    second = build_privacy_ir(process_document(build_identity_graph_pdf(), FileType.PDF))
    different = build_privacy_ir(process_document(build_test_pdf(), FileType.PDF))
    assert first.commitment_sha256 == second.commitment_sha256
    assert first.commitment_sha256 != different.commitment_sha256
    assert len(first.commitment_sha256) == 64


def test_privacy_ir_summary_never_serializes_source_plaintext():
    secret = "Aarav Testperson"
    ir = build_privacy_ir(process_document(build_identity_graph_pdf(), FileType.PDF))
    encoded = json.dumps(privacy_ir_summary(ir), sort_keys=True)
    assert secret not in encoded
    assert "@example.org" not in encoded
    assert privacy_ir_summary(ir)["plaintext_persisted"] is False


def test_analysis_response_and_audit_bind_to_privacy_ir(client):
    job = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "IR architecture test",
            "recipient": "local tester",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": 4,
        },
    ).json()
    uploaded = client.post(
        f"/api/v1/jobs/{job['id']}/files",
        files={"file": ("ir-test.pdf", build_identity_graph_pdf(), "application/pdf")},
    )
    assert uploaded.status_code == 201
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job['id']}/files/{file_id}/analyse")
    assert analysed.status_code == 200
    payload = analysed.json()
    assert payload["privacy_ir_schema"] == "veilgraph.privacy-ir.v1"
    assert payload["privacy_ir_units"] == payload["page_count"]
    assert len(payload["privacy_ir_commitment_sha256"]) == 64

    audit = client.get(f"/api/v1/jobs/{job['id']}/audit")
    assert audit.status_code == 200
    analysis_event = next(event for event in audit.json()["events"] if event["event_type"] == "ANALYSIS_COMPLETED")
    ir_meta = analysis_event["details"]["privacy_ir"]
    assert ir_meta["schema"] == "veilgraph.privacy-ir.v1"
    assert ir_meta["commitment_sha256"] == payload["privacy_ir_commitment_sha256"]
    assert ir_meta["plaintext_persisted"] is False
