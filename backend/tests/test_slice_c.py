from __future__ import annotations

import fitz

from app.core.enums import EntityType, FileType
from app.detection.direct_identifiers import normalize_value
from app.detection.pipeline import detect_all
from app.extraction.document_processor import process_document
from generate_identity_graph_document import build_identity_graph_pdf


def create_job(client, *, audience: str = "PUBLIC_RELEASE", level: int = 4) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public research release",
            "recipient": "Open evidence portal",
            "audience_profile": audience,
            "privacy_level": level,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def upload_and_analyse(client, job_id: str) -> str:
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("identity-graph.pdf", build_identity_graph_pdf(), "application/pdf")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    return file_id


def protect_pending(client, job_id: str, file_id: str) -> None:
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    for item in entities:
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                response = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert response.status_code == 200, response.text


def test_identity_dossier_detects_indirect_clues_and_relationship_people():
    document = process_document(build_identity_graph_pdf(), FileType.PDF)
    detections = detect_all(document)
    types = {item.entity_type for item in detections}
    assert document.page_count == 2
    assert document.scanned_pages == 0
    assert {
        EntityType.PERSON_NAME,
        EntityType.DATE_OF_BIRTH,
        EntityType.AGE,
        EntityType.STREET_ADDRESS,
        EntityType.LOCALITY,
        EntityType.POSTCODE,
        EntityType.EMPLOYER,
        EntityType.JOB_TITLE,
        EntityType.CASE_REFERENCE,
        EntityType.PHONE,
        EntityType.EMAIL,
    }.issubset(types)
    names = [item for item in detections if item.entity_type == EntityType.PERSON_NAME]
    assert {item.plaintext for item in names} == {"Aarav Testperson", "Meera Testperson"}
    assert any("mother" in (item.context_label or "") for item in names)
    assert not any(item.entity_type == EntityType.FACE for item in detections)
    employers = [item for item in detections if item.entity_type == EntityType.EMPLOYER]
    assert len(employers) == 2
    assert len({normalize_value(item.entity_type, item.plaintext) for item in employers}) == 1


def test_graph_exposes_relationship_paths_and_level_comparison(client):
    job_id = create_job(client, level=3)
    file_id = upload_and_analyse(client, job_id)
    protect_pending(client, job_id, file_id)

    level3 = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=3")
    level4 = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=4")
    assert level3.status_code == 200, level3.text
    assert level4.status_code == 200, level4.text
    graph3, graph4 = level3.json(), level4.json()
    assert graph3["graph_version"] == "ieg-0.3"
    assert len(graph3["graph_sha256"]) == 64
    assert any(edge["edge_type"] == "RELATED_TO" for edge in graph3["edges"])
    assert any("postcode and employer" in path["reason"].casefold() for path in graph3["high_risk_paths"])
    assert graph3["risk"]["before"] >= 75
    assert graph3["risk"]["after"] < graph3["risk"]["before"]
    assert graph4["risk"]["after"] < graph3["risk"]["after"]
    assert graph4["risk"]["utility_score"] > graph3["risk"]["utility_score"]


def test_audience_policy_changes_retention_and_residual_risk(client):
    public_job = create_job(client, audience="PUBLIC_RELEASE", level=3)
    public_file = upload_and_analyse(client, public_job)
    protect_pending(client, public_job, public_file)
    public_graph = client.get(f"/api/v1/jobs/{public_job}/files/{public_file}/graph?privacy_level=3").json()

    internal_job = create_job(client, audience="INTERNAL_OPERATIONS", level=3)
    internal_file = upload_and_analyse(client, internal_job)
    protect_pending(client, internal_job, internal_file)
    internal_graph = client.get(f"/api/v1/jobs/{internal_job}/files/{internal_file}/graph?privacy_level=3").json()

    public_employer = next(rule for rule in public_graph["policy"]["rules"] if rule["entity_type"] == "EMPLOYER")
    internal_employer = next(rule for rule in internal_graph["policy"]["rules"] if rule["entity_type"] == "EMPLOYER")
    assert public_employer["action"] == "GENERALIZE"
    assert internal_employer["action"] == "RETAIN"
    assert internal_graph["risk"]["after"] > public_graph["risk"]["after"]


def test_level4_pipeline_preserves_relationship_consistency_and_verifies(client):
    job_id = create_job(client, level=4)
    file_id = upload_and_analyse(client, job_id)
    analysis = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities")
    assert analysis.status_code == 200
    protect_pending(client, job_id, file_id)

    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 4},
    )
    assert transformed.status_code == 200, transformed.text
    payload = transformed.json()
    assert payload["privacy_level"] == 4
    assert payload["risk_before"] > payload["residual_risk"]
    assert payload["transformations_applied"] == 17

    blocked = client.get(f"/api/v1/jobs/{job_id}/outputs/{payload['output_id']}/download")
    assert blocked.status_code == 423
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{payload['output_id']}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["passed"] == 12
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0
    assert proof["proof_score"] == 100
    assert proof["attack_coverage"] == 12
    assert proof["critical_failures"] == 0
    assert proof["release_decision"] == "ALLOW_RELEASE"

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{payload['output_id']}/download")
    assert downloaded.status_code == 200
    pdf = fitz.open(stream=downloaded.content, filetype="pdf")
    text = "\n".join(page.get_text("text", sort=True) for page in pdf)
    pdf.close()
    lowered = text.casefold()
    assert "aarav testperson" not in lowered
    assert "meera testperson" not in lowered
    assert "kaveri analytics" not in lowered
    assert "vg-2026-00421" not in lowered
    assert "person a" in lowered
    assert "person b" in lowered
    assert lowered.count("organisation a") == 2
    assert lowered.count("case a") == 2


def test_level3_generalizes_exact_context_instead_of_only_masking(client):
    job_id = create_job(client, level=3)
    file_id = upload_and_analyse(client, job_id)
    protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 3},
    )
    assert transformed.status_code == 200, transformed.text
    output_id = transformed.json()["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.json()["status"] == "VERIFIED_SAFE", verified.json()
    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    pdf = fitz.open(stream=downloaded.content, filetype="pdf")
    text = "\n".join(page.get_text("text", sort=True) for page in pdf)
    pdf.close()
    assert "Born 2005-2009" in text
    assert "Age 18-24" in text
    assert "Bengaluru metropolitan area" in text
    assert "560XXX" in text
    assert "Private analytics organisation" in text
    assert "Early-career professional" in text
