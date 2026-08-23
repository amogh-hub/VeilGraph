from __future__ import annotations

import fitz

from generate_identity_graph_document import build_identity_graph_pdf


def _create_job(client, level: int = 2) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "Public evidence release",
            "recipient": "Citizen information portal",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": level,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _upload_and_analyse(client, job_id: str) -> str:
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("identity-graph.pdf", build_identity_graph_pdf(), "application/pdf")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    return file_id


def _protect_pending(client, job_id: str, file_id: str) -> None:
    entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
    for item in entities:
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                response = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert response.status_code == 200, response.text


def test_level2_is_a_first_class_api_privacy_level(client):
    job_id = _create_job(client, level=2)
    job = client.get(f"/api/v1/jobs/{job_id}")
    assert job.status_code == 200, job.text
    assert job.json()["privacy_level"] == 2


def test_level2_policy_protects_sensitive_entities_but_retains_later_context(client):
    job_id = _create_job(client, level=2)
    file_id = _upload_and_analyse(client, job_id)
    _protect_pending(client, job_id, file_id)

    response = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=2")
    assert response.status_code == 200, response.text
    graph = response.json()
    assert graph["policy"]["name"] == "Level 2 / Sensitive-entity protection"
    actions = {item["entity_type"]: item["action"] for item in graph["policy"]["rules"]}

    for protected_type in {
        "PERSON_NAME", "PHONE", "EMAIL", "AADHAAR_LIKE", "PAN_LIKE",
        "CASE_REFERENCE", "DATE_OF_BIRTH", "STREET_ADDRESS", "POSTCODE",
    }:
        assert actions[protected_type] == "PROTECT"

    for retained_type in {"AGE", "LOCALITY", "EMPLOYER", "JOB_TITLE"}:
        assert actions[retained_type] == "RETAIN"


def test_level2_output_uses_stable_opaque_tokens_and_passes_release_gate(client):
    job_id = _create_job(client, level=2)
    file_id = _upload_and_analyse(client, job_id)
    _protect_pending(client, job_id, file_id)

    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 2},
    )
    assert transformed.status_code == 200, transformed.text
    result = transformed.json()
    assert result["privacy_level"] == 2
    assert result["transformations_applied"] == 12
    assert result["risk_before"] > result["residual_risk"]

    verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{result['output_id']}/verify")
    assert verification.status_code == 200, verification.text
    proof = verification.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["passed"] == 12
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{result['output_id']}/download")
    assert downloaded.status_code == 200, downloaded.text
    pdf = fitz.open(stream=downloaded.content, filetype="pdf")
    text = "\n".join(page.get_text("text", sort=True) for page in pdf)
    pdf.close()

    lowered = text.casefold()
    for original in (
        "aarav testperson", "meera testperson", "+91 98765 43210", "aarav.test@example.org",
        "1234 5678 9012", "abcde1234f", "vg-2026-00421", "11 june 2007",
        "12 basalt lane", "560038",
    ):
        assert original not in lowered

    assert "[PERSON_001]" in text
    assert "[PERSON_002]" in text
    assert "[CASE_REFERENCE_001]" in text
    assert text.count("[CASE_REFERENCE_001]") == 2
    assert "Kaveri Analytics Pvt Ltd" in text
    assert "Junior Data Analyst" in text
    assert "Indiranagar, Bengaluru" in text


def test_identity_dossier_exposure_is_monotonic_across_levels_1_to_4(client):
    job_id = _create_job(client, level=1)
    file_id = _upload_and_analyse(client, job_id)
    _protect_pending(client, job_id, file_id)

    after = []
    for level in (1, 2, 3, 4):
        response = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level={level}")
        assert response.status_code == 200, response.text
        after.append(response.json()["risk"]["after"])

    assert after == sorted(after, reverse=True), after
    assert after[0] > after[1] > after[2] > after[3], after
