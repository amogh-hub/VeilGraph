from __future__ import annotations

import csv
import io
import json

from app.core.enums import AudienceProfile, EntityType, PrivacyLevel
from app.extraction.structured_data import (
    StructuredDataset,
    StructuredTable,
    export_xlsx,
    parse_structured_data,
    schema_signature,
    structured_visible_text,
    virtual_cell_index,
)
from app.policy.compiler import action_for, policy_descriptor
from app.proof.package import verify_proof_package_bytes
from app.transformation.sanitizer import ProtectionInstruction
from app.transformation.synthetic_twin import synthesize_structured_twin


HEADERS = ["Name", "Email", "Phone", "Age", "City", "Cohort", "Score", "Income"]
ROWS = [
    ["Aarav Testperson", "aarav.test@example.org", "+91 98765 43210", "19", "Bengaluru", "A", 62, 41000],
    ["Meera Sampleperson", "meera.sample@example.org", "+91 99887 76655", "22", "Bengaluru", "A", 68, 45000],
    ["Kabir Demoperson", "kabir.demo@example.org", "+91 91234 56780", "27", "Mysuru", "B", 74, 52000],
    ["Naina Exampleperson", "naina.example@example.org", "+91 92345 67801", "31", "Mysuru", "B", 79, 59000],
    ["Ravi Fictionperson", "ravi.fiction@example.org", "+91 93456 78012", "36", "Pune", "A", 83, 66000],
    ["Sana Mockperson", "sana.mock@example.org", "+91 94567 80123", "41", "Pune", "C", 87, 72000],
    ["Tara Testperson", "tara.test@example.org", "+91 95678 01234", "46", "Kochi", "C", 91, 81000],
    ["Vihaan Sampleperson", "vihaan.sample@example.org", "+91 96780 12345", "52", "Kochi", "B", 95, 91000],
]


def csv_bytes() -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(HEADERS)
    writer.writerows(ROWS)
    return stream.getvalue().encode("utf-8")


def _instructions(data: bytes) -> list[ProtectionInstruction]:
    dataset = parse_structured_data(data, "synthetic-demo.csv")
    instructions: list[ProtectionInstruction] = []
    entity_for_header = {
        "Name": EntityType.PERSON_NAME,
        "Email": EntityType.EMAIL,
        "Phone": EntityType.PHONE,
        "Age": EntityType.AGE,
        "City": EntityType.LOCALITY,
    }
    for ref in virtual_cell_index(dataset):
        entity_type = entity_for_header.get(ref.cell.header)
        if entity_type is None:
            continue
        entity_id = f"{entity_type.value}:{ref.cell.display_value.casefold()}"
        instructions.append(ProtectionInstruction(
            entity_id=entity_id,
            mention_id=f"m:{ref.page_index}:{ref.cell.header}",
            entity_type=entity_type,
            page_index=ref.page_index,
            rect=(0.0, 0.0, 1.0, 1.0),
            replacement="[SYNTHETIC TWIN VALUE]",
            char_start=ref.value_char_start,
            char_end=ref.value_char_end,
        ))
    return instructions


def _create_job(client, level: int = 5) -> str:
    response = client.post("/api/v1/jobs", json={
        "purpose": "Research-safe synthetic release",
        "recipient": "Research partner",
        "audience_profile": "RESEARCH_PARTNER",
        "privacy_level": level,
    })
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _protect_pending(client, job_id: str, file_id: str) -> None:
    for item in client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json():
        for mention in item["mentions"]:
            if mention["review_status"] == "PENDING":
                response = client.post(
                    f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                    json={"action": "PROTECT"},
                )
                assert response.status_code == 200, response.text


def test_level5_policy_is_a_real_fifth_gradation():
    assert int(PrivacyLevel.SYNTHETIC_TWIN) == 5
    assert action_for(EntityType.PERSON_NAME, PrivacyLevel.SYNTHETIC_TWIN, AudienceProfile.PUBLIC_RELEASE) == "SYNTHESIZE"
    assert action_for(EntityType.AGE, PrivacyLevel.SYNTHETIC_TWIN, AudienceProfile.RESEARCH_PARTNER) == "SYNTHESIZE"
    descriptor = policy_descriptor(
        AudienceProfile.RESEARCH_PARTNER,
        PrivacyLevel.SYNTHETIC_TWIN,
        {EntityType.PERSON_NAME, EntityType.AGE},
    )
    assert descriptor["name"] == "Level 5 / Synthetic Twin generation"
    assert {item["action"] for item in descriptor["rules"]} == {"SYNTHESIZE"}


def test_synthetic_engine_is_deterministic_schema_preserving_and_noncopying():
    source = csv_bytes()
    instructions = _instructions(source)
    first = synthesize_structured_twin(source, instructions, "synthetic-demo.csv")
    second = synthesize_structured_twin(source, instructions, "synthetic-demo.csv")
    assert first.data == second.data
    assert first.report["seed_commitment_sha256"] == second.report["seed_commitment_sha256"]
    assert schema_signature(source, "source.csv") == schema_signature(first.data, "synthetic.csv")
    assert first.report["schema_preserved"] is True
    assert first.report["exact_row_copy_rate"] == 0.0
    assert first.report["sensitive_exact_reuse_count"] == 0
    assert first.report["privacy_score"] >= 90
    assert first.report["utility_score"] >= 60
    assert first.report["numeric_correlation_fidelity"] >= 0.85
    visible = structured_visible_text(first.data, "synthetic.csv")
    for original in ("Aarav Testperson", "aarav.test@example.org", "+91 98765 43210", "Bengaluru"):
        assert original not in visible


def test_level5_csv_end_to_end_has_15_fail_closed_gates_and_signed_proof(client):
    source = csv_bytes()
    job_id = _create_job(client, 5)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("synthetic-demo.csv", source, "text/csv")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    _protect_pending(client, job_id, file_id)

    graph = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level=5")
    assert graph.status_code == 200, graph.text
    assert graph.json()["policy"]["privacy_level"] == 5
    assert any(rule["action"] == "SYNTHESIZE" for rule in graph.json()["policy"]["rules"])

    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 5},
    )
    assert transformed.status_code == 200, transformed.text
    payload = transformed.json()
    report = payload["synthetic_twin"]
    assert payload["privacy_level"] == 5
    assert report["schema"] == "veilgraph.synthetic-twin.v1"
    assert report["release_randomized"] is True
    assert report["schema_preserved"] is True
    assert report["exact_row_copy_rate"] == 0.0
    assert report["sensitive_exact_reuse_count"] == 0
    assert report["utility_score"] >= 60
    assert report["privacy_score"] >= 90

    output_id = payload["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["attack_coverage"] == 15
    assert proof["passed"] == 15
    assert proof["failed"] == 0
    assert proof["inconclusive"] == 0
    assert proof["proof_score"] == 100
    assert proof["synthetic_twin"]["output_sha256"] == report["output_sha256"]

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    assert schema_signature(source, "source.csv") == schema_signature(downloaded.content, "synthetic.csv")
    visible = downloaded.content.decode("utf-8")
    assert "Aarav Testperson" not in visible
    assert "aarav.test@example.org" not in visible
    assert "+91 98765 43210" not in visible

    certificate = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/certificate")
    assert certificate.status_code == 200, certificate.text
    assert certificate.json()["signature_valid"] is True

    proof_package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert proof_package.status_code == 200, proof_package.text
    package_result = verify_proof_package_bytes(proof_package.content)
    assert package_result["valid"] is True, package_result
    assert any(
        check["name"] == "protected_artifact_hash" and check["valid"]
        for check in package_result["checks"]
    ), package_result


def test_level5_refuses_non_dataset_instead_of_faking_document_synthesis(client):
    job_id = _create_job(client, 5)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": ("note.txt", b"Name: Aarav Testperson\nEmail: aarav.test@example.org\n", "text/plain")},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200
    _protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 5},
    )
    assert transformed.status_code == 422
    assert "structured CSV, JSON or XLSX" in transformed.json()["detail"]



def test_level5_release_salt_breaks_cross_release_linkability():
    source = csv_bytes()
    instructions = _instructions(source)
    first = synthesize_structured_twin(
        source, instructions, "synthetic-demo.csv", release_salt=b"A" * 32,
    )
    second = synthesize_structured_twin(
        source, instructions, "synthetic-demo.csv", release_salt=b"B" * 32,
    )
    assert first.data != second.data
    assert first.report["seed_commitment_sha256"] != second.report["seed_commitment_sha256"]
    assert first.report["release_randomized"] is True
    assert second.report["release_randomized"] is True
    assert first.report["schema_preserved"] is second.report["schema_preserved"] is True
    assert first.report["exact_row_copy_rate"] == second.report["exact_row_copy_rate"] == 0.0

def json_bytes() -> bytes:
    records = [dict(zip(HEADERS, row)) for row in ROWS]
    for index, record in enumerate(records):
        record["Meta"] = {"CohortLabel": record["Cohort"], "Sequence": index + 1}
    return json.dumps(records, ensure_ascii=False).encode("utf-8")


def xlsx_bytes() -> bytes:
    dataset = StructuredDataset(
        format="xlsx",
        tables=[StructuredTable("SyntheticStudy", list(HEADERS), [list(row) for row in ROWS])],
    )
    return export_xlsx(dataset)


def _level5_dataset_roundtrip(client, filename: str, source: bytes, content_type: str):
    job_id = _create_job(client, 5)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": (filename, source, content_type)},
    )
    assert uploaded.status_code == 201, uploaded.text
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    assert analysed.status_code == 200, analysed.text
    _protect_pending(client, job_id, file_id)
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": 5},
    )
    assert transformed.status_code == 200, transformed.text
    payload = transformed.json()
    assert payload["synthetic_twin"]["release_randomized"] is True
    assert payload["synthetic_twin"]["schema_preserved"] is True
    assert payload["synthetic_twin"]["exact_row_copy_rate"] == 0.0
    assert payload["synthetic_twin"]["privacy_score"] >= 90
    assert payload["synthetic_twin"]["utility_score"] >= 60

    output_id = payload["output_id"]
    verified = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
    assert verified.status_code == 200, verified.text
    proof = verified.json()
    assert proof["status"] == "VERIFIED_SAFE", proof
    assert proof["attack_coverage"] == proof["passed"] == 15
    assert proof["failed"] == proof["inconclusive"] == 0
    assert proof["proof_score"] == 100

    proof_package = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/proof-package")
    assert proof_package.status_code == 200, proof_package.text
    package_result = verify_proof_package_bytes(proof_package.content)
    assert package_result["valid"] is True, package_result

    downloaded = client.get(f"/api/v1/jobs/{job_id}/outputs/{output_id}/download")
    assert downloaded.status_code == 200
    assert schema_signature(source, filename) == schema_signature(downloaded.content, filename)
    visible = structured_visible_text(downloaded.content, filename)
    for original in ("Aarav Testperson", "aarav.test@example.org", "+91 98765 43210"):
        assert original not in visible
    return payload, downloaded.content


def test_level5_json_preserves_nested_schema_and_passes_15_gates(client):
    source = json_bytes()
    payload, protected = _level5_dataset_roundtrip(
        client, "synthetic-demo.json", source, "application/json",
    )
    parsed = json.loads(protected)
    assert isinstance(parsed, list) and len(parsed) == len(ROWS)
    assert all("Meta" in row and set(row["Meta"]) == {"CohortLabel", "Sequence"} for row in parsed)
    assert payload["synthetic_twin"]["record_count_original"] == len(ROWS)


def test_level5_xlsx_preserves_sheet_schema_and_passes_15_gates(client):
    source = xlsx_bytes()
    payload, protected = _level5_dataset_roundtrip(
        client,
        "synthetic-demo.xlsx",
        source,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    parsed = parse_structured_data(protected, "synthetic-demo.xlsx")
    assert parsed.tables[0].name == "SyntheticStudy"
    assert parsed.tables[0].headers == HEADERS
    assert payload["synthetic_twin"]["record_count_synthetic"] == len(ROWS)
