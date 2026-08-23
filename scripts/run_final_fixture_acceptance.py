#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
OUT = ROOT / "competition" / "final" / "FINAL_REAL_FIXTURE_ACCEPTANCE.json"

FIXTURES = [
    (ROOT / "competition/datasets/judge_showcase_v1/01_case_brief.txt", "text/plain"),
    (ROOT / "competition/datasets/judge_showcase_v1/04_case_packet.pdf", "application/pdf"),
    (ROOT / "competition/datasets/judge_showcase_v1/05_scanned_application.pdf", "application/pdf"),
]


def main() -> int:
    missing = [str(p.relative_to(ROOT)) for p, _ in FIXTURES if not p.is_file()]
    if missing:
        raise SystemExit(f"Missing required final fixtures: {missing}")

    with tempfile.TemporaryDirectory(prefix="veilgraph-final-fixtures-") as td:
        tmp = Path(td)
        os.environ.update({
            "VEILGRAPH_DATABASE_PATH": str(tmp / "final-fixtures.db"),
            "VEILGRAPH_WORKSPACE_ROOT": str(tmp / "jobs"),
            "VEILGRAPH_SIGNING_KEY_PATH": str(tmp / "signing.key"),
            "VEILGRAPH_RETENTION_WORKER_ENABLED": "false",
            "VEILGRAPH_OFFLINE_MODE": "true",
        })
        sys.path.insert(0, str(BACKEND))
        from fastapi.testclient import TestClient
        from main import app

        results: list[dict] = []
        with TestClient(app) as client:
            for path, mime in FIXTURES:
                created = client.post("/api/v1/jobs", json={
                    "purpose": "Final post-hardening acceptance",
                    "recipient": "NTRO/SIH evaluator",
                    "audience_profile": "PUBLIC_RELEASE",
                    "privacy_level": 4,
                    "retention_seconds": 3600,
                })
                created.raise_for_status()
                job_id = created.json()["id"]

                uploaded = client.post(
                    f"/api/v1/jobs/{job_id}/files",
                    files={"file": (path.name, path.read_bytes(), mime)},
                )
                uploaded.raise_for_status()
                file_id = uploaded.json()["id"]

                analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
                analysed.raise_for_status()

                entities_resp = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities")
                entities_resp.raise_for_status()
                entities = entities_resp.json()
                review_count = 0
                for entity in entities:
                    for mention in entity.get("mentions", []):
                        if mention.get("review_status") == "PENDING":
                            reviewed = client.post(
                                f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                                json={"action": "PROTECT"},
                            )
                            reviewed.raise_for_status()
                            review_count += 1

                transformed = client.post(
                    f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
                    json={"privacy_level": 4},
                )
                transformed.raise_for_status()
                transform_json = transformed.json()
                output_id = transform_json["output_id"]

                verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{output_id}/verify")
                verification.raise_for_status()
                verified = verification.json()

                attack_coverage = int(verified.get("attack_coverage", 0))
                passed = int(verified.get("passed", 0))
                failed = int(verified.get("failed", 0))
                inconclusive = int(verified.get("inconclusive", 0))
                blockers = int(verified.get("critical_blockers", 0))
                score = int(verified.get("proof_score", 0))
                status = verified.get("status")
                decision = verified.get("release_decision")

                all_passed = (
                    status == "VERIFIED_SAFE"
                    and decision == "ALLOW_RELEASE"
                    and attack_coverage == 12
                    and passed == 12
                    and failed == 0
                    and inconclusive == 0
                    and blockers == 0
                    and score == 100
                )
                results.append({
                    "fixture": str(path.relative_to(ROOT)),
                    "format": path.suffix.lower().lstrip("."),
                    "privacy_level": 4,
                    "reviewed_pending_mentions": review_count,
                    "transformations_applied": transform_json.get("transformations_applied"),
                    "verification_status": status,
                    "release_decision": decision,
                    "proof_score": score,
                    "attacks_passed": passed,
                    "attack_coverage": attack_coverage,
                    "failed": failed,
                    "inconclusive": inconclusive,
                    "critical_blockers": blockers,
                    "risk_before": verified.get("risk_before"),
                    "residual_risk": verified.get("residual_risk"),
                    "utility_score": verified.get("utility_score"),
                    "all_passed": all_passed,
                })

        report = {
            "schema": "veilgraph.final-real-fixture-acceptance.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "purpose": "Fresh machine acceptance of the three real fixtures that exposed v14.7-v14.9 native text / digital PDF / scanned PDF defects.",
            "fixtures": results,
            "all_passed": all(item["all_passed"] for item in results) and len(results) == 3,
            "release_rule": "Every fixture must reach VERIFIED_SAFE / ALLOW_RELEASE with exactly 12/12 mandatory non-video gates, 100/100 proof score, zero failures, zero inconclusive gates and zero critical blockers.",
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        print(f"Wrote {OUT}")
        return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
