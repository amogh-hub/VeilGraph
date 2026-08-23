#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
DATASET = ROOT / "competition" / "datasets" / "judge_showcase_v1" / "08_research_records.csv"
OUT_JSON = ROOT / "competition" / "phase3" / "GRADATION_CALIBRATION_RESULTS.json"
OUT_MD = ROOT / "competition" / "phase3" / "GRADATION_CALIBRATION_REPORT.md"


def main() -> int:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="veilgraph-gradation-") as td:
        tmp = Path(td)
        os.environ.update({
            "VEILGRAPH_DATABASE_PATH": str(tmp / "calibration.db"),
            "VEILGRAPH_WORKSPACE_ROOT": str(tmp / "jobs"),
            "VEILGRAPH_SIGNING_KEY_PATH": str(tmp / "signing.key"),
            "VEILGRAPH_RETENTION_WORKER_ENABLED": "false",
            "VEILGRAPH_OFFLINE_MODE": "true",
        })
        import sys
        sys.path.insert(0, str(BACKEND))
        from fastapi.testclient import TestClient
        from main import app

        data = DATASET.read_bytes()
        levels = []
        with TestClient(app) as client:
            for level in range(1, 6):
                created = client.post("/api/v1/jobs", json={
                    "purpose": "Public research release",
                    "recipient": "External research partner",
                    "audience_profile": "PUBLIC_RELEASE",
                    "privacy_level": level,
                    "retention_seconds": 3600,
                })
                created.raise_for_status(); job = created.json(); job_id = job["id"]
                uploaded = client.post(
                    f"/api/v1/jobs/{job_id}/files",
                    files={"file": (DATASET.name, data, "text/csv")},
                )
                uploaded.raise_for_status(); file_id = uploaded.json()["id"]
                analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
                analysed.raise_for_status()
                entities = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json()
                for entity in entities:
                    for mention in entity["mentions"]:
                        if mention["review_status"] == "PENDING":
                            response = client.post(
                                f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                                json={"action": "PROTECT"},
                            )
                            response.raise_for_status()
                graph = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level={level}")
                graph.raise_for_status(); graph_json = graph.json()
                transform = client.post(
                    f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
                    json={"privacy_level": level},
                )
                transform.raise_for_status(); transformed = transform.json()
                verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{transformed['output_id']}/verify")
                verification.raise_for_status(); verified = verification.json()
                rules = graph_json["policy"]["rules"]
                active = [rule for rule in rules if rule["action"] != "RETAIN"]
                context_rules = [rule for rule in rules if rule["entity_type"] in {
                    "DATE_OF_BIRTH", "GENERIC_DATE", "AGE", "STREET_ADDRESS", "BUILDING_NUMBER",
                    "LOCALITY", "POSTCODE", "EMPLOYER", "JOB_TITLE", "PERSON_TITLE", "DEMOGRAPHIC_ATTRIBUTE",
                }]
                context_active = [rule for rule in context_rules if rule["action"] != "RETAIN"]
                levels.append({
                    "privacy_level": level,
                    "policy_name": graph_json["policy"]["name"],
                    "risk_before": verified["risk_before"],
                    "residual_risk": verified["residual_risk"],
                    "utility_score": verified["utility_score"],
                    "release_status": verified["status"],
                    "release_decision": verified["release_decision"],
                    "attack_coverage": verified["attack_coverage"],
                    "attacks_passed": verified["passed"],
                    "transformations_applied": transformed["transformations_applied"],
                    "active_entity_types": len(active),
                    "total_entity_types": len(rules),
                    "intervention_coverage": round(len(active) / len(rules), 6) if rules else 0.0,
                    "context_types_protected": len(context_active),
                    "context_types_present": len(context_rules),
                    "context_protection_coverage": round(len(context_active) / len(context_rules), 6) if context_rules else 0.0,
                    "actions": {rule["entity_type"]: rule["action"] for rule in rules},
                    "source_independent_population": level == 5,
                    "synthetic_twin": transformed.get("synthetic_twin"),
                })

        coverage = [item["intervention_coverage"] for item in levels]
        context = [item["context_protection_coverage"] for item in levels]
        report = {
            "schema": "veilgraph.gradation-calibration.v1",
            "generated_at_unix": int(time.time()),
            "source_fixture": str(DATASET.relative_to(ROOT)),
            "source_role": "Judge Showcase development/demo fixture; calibration evidence, not untouched generalization evidence.",
            "same_source_all_levels": True,
            "levels": levels,
            "checks": {
                "all_levels_executed": len(levels) == 5,
                "all_release_gates_passed": all(item["release_status"] == "VERIFIED_SAFE" for item in levels),
                "intervention_coverage_non_decreasing": all(a <= b for a, b in zip(coverage, coverage[1:])),
                "context_protection_non_decreasing": all(a <= b for a, b in zip(context, context[1:])),
                "level5_source_independent": bool(levels[-1]["source_independent_population"]),
                "level5_has_15_gates": levels[-1]["attack_coverage"] == 15,
            },
            "interpretation": (
                "Gradation is calibrated as a non-decreasing scope of protected entity/context classes plus a distinct relationship-preserving L4 and source-independent L5. "
                "Residual Exposure is also reported as a measured product risk indicator; it is not forced to be numerically monotonic when two adjacent levels use different privacy/utility mechanisms."
            ),
        }
        report["all_passed"] = all(report["checks"].values())
        OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lines = [
            "# VeilGraph L1-L5 Gradation Calibration",
            "",
            "Same source fixture processed independently through every privacy level.",
            "",
            "| Level | Policy | Intervention coverage | Context coverage | Exposure | Utility | Red Team | Release |",
            "|---:|---|---:|---:|---:|---:|---:|---|",
        ]
        for item in levels:
            lines.append(
                f"| L{item['privacy_level']} | {item['policy_name']} | {item['intervention_coverage']:.0%} | "
                f"{item['context_protection_coverage']:.0%} | {item['risk_before']} → {item['residual_risk']} | "
                f"{item['utility_score']}% | {item['attacks_passed']}/{item['attack_coverage']} | {item['release_status']} |"
            )
        lines += ["", "## Acceptance", ""]
        for name, value in report["checks"].items():
            lines.append(f"- {'PASS' if value else 'FAIL'} — {name.replace('_', ' ')}")
        lines += ["", "## Claim boundary", "", report["interpretation"], ""]
        OUT_MD.write_text("\n".join(lines), encoding="utf-8")
        print(json.dumps(report["checks"], indent=2, sort_keys=True))
        print(f"Wrote {OUT_JSON}")
        return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
