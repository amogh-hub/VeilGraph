from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# Isolate benchmark state from ordinary VeilGraph jobs before importing app settings.
_tmp = tempfile.TemporaryDirectory(prefix="veilbench-")
os.environ["VEILGRAPH_DATABASE_PATH"] = str(Path(_tmp.name) / "veilbench.db")
os.environ["VEILGRAPH_WORKSPACE_ROOT"] = str(Path(_tmp.name) / "jobs")
os.environ["VEILGRAPH_SIGNING_KEY_PATH"] = str(Path(_tmp.name) / "device.key")
os.environ["VEILGRAPH_OFFLINE_MODE"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from app.benchmark.openpii import benchmark_openpii  # noqa: E402
from app.benchmark.piimb import benchmark_piimb  # noqa: E402
from app.benchmark.veilbench import benchmark_curated  # noqa: E402
from generate_identity_graph_document import build_identity_graph_pdf  # noqa: E402
from generate_scanned_test_document import build_scanned_pdf  # noqa: E402
from main import app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CURATED_CORPUS = Path(__file__).resolve().parent / "benchmark_corpus" / "veilbench_curated_v1.json"
OUT_JSON = ROOT / "competition" / "veilbench-results.json"
OUT_MD = ROOT / "competition" / "VEILBENCH_REPORT.md"


def _tool_version(command: str) -> str:
    try:
        args = [command, "-v"] if command == "pdftotext" else [command, "--version"]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return (proc.stdout or proc.stderr).splitlines()[0].strip()
    except Exception:
        return "unavailable"


def _create(client: TestClient, level: int) -> str:
    response = client.post(
        "/api/v1/jobs",
        json={
            "purpose": "VeilBench deterministic validation",
            "recipient": "Local benchmark harness",
            "audience_profile": "PUBLIC_RELEASE",
            "privacy_level": level,
        },
    )
    response.raise_for_status()
    return response.json()["id"]


def _review(client: TestClient, job_id: str, file_id: str) -> int:
    reviewed = 0
    for item in client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/entities").json():
        entity_type = item["entity"]["entity_type"]
        for mention in item["mentions"]:
            if mention["review_status"] != "PENDING":
                continue
            action = "IGNORE" if entity_type == "QR_CODE" and mention["confidence"] <= 0.55 else "PROTECT"
            response = client.post(
                f"/api/v1/jobs/{job_id}/mentions/{mention['id']}/review",
                json={"action": action},
            )
            response.raise_for_status()
            reviewed += 1
    return reviewed


def run_system_case(client: TestClient, *, name: str, filename: str, data: bytes, media_type: str, level: int) -> dict:
    started = time.perf_counter()
    job_id = _create(client, level)
    uploaded = client.post(
        f"/api/v1/jobs/{job_id}/files",
        files={"file": (filename, data, media_type)},
    )
    uploaded.raise_for_status()
    file_id = uploaded.json()["id"]
    analysed = client.post(f"/api/v1/jobs/{job_id}/files/{file_id}/analyse")
    analysed.raise_for_status()
    analysis = analysed.json()
    review_count = _review(client, job_id, file_id)
    graph = client.get(f"/api/v1/jobs/{job_id}/files/{file_id}/graph?privacy_level={level}")
    graph.raise_for_status()
    graph_data = graph.json()
    transformed = client.post(
        f"/api/v1/jobs/{job_id}/files/{file_id}/transform",
        json={"privacy_level": level},
    )
    transformed.raise_for_status()
    output = transformed.json()
    verification = client.post(f"/api/v1/jobs/{job_id}/outputs/{output['output_id']}/verify")
    verification.raise_for_status()
    proof = verification.json()
    certificate = client.get(f"/api/v1/jobs/{job_id}/outputs/{output['output_id']}/certificate")
    certificate.raise_for_status()
    cert = certificate.json()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    passed = (
        proof["status"] == "VERIFIED_SAFE"
        and proof["passed"] == 12
        and proof["proof_score"] == 100
        and proof["critical_failures"] == 0
        and cert["signature_valid"] is True
    )
    result = {
        "name": name,
        "passed": passed,
        "duration_ms": elapsed_ms,
        "privacy_level": level,
        "page_count": analysis["page_count"],
        "scanned_pages": analysis["scanned_pages"],
        "canonical_entities": analysis["canonical_entities"],
        "mentions": analysis["mentions"],
        "direct_mentions": analysis["direct_identifier_mentions"],
        "quasi_mentions": analysis["quasi_identifier_mentions"],
        "visual_mentions": analysis["visual_mentions"],
        "human_reviews": review_count,
        "graph_nodes": len(graph_data["nodes"]),
        "graph_edges": len(graph_data["edges"]),
        "risk_before": output["risk_before"],
        "residual_risk": output["residual_risk"],
        "utility_score": output["utility_score"],
        "transformations": output["transformations_applied"],
        "proof_score": proof["proof_score"],
        "attacks_passed": proof["passed"],
        "attack_coverage": proof["attack_coverage"],
        "critical_blockers": proof["critical_failures"],
        "certificate_signature_valid": cert["signature_valid"],
        "certificate_id": cert["payload"]["certificate_id"],
        "output_sha256": cert["payload"]["output_sha256"],
    }
    client.delete(f"/api/v1/jobs/{job_id}/destroy")
    return result


def _system_benchmark() -> dict:
    client = TestClient(app)
    cases = [
        run_system_case(
            client,
            name="Digital identity reconstruction dossier · Level 4",
            filename="test_identity_graph_document.pdf",
            data=build_identity_graph_pdf(),
            media_type="application/pdf",
            level=4,
        ),
        run_system_case(
            client,
            name="Scanned multimodal dossier · Level 1",
            filename="test_scanned_document.pdf",
            data=build_scanned_pdf(),
            media_type="application/pdf",
            level=1,
        ),
    ]
    return {
        "case_count": len(cases),
        "cases_passed": sum(case["passed"] for case in cases),
        "overall_pass": all(case["passed"] for case in cases),
        "mandatory_attack_pass_rate": (
            sum(case["attacks_passed"] for case in cases) / sum(case["attack_coverage"] for case in cases)
        ),
        "cases": cases,
    }


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _accuracy_lines(title: str, result: dict) -> list[str]:
    overall = result["overall"]
    lines = [
        f"## {title}",
        "",
        f"- Cases: **{result['case_count']}**",
        f"- Gold spans: **{result['gold_span_count']}**",
        f"- Precision: **{_pct(overall['precision'])}**",
        f"- Recall: **{_pct(overall['recall'])}**",
        f"- F1: **{_pct(overall['f1'])}**",
        f"- Macro F1: **{_pct(result['macro_f1'])}**",
        f"- Exact case passes: **{result['exact_case_passes']}/{result['case_count']}**",
        f"- Median detector latency: **{result['performance']['median_case_ms']} ms/case**",
        f"- P95 detector latency: **{result['performance']['p95_case_ms']} ms/case**",
        f"- Throughput: **{result['performance']['cases_per_second']} cases/s**",
        f"- Peak process RSS: **{result['performance']['peak_process_rss_mb']} MB**",
        "",
        "| Entity | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for entity, metrics in result["per_entity"].items():
        lines.append(
            f"| {entity} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | "
            f"{_pct(metrics['precision'])} | {_pct(metrics['recall'])} | {_pct(metrics['f1'])} |"
        )
    lines.append("")
    return lines


def _write_report(report: dict) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    lines = [
        "# VeilBench v1.0 — Accuracy, Performance & Release Evidence",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "VeilBench separates **detection accuracy** from **release-safety verification**. A 12/12 Red Team result is not presented as Precision/Recall/F1, and a high F1 score is not presented as an anonymity guarantee.",
        "",
    ]
    lines += _accuracy_lines("A. Bundled curated accuracy corpus", report["curated_accuracy"])
    piimb = report.get("standardized_masking_benchmark")
    if piimb is not None:
        score = piimb["overall"]
        lines += [
            "## B. Standardized open-source masking benchmark (PIIMB)",
            "",
            f"- Rows scored: **{piimb['rows_scored']}**",
            f"- Characters scored: **{piimb['characters_scored']}**",
            f"- Precision: **{_pct(score['precision'])}**",
            f"- Recall: **{_pct(score['recall'])}**",
            f"- F1: **{_pct(score['f1'])}**",
            f"- F2: **{_pct(score['f2'])}**",
            f"- Character FPR: **{_pct(score['fpr'])}**",
            f"- Median latency: **{piimb['performance']['median_sentence_ms']} ms/sentence**",
            "",
        ]
    else:
        lines += [
            "## B. Standardized open-source masking benchmark (PIIMB)",
            "",
            "**NOT RUN in this report.** Use `scripts/run_veilbench_piimb.sh <jsonl> [limit]`. VeilGraph does not claim the Stage-1 open-source benchmark requirement is closed until this section contains measured results.",
            "",
        ]

    if report.get("open_source_accuracy") is not None:
        lines += _accuracy_lines("C. Optional OpenPII entity-type benchmark", report["open_source_accuracy"])
        dataset = report["open_source_accuracy"]["dataset"]
        lines += [
            f"OpenPII input file: `{dataset['input_file']}`",
            f"Mapped gold spans: **{dataset['mapped_gold_spans']}** · Unmapped gold spans disclosed: **{dataset['unmapped_gold_spans']}**",
            "",
        ]

    if report.get("system_evidence") is not None:
        system = report["system_evidence"]
        lines += [
            "## D. End-to-end release-safety evidence",
            "",
            f"Overall: **{'PASS' if system['overall_pass'] else 'FAIL'}** · {system['cases_passed']}/{system['case_count']} cases passed",
            f"Mandatory attack pass rate: **{system['mandatory_attack_pass_rate'] * 100:.1f}%**",
            "",
        ]
        for case in system["cases"]:
            lines += [
                f"### {case['name']}",
                "",
                f"- Result: **{'PASS' if case['passed'] else 'FAIL'}**",
                f"- Duration: {case['duration_ms']} ms",
                f"- Entities / mentions: {case['canonical_entities']} / {case['mentions']}",
                f"- Graph: {case['graph_nodes']} nodes / {case['graph_edges']} edges",
                f"- Exposure: {case['risk_before']} → {case['residual_risk']}",
                f"- Utility retained: {case['utility_score']}",
                f"- Privacy Red Team: {case['attacks_passed']}/{case['attack_coverage']} PASS · Proof {case['proof_score']}/100",
                f"- Certificate signature valid: {case['certificate_signature_valid']}",
                "",
            ]

    lines += [
        "## Claim boundaries",
        "",
        "- Precision/Recall/F1 apply only to the explicitly named and sampled benchmark corpus.",
        "- Unmapped third-party entity classes are disclosed rather than silently scored as negatives.",
        "- Release-safety tests demonstrate the implemented attacks and fixtures; they do not constitute a legal or mathematical guarantee of anonymity.",
        "- Process RSS is a process-wide maximum and includes imported/native dependencies.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run VeilBench v1.0")
    parser.add_argument("--piimb-jsonl", type=Path, help="Optional local PIIMB sentences JSONL file (recommended external benchmark)")
    parser.add_argument("--piimb-task", default="ai4privacy-en", help="PIIMB task filter; use all to disable")
    parser.add_argument("--piimb-limit", type=int, default=5000, help="Maximum PIIMB rows to score")
    parser.add_argument("--openpii-jsonl", type=Path, help="Optional local Ai4Privacy OpenPII JSONL file")
    parser.add_argument("--openpii-limit", type=int, default=500, help="Maximum mapped OpenPII rows to score")
    parser.add_argument("--openpii-language", default="en", help="Language filter for OpenPII rows; use 'all' to disable")
    parser.add_argument("--skip-system", action="store_true", help="Skip slower PDF/OCR end-to-end evidence cases")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    curated = benchmark_curated(CURATED_CORPUS)
    piimb = None
    if args.piimb_jsonl is not None:
        task = None if args.piimb_task.casefold() == "all" else args.piimb_task
        piimb = benchmark_piimb(args.piimb_jsonl, task=task, limit=args.piimb_limit)
    open_source = None
    if args.openpii_jsonl is not None:
        language = None if args.openpii_language.casefold() == "all" else args.openpii_language
        open_source = benchmark_openpii(
            args.openpii_jsonl,
            limit=args.openpii_limit,
            language=language,
        )
    system = None if args.skip_system else _system_benchmark()

    report = {
        "schema": "veilgraph.veilbench.v1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "tesseract": _tool_version("tesseract"),
            "pdftotext": _tool_version("pdftotext"),
            "offline_mode": True,
        },
        "curated_accuracy": curated,
        "standardized_masking_benchmark": piimb,
        "open_source_accuracy": open_source,
        "system_evidence": system,
        "completion": {
            "precision_recall_f1_engine": True,
            "curated_accuracy_benchmark": True,
            "open_source_testing_dataset_measured": piimb is not None or open_source is not None,
            "standardized_piimb_measured": piimb is not None,
            "end_to_end_release_benchmark": system is not None,
        },
        "claim_boundary": "Metrics are corpus-specific measured evidence, not universal accuracy or anonymity guarantees.",
    }
    _write_report(report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Wrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")
    if system is not None and not system["overall_pass"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
