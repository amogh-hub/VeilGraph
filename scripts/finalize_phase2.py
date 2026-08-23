#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.security.signing import public_key_b64, sign_payload, signer_fingerprint, verify_payload

PHASE1 = ROOT / "competition/phase1"
PHASE2 = ROOT / "competition/phase2"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(path: Path) -> Path:
    if not path.is_file():
        raise SystemExit(f"Missing required Phase-2 evidence: {path.relative_to(ROOT)}")
    return path


def load(path: Path) -> dict:
    value = json.loads(require(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"Expected JSON object: {path.relative_to(ROOT)}")
    return value


def main() -> int:
    phase1_manifest = require(PHASE1 / "PHASE_1_FREEZE_MANIFEST.json")
    phase1 = load(phase1_manifest)
    if phase1.get("status") != "COMPLETE_AND_FROZEN":
        raise SystemExit("Phase 1 is not recorded as COMPLETE_AND_FROZEN")

    subprocess.run([sys.executable, str(ROOT / "scripts/verify_broad_pii_v5_freeze.py")], cwd=ROOT, check=True)

    security = load(PHASE2 / "PHASE2_SECURITY_RESULTS.json")
    benchmark = load(PHASE2 / "PHASE2_BENCHMARK_RESULTS.json")
    release = load(PHASE2 / "PHASE2_RELEASE_PACKAGE_RESULTS.json")
    regression = load(PHASE2 / "PHASE2_FULL_REGRESSION.json")
    if security.get("schema") != "veilgraph.phase2-security-selftest.v2" or not security.get("all_passed"):
        raise SystemExit("Phase-2 v2 security self-test is not green")
    if benchmark.get("schema") != "veilgraph.phase2-benchmark.v2" or not benchmark.get("all_passed"):
        raise SystemExit("Phase-2 v2 performance/scale functional gates are not green")
    if not benchmark.get("detector_concurrency", {}).get("passed"):
        raise SystemExit("Detector concurrency probe is not green")
    if not benchmark.get("api_job_concurrency", {}).get("passed"):
        raise SystemExit("Integrated API-job concurrency/isolation probe is not green")
    if not release.get("verification", {}).get("valid"):
        raise SystemExit("Sanitized release package verification is not green")
    if regression.get("schema") != "veilgraph.phase2-full-regression.v2" or not regression.get("all_passed"):
        raise SystemExit("Strict full regression closure is not green")

    cots = require(PHASE2 / "COTS_CAPABILITY_COMPARISON.md")
    cots_protocol = require(PHASE2 / "COTS_BENCHMARK_PROTOCOL.md")
    scope = require(PHASE2 / "PHASE_2_SCOPE_LOCK.md")
    trace = require(PHASE2 / "PHASE_2_REQUIREMENT_TRACEABILITY.md")

    production_surface = [
        "backend/main.py",
        "backend/app/core/config.py",
        "backend/app/ops/__init__.py",
        "backend/app/ops/metrics.py",
        "backend/app/ops/admission.py",
        "backend/app/ops/status.py",
        "backend/app/ops/routes.py",
        "backend/app/security/deployment.py",
        "backend/app/security/network_guard.py",
        "backend/app/security/workspace.py",
        "backend/app/security/release_package.py",
        "backend/app/proof/package.py",
        "scripts/run_phase2_benchmarks.py",
        "scripts/run_phase2_security_selftest.py",
        "scripts/build_competition_release.py",
        "scripts/verify_competition_release.py",
        "scripts/record_phase2_regression.py",
        "scripts/finalize_phase2.py",
        "scripts/verify_phase2_freeze.py",
        "scripts/run_phase2_complete.sh",
    ]
    surface_hashes: dict[str, str] = {}
    for rel in production_surface:
        surface_hashes[rel] = sha256(require(ROOT / rel))

    evidence_paths = [
        PHASE2 / "PHASE2_SECURITY_RESULTS.json",
        PHASE2 / "PHASE2_BENCHMARK_RESULTS.json",
        PHASE2 / "PHASE2_BENCHMARK_REPORT.md",
        PHASE2 / "PHASE2_RELEASE_PACKAGE_RESULTS.json",
        PHASE2 / "PHASE2_FULL_REGRESSION.json",
        PHASE2 / "PHASE2_FULL_REGRESSION.log",
        cots,
        cots_protocol,
        scope,
        trace,
    ]
    evidence_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in evidence_paths}

    cases = benchmark.get("cases", [])
    summary_cases = [
        {
            "name": item.get("name"),
            "p50_ms": item.get("p50_ms"),
            "p95_ms": item.get("p95_ms"),
            "p50_process_cpu_ms": item.get("p50_process_cpu_ms"),
            "cpu_core_equivalent_pct_p50": item.get("cpu_core_equivalent_pct_p50"),
            "throughput_kib_s_p50": item.get("throughput_kib_s_p50"),
            "python_peak_alloc_mib": item.get("python_peak_alloc_mib"),
            "process_high_water_rss_mib": item.get("process_high_water_rss_mib"),
        }
        for item in cases
    ]

    release_path_value = release.get("output")
    if not isinstance(release_path_value, str):
        raise SystemExit("Sanitized release result does not contain an output path")
    release_path = require(ROOT / release_path_value)
    release_sha = sha256(release_path)
    if release_sha != release.get("sha256"):
        raise SystemExit("Sanitized release ZIP hash no longer matches Phase-2 release evidence")

    payload = {
        "schema": "veilgraph.phase2-freeze.v2",
        "phase": "PHASE 2 — PRODUCTION, SECURITY & SCALE",
        "status": "COMPLETE_AND_FROZEN",
        "closed_at_utc": datetime.now(timezone.utc).isoformat(),
        "phase1_detector_preserved": "Broad PII v5",
        "phase1_freeze_manifest_sha256": sha256(phase1_manifest),
        "production_surface_sha256": surface_hashes,
        "evidence_sha256": evidence_hashes,
        "security": {
            "checks_passed": security.get("passed"),
            "checks_total": security.get("total"),
            "all_passed": security.get("all_passed"),
        },
        "benchmark": {
            "all_passed": benchmark.get("all_passed"),
            "cases": summary_cases,
            "detector_concurrency": benchmark.get("detector_concurrency"),
            "api_job_concurrency": benchmark.get("api_job_concurrency"),
            "process_high_water_rss_mib": benchmark.get("process_high_water_rss_mib"),
        },
        "regression": regression,
        "release": {
            "path": release_path_value,
            "sha256": release_sha,
            "size_bytes": release.get("size_bytes"),
            "entry_count": release.get("entry_count"),
            "verification_valid": release.get("verification", {}).get("valid"),
        },
        "cots": {
            "capability_comparison_frozen": True,
            "quantitative_protocol_frozen": True,
            "quantitative_vendor_measurements_required_to_be_real_not_estimated": True,
            "quantitative_vendor_measurements_phase": "PHASE 3 — EVIDENCE & FINAL RELEASE",
        },
        "completion_rule": {
            "arbitrary_future_latency_target_reopens_phase": False,
            "phase1_accuracy_loop_reopened": False,
            "manual_acceptance_required_before_treating_this_freeze_as_authoritative": True,
        },
        "next_phase": "PHASE 3 — EVIDENCE & FINAL RELEASE",
        "signer": {
            "algorithm": "Ed25519",
            "public_key_b64": public_key_b64(),
            "public_key_sha256": signer_fingerprint(),
        },
    }
    signed = {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": sign_payload(payload),
    }
    if not verify_payload(payload, signed["signature_b64"], payload["signer"]["public_key_b64"]):
        raise SystemExit("Phase-2 freeze signature self-check failed")

    freeze = PHASE2 / "PHASE_2_FREEZE_MANIFEST.json"
    freeze.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_lines = [
        "# VeilGraph — Phase 2 Final Report",
        "",
        "## Status",
        "**PHASE 2 — PRODUCTION, SECURITY & SCALE: MACHINE GATES COMPLETE; MANUAL ACCEPTANCE REQUIRED**",
        "",
        f"- Security self-test: {security.get('passed')}/{security.get('total')} PASS",
        f"- Full regression: {regression.get('pytest_passed')} passed, {regression.get('pytest_failed')} failed",
        f"- OpenAPI generation: {'PASS' if regression.get('openapi_written') else 'FAIL'}",
        f"- TypeScript: {'PASS' if regression.get('typescript_typecheck') else 'FAIL'}",
        f"- Vite production build: {'PASS' if regression.get('vite_production_build') else 'FAIL'}",
        f"- Sanitized release package SHA-256: `{release_sha}`",
        f"- Detector concurrency: {benchmark.get('detector_concurrency', {}).get('completed')}/{benchmark.get('detector_concurrency', {}).get('workers')} deterministic workers",
        f"- Integrated API-job concurrency: {benchmark.get('api_job_concurrency', {}).get('completed')}/{benchmark.get('api_job_concurrency', {}).get('workers')} isolated jobs",
        f"- Process lifetime high-water RSS after benchmark: {benchmark.get('process_high_water_rss_mib')} MiB",
        "",
        "## Measured performance",
        "| Case | p50 ms | p95 ms | CPU p50 ms | CPU core-equiv % | KiB/s p50 | Python peak MiB | Process high-water RSS MiB |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in summary_cases:
        report_lines.append(
            f"| {item['name']} | {item['p50_ms']} | {item['p95_ms']} | {item['p50_process_cpu_ms']} | "
            f"{item['cpu_core_equivalent_pct_p50']} | {item['throughput_kib_s_p50']} | {item['python_peak_alloc_mib']} | "
            f"{item['process_high_water_rss_mib']} |"
        )
    report_lines += [
        "",
        "## Production/security controls ready for manual freeze acceptance",
        "- finite heavy-operation concurrency admission;",
        "- PII-free operational metrics honoring configured metric-window capacity;",
        "- offline localhost boundary plus fail-closed Python DNS/socket egress guard;",
        "- secure-online bearer-token boundary with trusted-proxy-only forwarded HTTPS;",
        "- 0700 workspace directories, 0600 encrypted blobs and atomic encrypted writes;",
        "- hardened proof ZIP verification limits/path checks;",
        "- preserved retention/destruction and signed proof architecture;",
        "- deterministic sanitized competition release builder excluding private/runtime material and enforcing exact manifest membership;",
        "- COTS/industry capability comparison plus frozen Phase-3 quantitative benchmark protocol;",
        "- strict regression closure derived from observed pytest/OpenAPI/TypeScript/Vite gates.",
        "",
        "## Claim boundaries",
        "- Python allocator peak does not include all native allocations.",
        "- Process high-water RSS is not per-case resident memory.",
        "- Commercial COTS quantitative results are not claimed until actually measured under the frozen protocol.",
        "",
        "## Next",
        "Run `scripts/verify_phase2_freeze.py`, inspect the generated evidence manually, and only then mark Phase 2 authoritative and move to **PHASE 3 — EVIDENCE & FINAL RELEASE**.",
    ]
    (PHASE2 / "PHASE_2_FINAL_REPORT.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    complete = """# VeilGraph — Phase 2 Machine Closure\n\n**PHASE 2 machine gates are COMPLETE. Manual acceptance is still required before the Phase-2 freeze is treated as authoritative.**\n\nPhase-1 Broad PII v5 remains preserved. Phase-2 production/security/scale controls and measured evidence are committed in `PHASE_2_FREEZE_MANIFEST.json`.\n\nNext after manual acceptance: **PHASE 3 — EVIDENCE & FINAL RELEASE**.\n"""
    (PHASE2 / "PHASE_2_COMPLETE.md").write_text(complete, encoding="utf-8")

    print(f"Wrote {freeze.relative_to(ROOT)}")
    print(f"Freeze manifest SHA-256: {sha256(freeze)}")
    print("PHASE 2 MACHINE ACCEPTANCE: PASS — MANUAL REVIEW STILL REQUIRED")
    print("Do not begin Phase 3 until the Phase-2 evidence is manually accepted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
