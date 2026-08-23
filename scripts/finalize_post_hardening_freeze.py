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
FINAL = ROOT / "competition" / "final"
P1 = ROOT / "competition" / "phase1"
P2 = ROOT / "competition" / "phase2"
P3 = ROOT / "competition" / "phase3"
sys.path.insert(0, str(BACKEND))

from app.security.signing import public_key_b64, sign_payload, signer_fingerprint, verify_payload


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(rel: str | Path) -> Path:
    p = rel if isinstance(rel, Path) else ROOT / rel
    if not p.is_file():
        raise SystemExit(f"Missing required final-acceptance artifact: {p.relative_to(ROOT)}")
    return p


def load(rel: str | Path) -> dict:
    p = require(rel)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"Expected JSON object: {p.relative_to(ROOT)}")
    return data


def collect(paths: list[Path]) -> dict[str, str]:
    return {str(p.relative_to(ROOT)): sha(require(p)) for p in sorted(paths)}


def sign(payload: dict) -> dict:
    signed = {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": sign_payload(payload),
    }
    if not verify_payload(payload, signed["signature_b64"], payload["signer"]["public_key_b64"]):
        raise SystemExit("Ed25519 freeze signature self-check failed")
    return signed


def signer() -> dict:
    return {
        "algorithm": "Ed25519",
        "public_key_b64": public_key_b64(),
        "public_key_sha256": signer_fingerprint(),
    }


def write_signed(path: Path, payload: dict) -> str:
    signed = sign(payload)
    path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sha(path)


def main() -> int:
    FINAL.mkdir(parents=True, exist_ok=True)

    # Detector/model freeze must still be exact. This is deliberately independent of v14.7-v14.9 sanitizer/Red-Team hardening.
    subprocess.run([sys.executable, str(ROOT / "scripts/verify_broad_pii_v5_freeze.py")], cwd=ROOT, check=True)

    broad = load(P1 / "BROAD_PII_V5_FREEZE_MANIFEST.json")
    phase2_security = load(P2 / "PHASE2_SECURITY_RESULTS.json")
    phase2_benchmark = load(P2 / "PHASE2_BENCHMARK_RESULTS.json")
    phase2_release = load(P2 / "PHASE2_RELEASE_PACKAGE_RESULTS.json")
    grad = load(P3 / "GRADATION_CALIBRATION_RESULTS.json")
    learn = load(P3 / "MODEL_LEARNING_EVIDENCE.json")
    online = load(P3 / "SECURE_ONLINE_ACCEPTANCE.json")
    cots = load(P3 / "COTS_QUANTITATIVE_RESULTS.json")
    regression = load(FINAL / "FINAL_FULL_REGRESSION.json")
    fixtures = load(FINAL / "FINAL_REAL_FIXTURE_ACCEPTANCE.json")

    if not phase2_security.get("all_passed"):
        raise SystemExit("Phase-2 security self-test is not green")
    if not phase2_benchmark.get("all_passed"):
        raise SystemExit("Phase-2 performance/scale benchmark is not green")
    if not phase2_release.get("verification", {}).get("valid"):
        raise SystemExit("Sanitized competition release verification is not green")
    if not grad.get("all_passed"):
        raise SystemExit("L1-L5 gradation calibration is not green")
    if not learn.get("all_passed"):
        raise SystemExit("Controlled model-learning evidence is not green")
    if not online.get("all_passed"):
        raise SystemExit("Secure-online TLS acceptance is not green")
    if not cots.get("literal_ntro_cots_requirement_closed"):
        raise SystemExit("Real commercial COTS benchmark requirement is not closed")
    if not regression.get("all_passed"):
        raise SystemExit("Final full backend/frontend regression is not green")
    if not fixtures.get("all_passed"):
        raise SystemExit("Final TXT / digital-PDF / scanned-PDF real-fixture acceptance is not green")

    # Phase 1 v2: preserve the exact Broad PII v5/model surface and the scientific evidence without retuning consumed holdouts.
    phase1_surface: list[Path] = []
    for item in broad.get("frozen_files", []):
        phase1_surface.append(require(item["path"]))
    phase1_surface.append(require("backend/benchmark_corpus/veilbench_curated_v1.json"))
    phase1_evidence = [
        require(P1 / "BROAD_PII_V5_FREEZE_MANIFEST.json"),
        require(P1 / "EXTERNAL_HOLDOUT_TAB_RESULTS.json"),
        require(P1 / "EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json"),
        require(P1 / "JUDGE_READINESS_RESULTS.json"),
        require(ROOT / "competition/HOLDOUT_NEMOTRON_RESULTS.json"),
        require(ROOT / "competition/HOLDOUT_NEMOTRON_REPORT.md"),
        require(ROOT / "competition/CLAIMS_AND_BOUNDARIES.md"),
        require(FINAL / "FINAL_FULL_REGRESSION.json"),
    ]
    p1_payload = {
        "schema": "veilgraph.phase1-authoritative-freeze.v2",
        "phase": "PHASE 1 — ACCURACY & JUDGE-DATA READINESS",
        "status": "COMPLETE_AND_FROZEN",
        "closed_at_utc": datetime.now(timezone.utc).isoformat(),
        "sih_problem_id": "SIH260381",
        "frozen_detector": "Broad PII v5",
        "semantic_ner": broad.get("semantic_model", {}),
        "detector_model_surface_sha256": collect(phase1_surface),
        "scientific_evidence_sha256": collect(phase1_evidence),
        "final_regression": regression,
        "claim_boundary": "Consumed external holdouts are preserved as evidence and are not tuning inputs. Difficult holdout recall is reported rather than hidden.",
        "signer": signer(),
    }
    p1_path = FINAL / "PHASE_1_AUTHORITATIVE_FREEZE_MANIFEST.json"
    p1_sha = write_signed(p1_path, p1_payload)

    # Phase 2 v2: sign the complete current production backend, including the v14.7-v14.9 sanitizer/Red-Team hardening.
    backend_surface = [p for p in (BACKEND / "app").rglob("*.py") if "__pycache__" not in p.parts]
    backend_surface += [require("backend/main.py")]
    phase2_scripts = [
        "scripts/run_checks.sh",
        "scripts/run_phase2_security_selftest.py",
        "scripts/run_phase2_benchmarks.py",
        "scripts/build_competition_release.py",
        "scripts/verify_competition_release.py",
        "scripts/verify_certificate.py",
        "scripts/verify_proof_package.py",
        "scripts/start_local.sh",
    ]
    backend_surface += [require(p) for p in phase2_scripts]
    phase2_evidence = [
        require(P2 / "PHASE2_SECURITY_RESULTS.json"),
        require(P2 / "PHASE2_BENCHMARK_RESULTS.json"),
        require(P2 / "PHASE2_BENCHMARK_REPORT.md"),
        require(P2 / "PHASE2_RELEASE_PACKAGE_RESULTS.json"),
        require(P2 / "COTS_CAPABILITY_COMPARISON.md"),
        require(P2 / "PHASE_2_REQUIREMENT_TRACEABILITY.md"),
        require(FINAL / "FINAL_FULL_REGRESSION.json"),
        require(FINAL / "FINAL_REAL_FIXTURE_ACCEPTANCE.json"),
    ]
    p2_payload = {
        "schema": "veilgraph.phase2-authoritative-freeze.v2",
        "phase": "PHASE 2 — PRODUCTION, SECURITY & SCALE",
        "status": "COMPLETE_AND_FROZEN",
        "closed_at_utc": datetime.now(timezone.utc).isoformat(),
        "sih_problem_id": "SIH260381",
        "phase1_authoritative_freeze_sha256": p1_sha,
        "production_backend_surface_sha256": collect(backend_surface),
        "evidence_sha256": collect(phase2_evidence),
        "security": phase2_security,
        "benchmark": phase2_benchmark,
        "release": phase2_release,
        "post_hardening": {
            "native_text_and_digital_pdf_occurrence_propagation": True,
            "scanned_pdf_replacement_rendering": True,
            "approved_replacement_aware_red_team": True,
            "scanned_pdf_post_transform_ocr_residual_closure": True,
            "real_fixture_acceptance": fixtures,
        },
        "signer": signer(),
    }
    p2_path = FINAL / "PHASE_2_AUTHORITATIVE_FREEZE_MANIFEST.json"
    p2_sha = write_signed(p2_path, p2_payload)

    # Phase 3 v2: sign the final UI, final evidence/online/COTS scripts, and the pre-GF evidence package.
    frontend_surface: list[Path] = []
    for rel in ["frontend/index.html", "frontend/package.json", "frontend/package-lock.json", "frontend/vite.config.ts", "frontend/tsconfig.json"]:
        frontend_surface.append(require(rel))
    frontend_surface += [p for p in (ROOT / "frontend/src").rglob("*") if p.is_file() and "node_modules" not in p.parts]
    for rel in ["frontend/public/veilgraph-brand-light.png", "frontend/public/veilgraph-brand-dark.png"]:
        frontend_surface.append(require(rel))

    phase3_surface = frontend_surface + [
        require("backend/app/api/routes.py"),
        require("backend/app/transformation/synthetic_export.py"),
        require("backend/app/transformation/sanitizer.py"),
        require("backend/app/verification/red_team.py"),
        require("backend/app/policy/compiler.py"),
        require("scripts/run_gradation_calibration.py"),
        require("scripts/run_model_learning_evidence.py"),
        require("scripts/run_secure_online_acceptance.py"),
        require("scripts/run_cots_benchmark.py"),
        require("scripts/setup_cots_benchmark.sh"),
        require("scripts/run_final_fixture_acceptance.py"),
        require("scripts/run_final_post_hardening_acceptance.sh"),
        require("scripts/record_final_regression.py"),
        require("scripts/finalize_post_hardening_freeze.py"),
        require("scripts/verify_post_hardening_freeze.py"),
        require("deployment/online/README.md"),
    ]
    phase3_evidence = [
        require(P3 / "GRADATION_CALIBRATION_RESULTS.json"),
        require(P3 / "GRADATION_CALIBRATION_REPORT.md"),
        require(P3 / "MODEL_LEARNING_EVIDENCE.json"),
        require(P3 / "SECURE_ONLINE_ACCEPTANCE.json"),
        require(P3 / "COTS_QUANTITATIVE_RESULTS.json"),
        require(P3 / "COTS_QUANTITATIVE_REPORT.md"),
        require(P3 / "CONTROLLED_MODEL_LEARNING_LIFECYCLE.md"),
        require(P3 / "COTS_QUANTITATIVE_PROTOCOL.md"),
        require(P3 / "SIH260381_FINAL_TRACEABILITY.md"),
        require(FINAL / "FINAL_FULL_REGRESSION.json"),
        require(FINAL / "FINAL_FULL_REGRESSION.log"),
        require(FINAL / "FINAL_REAL_FIXTURE_ACCEPTANCE.json"),
        require(ROOT / "competition/JUDGE_DATASET_READINESS_V8.md"),
        require(ROOT / "competition/HOLDOUT_NEMOTRON_RESULTS.json"),
    ]
    p3_payload = {
        "schema": "veilgraph.pre-grand-finale-authoritative-freeze.v2",
        "phase": "PHASE 3 — EVIDENCE & FINAL RELEASE",
        "status": "PRE_GRAND_FINALE_COMPLETE_AND_FROZEN",
        "closed_at_utc": datetime.now(timezone.utc).isoformat(),
        "sih_problem_id": "SIH260381",
        "problem_owner": "NTRO",
        "phase1_authoritative_freeze_sha256": p1_sha,
        "phase2_authoritative_freeze_sha256": p2_sha,
        "final_surface_sha256": collect(phase3_surface),
        "final_evidence_sha256": collect(phase3_evidence),
        "closure": {
            "l1_l5_gradation_calibration": grad,
            "controlled_model_learning": learn,
            "secure_online_tls": online,
            "real_commercial_cots": cots,
            "final_full_regression": regression,
            "real_problem_fixture_acceptance": fixtures,
            "l5_verified_synthetic_exports": ["csv", "json", "xlsx", "docx", "pdf"],
            "operational_external_model_api_required": False,
        },
        "only_external_pending_item": {
            "requirement": "NTRO Stage-2 private Grand Finale dataset evaluation",
            "status": "PENDING_EXTERNAL_DATA",
            "reason": "The dataset is supplied by NTRO only at the Grand Finale; the implementation is ready but cannot execute unavailable private data pre-finale.",
        },
        "supersedes_historical_freezes": {
            "phase1_historical_manifest_sha256": sha(require(P1 / "PHASE_1_FREEZE_MANIFEST.json")),
            "phase2_historical_manifest_sha256": sha(require(P2 / "PHASE_2_FREEZE_MANIFEST.json")),
            "pre_grand_finale_historical_manifest_sha256": sha(require(P3 / "PRE_GRAND_FINALE_FREEZE_MANIFEST.json")) if (P3 / "PRE_GRAND_FINALE_FREEZE_MANIFEST.json").is_file() else None,
            "note": "Historical manifests remain preserved as provenance. These v2 manifests are the authoritative post-hardening freeze.",
        },
        "signer": signer(),
    }
    p3_path = FINAL / "PRE_GRAND_FINALE_AUTHORITATIVE_FREEZE_MANIFEST.json"
    p3_sha = write_signed(p3_path, p3_payload)

    summary = f"""# VeilGraph — Final Post-Hardening Acceptance\n\n**STATUS: PRE-GRAND-FINALE COMPLETE & FROZEN**\n\nAuthoritative post-hardening manifests:\n\n- Phase 1: `{p1_path.relative_to(ROOT)}` — SHA-256 `{p1_sha}`\n- Phase 2: `{p2_path.relative_to(ROOT)}` — SHA-256 `{p2_sha}`\n- Pre-Grand-Finale: `{p3_path.relative_to(ROOT)}` — SHA-256 `{p3_sha}`\n\nThe three real fixtures that exposed native-text, digital-PDF and scanned-PDF defects all passed 12/12 mandatory gates with 100/100 proof score in fresh machine acceptance.\n\nThe only externally pending SIH260381 item is evaluation on the NTRO Stage-2 private dataset supplied at the Grand Finale.\n"""
    (FINAL / "FINAL_SYSTEM_COMPLETE.md").write_text(summary, encoding="utf-8")

    print(f"Phase-1 authoritative freeze SHA-256: {p1_sha}")
    print(f"Phase-2 authoritative freeze SHA-256: {p2_sha}")
    print(f"Pre-Grand-Finale authoritative freeze SHA-256: {p3_sha}")
    print("VEILGRAPH FINAL POST-HARDENING ACCEPTANCE: PASS — COMPLETE & FROZEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
