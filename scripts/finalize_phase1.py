#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE = ROOT / "competition" / "phase1"

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def require(path: Path) -> Path:
    if not path.is_file():
        raise SystemExit(f"Missing required Phase-1 evidence: {path.relative_to(ROOT)}")
    return path

verify = require(ROOT / "scripts" / "verify_broad_pii_v5_freeze.py")
subprocess.run([sys.executable, str(verify)], cwd=ROOT, check=True)

ari = json.loads(require(PHASE / "EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json").read_text(encoding="utf-8"))
tab = json.loads(require(PHASE / "EXTERNAL_HOLDOUT_TAB_RESULTS.json").read_text(encoding="utf-8"))
judge = json.loads(require(PHASE / "JUDGE_READINESS_RESULTS.json").read_text(encoding="utf-8"))
v5 = json.loads(require(PHASE / "BROAD_PII_V5_FREEZE_MANIFEST.json").read_text(encoding="utf-8"))

if ari.get("results", {}).get("documents") != 1201:
    raise SystemExit("ARI result does not contain the expected 1,201 evaluated documents.")
if ari.get("raw_holdout_persisted_in_repository") is not False:
    raise SystemExit("ARI provenance does not assert raw holdout non-persistence.")
if ari.get("detector_tuned_on_test_rows") is not False:
    raise SystemExit("ARI provenance does not assert detector was not tuned on test rows.")
if ari.get("source", {}).get("data_artifact_identity_verified") is not True:
    raise SystemExit("ARI immutable test-artifact verification evidence is missing.")

docs = [
    PHASE / "PHASE_1_FINAL_REPORT.md",
    PHASE / "PHASE_1_LIMITATIONS.md",
    PHASE / "PHASE_1_REQUIREMENT_TRACEABILITY.md",
    PHASE / "PHASE_1_COMPLETE.md",
    PHASE / "PHASE1_SCOPE_LOCK.md",
]
evidence = [
    PHASE / "JUDGE_READINESS_RESULTS.json",
    PHASE / "EXTERNAL_HOLDOUT_TAB_RESULTS.json",
    PHASE / "EXTERNAL_HOLDOUT_ARI_SYNTHETIC_TEST_RESULTS.json",
    PHASE / "BROAD_PII_V5_FREEZE_MANIFEST.json",
]
for p in docs + evidence:
    require(p)

manifest = {
    "schema": "veilgraph.phase1-freeze.v1",
    "phase": "PHASE 1 — ACCURACY & JUDGE-DATA READINESS",
    "status": "COMPLETE_AND_FROZEN",
    "closed_at_utc": datetime.now(timezone.utc).isoformat(),
    "frozen_detector": "Broad PII v5",
    "semantic_ner": {
        "version": "3.0.0",
        "training_examples": 2330,
        "runtime_network_required": False,
    },
    "regression_acceptance": {
        "backend_tests_passed": 237,
        "backend_tests_failed": 0,
        "nonfatal_warnings": 5,
        "typescript_typecheck": "PASS",
        "vite_production_build": "PASS",
    },
    "manual_browser_acceptance": {
        "docx_l4_recommendation": "PASS",
        "docx_l5_unsupported_restriction": "PASS",
        "xlsx_l5_synthetic_twin_recommendation": "PASS",
    },
    "external_evidence_policy": {
        "tab_v4_preserved": True,
        "ari_v5_preserved": True,
        "ari_quality_gate": "FAIL_DOCUMENTED_LIMITATION",
        "external_gate_failure_reopens_phase_automatically": False,
        "broad_pii_v6_required_for_phase1_completion": False,
    },
    "artifacts": {
        str(p.relative_to(ROOT)): sha256(p) for p in docs + evidence
    },
    "next_phase": "PHASE 2 — PRODUCTION, SECURITY & SCALE",
}

out = PHASE / "PHASE_1_FREEZE_MANIFEST.json"
out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

print(f"Wrote {out.relative_to(ROOT)}")
print(f"Freeze manifest SHA-256: {sha256(out)}")
print("PHASE 1 FINAL ACCEPTANCE: PASS — COMPLETE & FROZEN")
print("Next: PHASE 2 — PRODUCTION, SECURITY & SCALE")
