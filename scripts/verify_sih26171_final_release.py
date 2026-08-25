#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts" / "sih26171"
VERIFY = ROOT / "artifacts" / "verification" / "latest.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


required = {
    "scorecard": ART / "scorecard-latest.json",
    "egress": ART / "egress-witness-latest.json",
    "resources": ART / "resources-chrome.json",
    "adversarial": ART / "adversarial-report.json",
    "claims": ART / "claim-registry.json",
    "dashboard": ART / "judge-dashboard.html",
    "verification": VERIFY,
}

missing = [name for name, path in required.items() if not path.is_file()]
if missing:
    raise SystemExit("FINAL_RELEASE_BLOCKED: missing " + ", ".join(missing))

score = load(required["scorecard"])
egress = load(required["egress"])
adversarial = load(required["adversarial"])
verify = load(required["verification"])

checks = {
    "scorecard_release_ready": score.get("scorecard_release_ready") is True,
    "egress_clean": (
        egress.get("request_count", 0) >= 1
        and egress.get("all_requests_clean") is True
        and egress.get("total_raw_canary_hits", 1) == 0
        and egress.get("total_forbidden_raw_key_hits", 1) == 0
    ),
    "adversarial_pass": adversarial.get("overall_pass") is True,
    "full_checkpoint_validated": (
        verify.get("verification_mode") == "full"
        and verify.get("overall_status") == "VALIDATED"
        and verify.get("summary", {}).get("failed") == 0
        and verify.get("summary", {}).get("skipped") == 0
    ),
    "chrome_5_runs": score.get("cross_browser", {}).get("chrome_complete_runs", 0) >= 5,
    "firefox_1_run": score.get("cross_browser", {}).get("firefox_complete_runs", 0) >= 1,
}

release_ready = all(checks.values())

manifest_files = [
    ROOT / "README.md",
    ROOT / "ARCHITECTURE.md",
    ROOT / "SECURITY.md",
    ROOT / "THREAT_MODEL.md",
    ROOT / "EVALUATION.md",
    ROOT / "SIH_TRACEABILITY.md",
    ROOT / "PRIVACY_MODEL.md",
    ROOT / "PUBLIC_RELEASE.md",
    ROOT / "GRAND_FINALE_STAGE2.md",
    ROOT / "competition" / "SIH26171_BENCHMARK_PROTOCOL.md",
    *required.values(),
]
manifest = {
    "schema": "veilgraph.sih26171-final-release-manifest.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "validated_source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "release_ready": release_ready,
    "checks": checks,
    "files": {
        str(path.relative_to(ROOT)): {"sha256": digest(path), "bytes": path.stat().st_size}
        for path in manifest_files
        if path.is_file()
    },
}
(ART / "FINAL_RELEASE_MANIFEST.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

lines = [
    "VEILGRAPH SIH26171 FINAL RELEASE",
    "=" * 72,
]
for name, passed in checks.items():
    lines.append(f"{'PASS' if passed else 'FAIL'}  {name}")
lines += [
    "=" * 72,
    f"RESULT: {'RELEASE_READY' if release_ready else 'BLOCKED'}",
    f"MANIFEST: artifacts/sih26171/FINAL_RELEASE_MANIFEST.json",
]
(ART / "FINAL_RELEASE_RESULT.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
raise SystemExit(0 if release_ready else 2)
