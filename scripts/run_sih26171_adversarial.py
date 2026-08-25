#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
PYTHON = BACKEND / ".venv" / "bin" / "python"
OUT = ROOT / "artifacts" / "sih26171"
LOG = OUT / "adversarial-pytest.log"

TESTS = [
    "tests/test_browser_secure_transport.py",
    "tests/test_browser_capture_api.py",
    "tests/test_browser_privacy_pipeline.py",
    "tests/test_browser_release_gate.py",
    "tests/test_browser_reasoning.py",
    "tests/test_browser_action_confidence_v2.py",
]

ATTACK_MATRIX = [
    ("malicious localhost listener / raw capture interception", "test_browser_secure_transport.py"),
    ("transport replay / one-time session reuse", "test_browser_secure_transport.py"),
    ("transport endpoint confusion", "test_browser_secure_transport.py"),
    ("ciphertext tampering / AES-GCM authentication", "test_browser_secure_transport.py"),
    ("raw credential leakage", "test_browser_privacy_pipeline.py"),
    ("privacy-floor downgrade", "test_browser_privacy_pipeline.py"),
    ("inconclusive visual coverage", "test_browser_privacy_pipeline.py"),
    ("signed payload tampering", "test_browser_release_gate.py"),
    ("wrong / untrusted signer", "test_browser_reasoning.py"),
    ("authorization replay", "test_browser_reasoning.py"),
    ("hostile model target selection", "test_browser_reasoning.py"),
    ("invalid typed action shape", "test_browser_reasoning.py"),
    ("terminal non-DONE/WAIT action", "test_browser_reasoning.py"),
    ("ambiguous click target autonomy", "test_browser_action_confidence_v2.py"),
    ("unrelated click target autonomy", "test_browser_action_confidence_v2.py"),
    ("high-impact confirmation bypass", "test_browser_action_confidence_v2.py"),
]

OUT.mkdir(parents=True, exist_ok=True)
proc = subprocess.run(
    [str(PYTHON), "-m", "pytest", *TESTS, "-q"],
    cwd=str(BACKEND),
    env={**__import__("os").environ, "PYTHONPATH": "."},
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    check=False,
)
LOG.write_text(proc.stdout, encoding="utf-8")

match = re.findall(r"(\d+) passed(?:,\s*(\d+) warnings?)?", proc.stdout)
passed = int(match[-1][0]) if match else 0
warnings = int(match[-1][1] or 0) if match else 0

report = {
    "schema": "veilgraph.sih26171-adversarial-closure.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "overall_pass": proc.returncode == 0,
    "pytest_passed": passed,
    "pytest_warnings": warnings,
    "test_files": TESTS,
    "attack_matrix": [
        {"attack": attack, "covered_by": test, "status": "PASS" if proc.returncode == 0 else "REVIEW"}
        for attack, test in ATTACK_MATRIX
    ],
    "claim_boundary": (
        "Coverage applies to the named implemented attacks and regression fixtures. "
        "It is not a mathematical guarantee against every possible browser attack."
    ),
}
(OUT / "adversarial-report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

lines = [
    "# SIH26171 Adversarial Closure",
    "",
    f"Overall: **{'PASS' if report['overall_pass'] else 'FAIL'}**",
    f"Pytest: **{passed} passed**, {warnings} warnings",
    "",
    "| Attack | Regression evidence | Status |",
    "|---|---|---|",
]
for row in report["attack_matrix"]:
    lines.append(f"| {row['attack']} | `{row['covered_by']}` | {row['status']} |")
lines += ["", report["claim_boundary"], ""]
(OUT / "ADVERSARIAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

print(f"ADVERSARIAL_CLOSURE={'PASS' if report['overall_pass'] else 'FAIL'}")
print(f"PYTEST_PASSED={passed}")
raise SystemExit(proc.returncode)
