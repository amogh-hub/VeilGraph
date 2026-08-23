from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
EXTENSION_DIST = ROOT / "browser-extension" / "dist"

os.environ.setdefault("PYTHONPATH", str(BACKEND))
import sys
sys.path.insert(0, str(BACKEND))

from app.browser.models import (  # noqa: E402
    BrowserGateResult,
    BrowserPublicElement,
    BrowserPublicPage,
    BrowserReleasePayload,
    BrowserVerificationSummary,
)
from app.browser.release_gate import authorize_network_release  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.enums import TestStatus  # noqa: E402


def main() -> int:
    subprocess.run(
        ["npm", "run", "build"],
        cwd=ROOT / "browser-extension",
        check=True,
    )
    with tempfile.TemporaryDirectory(prefix="veilgraph-browser-interop-") as temp:
        settings.signing_key_path = Path(temp) / "device.key"
        payload = BrowserReleasePayload(
            session_id="session_interop_0123456789",
            task_id="task_interop_0123456789",
            task="Submit the sanitized form",
            page=BrowserPublicPage(
                origin="https://interop.example",
                title="Interop ✓",
                elements=[
                    BrowserPublicElement(
                        element_id="vg_interop_button",
                        role="button",
                        label="Submit",
                        text="Submit",
                        bbox=(1000, 2000, 3000, 2600),
                    )
                ],
            ),
            privacy_level=4,
            network_privacy_floor=4,
            identity_exposure_before=88,
            residual_identity_exposure=7,
            task_utility_score=97,
            minimization_basis_points=9100,
        )
        tests = [
            BrowserGateResult(
                name=f"gate_{index}",
                status=TestStatus.PASS,
                detail="passed",
                attack_class="browser_network_release",
                severity="critical",
            )
            for index in range(12)
        ]
        verification = BrowserVerificationSummary(
            tests=tests,
            proof_score=100,
            critical_failures=0,
            policy_floor_satisfied=True,
            forbidden_raw_fields_present=False,
            payload_commitment_valid=True,
            critical_exposure_present=False,
        )
        authorization = authorize_network_release(
            payload,
            verification,
            now=datetime(2026, 8, 23, 16, 30, tzinfo=timezone.utc),
            ttl_seconds=120,
        )
        fixture = Path(temp) / "fixture.json"
        fixture.write_text(
            json.dumps(
                {
                    "payload": payload.model_dump(mode="json", by_alias=True),
                    "authorization": authorization.model_dump(mode="json", by_alias=True),
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        verifier = Path(temp) / "verify.mjs"
        module_url = (EXTENSION_DIST / "security" / "releaseGate.js").resolve().as_uri()
        verifier.write_text(
            f"""
import fs from 'node:fs';
const {{ verifyNetworkAuthorization }} = await import({json.dumps(module_url)});
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const result = await verifyNetworkAuthorization(fixture.authorization, fixture.payload, Date.parse('2026-08-23T16:30:01Z'));
if (!result.allowed) {{ console.error(result); process.exit(1); }}
fixture.payload.task = 'tampered';
const tampered = await verifyNetworkAuthorization(fixture.authorization, fixture.payload, Date.parse('2026-08-23T16:30:01Z'));
if (tampered.allowed) {{ console.error('tampered payload was accepted'); process.exit(1); }}
console.log('Python↔browser release authorization interoperability: PASS');
""",
            encoding="utf-8",
        )
        subprocess.run(["node", str(verifier), str(fixture)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
