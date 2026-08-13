#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    # Final backend privacy / release hardening.
    "backend/app/transformation/sanitizer.py": "eaebb8dffd4848b61a108f17eb600c033236756ff758514f8df961702eda4ac5",
    "backend/app/verification/red_team.py": "fc658dc08344b9ed399e0dcfc2b01cb137957387d2bd3f959d19a80d1b7bcefa",
    "backend/app/policy/compiler.py": "354081afa1fa2fedf38f3bae0996f50306d34949c098043703c5e3269aa9867a",
    "backend/app/api/routes.py": "121272681bab371d2ee4479a9bac47fd3db966e01d295da650ed0f31ce968343",
    "backend/app/transformation/synthetic_export.py": "4015bef6f42edbdf14a7336a7ea6ac1eda56dcfe3edfd9630e5b5f557ca4517c",
    # Final UI v14.6.
    "frontend/index.html": "ebb9ec2586df1cc16f73ee21f9bd9e92014301c6f5fc4442dfdb3d553b435cd9",
    "frontend/src/App.tsx": "d34fbf55cfada4b93e3cbdc2b008dd73a0dcb08fd22b84cdced177f9b78af4e9",
    "frontend/src/styles.css": "31b94f0feba426e9bc7ba64b2b2bc555a61307c83662b38748388cc2f8de37e4",
    "frontend/src/api/client.ts": "5e1017be1a3c8c48d429c79864b0bc1e10e718c91b90700cdaff740e2b00a143",
    "frontend/public/veilgraph-brand-light.png": "c27bf78a8d1c612be9a7429a4f612c1c2632c1f499770030709b6c4a825db60f",
    "frontend/public/veilgraph-brand-dark.png": "de6a0351d7bca50e843631829c9a535c9f3bc6ad15dfed27ba4889a5eb24e82e",
    # Final regression fixtures that specifically lock the bugs found in real manual testing.
    "backend/tests/test_native_pdf_text_hardening_v147.py": "b90d17c13c008b69fc55cdc44789c95a2644fadd26ef452fbd0e02570fd68280",
    "backend/tests/test_locality_release_hardening_v148.py": "aad32ac9ffba5c9b305cdd223d6ae00c741063af8989c2e66a2432421aa77a12",
    "backend/tests/test_scanned_ocr_residual_closure_v149.py": "d2663fe490fc5aa41506f12d883c380765bb536a732c9eda58bc2d2c5d387020",
    "backend/tests/test_phase3_pre_finals.py": "cdf8c176ef7620b837bacd6fb4a358658c11e561210424dd210f7258a34f2bdd",
    # Accepted Phase-3 evidence runners / COTS recovery.
    "scripts/run_gradation_calibration.py": "7eea02ca07b82a16cd6ac3c6f7c50647c56603c5672de5e037d08dd736fc7415",
    "scripts/run_model_learning_evidence.py": "ce37004cbda4c71a8180f26d16d0caff3accd86846f74dbb68a8ed482d3d8482",
    "scripts/run_secure_online_acceptance.py": "9dc03bc9e4fd021abef5c581edd285a8926b7d359593bbb54dea16160d697263",
    "scripts/run_cots_benchmark.py": "3e84b0875deb8720e9d0e7ecbda6eda2c1fa0f52cb3b52749c2434061091ad7e",
    "scripts/setup_cots_benchmark.sh": "29a97fa0fea595df5edeb7c0e87ae16cfbb8ceb486edf6accb5fea77bde41c26",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    bad: list[str] = []
    for rel, expected in EXPECTED.items():
        p = ROOT / rel
        if not p.is_file():
            bad.append(f"MISSING {rel}")
            continue
        actual = sha(p)
        if actual != expected:
            bad.append(f"HASH_MISMATCH {rel} expected={expected} actual={actual}")
    if bad:
        print("VeilGraph final post-hardening base INVALID")
        print("\n".join(bad))
        return 1
    print(f"VeilGraph final post-hardening base VALID: {len(EXPECTED)}/{len(EXPECTED)} locked files exact")
    print("UI v14.6 + backend v14.7/v14.8/v14.9 + Phase-3 evidence runners match the accepted final state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
