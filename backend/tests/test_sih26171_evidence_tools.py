from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.browser.evidence import LoopEvidenceError, record_secure_loop_evidence


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def complete_loop() -> dict:
    return {
        "contract": "SECURE_AGENT_LOOP_V1",
        "loop_id": "VGL-AAAAAAAAAAAAAAAAAAAAAAAA",
        "status": "COMPLETE",
        "task": "Open follow-up options and complete it",
        "step_count": 2,
        "max_steps": 6,
        "started_at": "2026-08-25T11:00:00Z",
        "ended_at": "2026-08-25T11:00:30Z",
        "pending_execution": None,
        "stop_reason": None,
        "trace": [
            {"sequence": 1, "stage": "PRIVACY", "elapsed_ms": 100},
            {"sequence": 2, "stage": "EXECUTE", "elapsed_ms": 5},
        ],
    }


def test_loop_evidence_rejects_raw_private_material(tmp_path, monkeypatch):
    import app.browser.evidence as evidence
    monkeypatch.setattr(evidence, "OUT", tmp_path)
    raw = complete_loop()
    raw["task"] = "Aarav Mehta"
    with pytest.raises(LoopEvidenceError, match="raw/private"):
        record_secure_loop_evidence({"browser": "Chrome/140", "result": raw})


def test_loop_evidence_records_complete_sanitized_trace(tmp_path, monkeypatch):
    import app.browser.evidence as evidence
    monkeypatch.setattr(evidence, "OUT", tmp_path)
    result = record_secure_loop_evidence({"browser": "Chrome/140", "result": complete_loop()})
    assert result["status"] == "RECORDED"
    assert result["browser_family"] == "chrome"
    stored = json.loads((tmp_path / "chrome-VGL-AAAAAAAAAAAAAAAAAAAAAAAA.json").read_text())
    assert stored["result"]["status"] == "COMPLETE"


def test_egress_witness_detects_raw_canary_and_forbidden_key():
    witness = load_script("veilgraph_witness_test", "scripts/egress_witness.py")
    unsafe = {
        "schema": "veilgraph.browser-reasoning-request.v1",
        "payload": {
            "schema": "veilgraph.browser-release-payload.v1",
            "frames": [{"raw_value": "Aarav Mehta"}],
        },
        "authorization": {"payload": {"decision": "ALLOW_NETWORK_RELEASE"}},
    }
    result = witness.inspect_external_request(json.dumps(unsafe).encode())
    assert result["clean_external_request"] is False
    assert result["raw_canary_count"] >= 1
    assert result["forbidden_raw_key_count"] >= 1
