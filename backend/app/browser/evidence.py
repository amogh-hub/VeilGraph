from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts" / "sih26171" / "live-loop-samples"

_LOOP_ID = re.compile(r"^VGL-[A-F0-9]{24}$")
_FORBIDDEN_TOKENS = (
    "screenshotdataurl",
    "screenshot_data_url",
    "image_base64",
    "raw_value",
    "rawvalue",
    "aarav mehta",
    "pc-blr-482917",
    "aarav.mehta.demo@example.test",
    "+91 90000 48291",
    "14 feb 1992",
    "indiranagar, bengaluru",
    "synthetic orbit labs",
    "vg-canary-relation-7f91a2",
)


class LoopEvidenceError(ValueError):
    pass


def _browser_family(user_agent: str) -> str:
    folded = user_agent.casefold()
    if "firefox/" in folded:
        return "firefox"
    if "chrome/" in folded or "chromium/" in folded:
        return "chrome"
    return "unknown"


def _safe_result(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LoopEvidenceError("loop evidence result must be an object")

    if raw.get("contract") != "SECURE_AGENT_LOOP_V1":
        raise LoopEvidenceError("unsupported loop evidence contract")

    if raw.get("status") != "COMPLETE":
        raise LoopEvidenceError("only COMPLETE secure loops are accepted as latency evidence")

    loop_id = raw.get("loop_id")
    if not isinstance(loop_id, str) or not _LOOP_ID.fullmatch(loop_id):
        raise LoopEvidenceError("invalid loop_id")

    step_count = raw.get("step_count")
    max_steps = raw.get("max_steps")
    if not isinstance(step_count, int) or not 1 <= step_count <= 32:
        raise LoopEvidenceError("invalid step_count")
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 32:
        raise LoopEvidenceError("invalid max_steps")
    if step_count > max_steps:
        raise LoopEvidenceError("step_count exceeds max_steps")

    if raw.get("pending_execution") is not None:
        raise LoopEvidenceError("COMPLETE loop must not have pending execution")
    if raw.get("stop_reason") is not None:
        raise LoopEvidenceError("COMPLETE loop must not have stop_reason")

    trace = raw.get("trace")
    if not isinstance(trace, list) or not trace:
        raise LoopEvidenceError("loop evidence trace is missing")

    sequences = [item.get("sequence") for item in trace if isinstance(item, dict)]
    if sequences != list(range(1, len(trace) + 1)):
        raise LoopEvidenceError("loop trace sequence is not contiguous")

    if not any(item.get("stage") == "EXECUTE" for item in trace if isinstance(item, dict)):
        raise LoopEvidenceError("COMPLETE loop has no executed action")
    if not any(item.get("stage") == "PRIVACY" for item in trace if isinstance(item, dict)):
        raise LoopEvidenceError("COMPLETE loop has no privacy release stage")

    return raw


def record_secure_loop_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    user_agent = payload.get("browser")
    if not isinstance(user_agent, str) or not user_agent or len(user_agent) > 512:
        raise LoopEvidenceError("browser user-agent evidence is invalid")

    result = _safe_result(payload.get("result"))

    encoded = json.dumps(result, sort_keys=True, ensure_ascii=False)
    folded = encoded.casefold()
    hit = next((token for token in _FORBIDDEN_TOKENS if token in folded), None)
    if hit is not None:
        raise LoopEvidenceError("raw/private browser material appeared in loop evidence")

    family = _browser_family(user_agent)
    loop_id = result["loop_id"]

    OUT.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": "veilgraph.sih26171-live-loop-evidence.v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "browser_family": family,
        "user_agent": user_agent,
        "result": result,
    }

    path = OUT / f"{family}-{loop_id}.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)

    try:
        evidence_file = str(path.relative_to(ROOT))
    except ValueError:
        # Tests and alternate evidence sinks may intentionally place the
        # destination outside the repository. The runtime production path
        # remains repository-relative, while external test paths are safely
        # represented as absolute paths instead of failing.
        evidence_file = str(path)

    return {
        "status": "RECORDED",
        "browser_family": family,
        "loop_id": loop_id,
        "evidence_file": evidence_file,
    }
