#!/usr/bin/env python3
from __future__ import annotations

import base64
import io
import json
import math
import os
import platform
import resource
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

_TMP = tempfile.TemporaryDirectory(prefix="sih26171-scorecard-")
os.environ["VEILGRAPH_DATABASE_PATH"] = str(Path(_TMP.name) / "scorecard.db")
os.environ["VEILGRAPH_WORKSPACE_ROOT"] = str(Path(_TMP.name) / "jobs")
os.environ["VEILGRAPH_SIGNING_KEY_PATH"] = str(Path(_TMP.name) / "device.key")
os.environ["VEILGRAPH_OFFLINE_MODE"] = "true"

from app.benchmark.veilbench import benchmark_curated  # noqa: E402
from app.browser.models import BrowserLocalCaptureMetadata  # noqa: E402
from app.browser.privacy_pipeline import prepare_browser_release  # noqa: E402


OUT = ROOT / "artifacts" / "sih26171"
LIVE = OUT / "live-loop-samples"
CORPUS = BACKEND / "benchmark_corpus" / "veilbench_curated_v1.json"
MODEL = ROOT / "browser-extension" / "models" / "ultraface" / "version-RFB-320.onnx"

WEIGHTS = {
    "visual_context_accuracy": 25,
    "pii_precision_recall": 20,
    "redaction_precision": 20,
    "client_resource_utilization": 20,
    "end_to_end_latency": 15,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def f1(precision: float, recall: float) -> float:
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * p
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[low]
    part = pos - low
    return ordered[low] + (ordered[high] - ordered[low]) * part


def png() -> bytes:
    image = Image.new("RGB", (800, 600), "white")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


TARGET = (800, 3000, 4500, 3800)
S1 = (800, 800, 4500, 1400)
S2 = (800, 1600, 4500, 2200)
D1 = (5500, 3000, 7600, 3600)
D2 = (5500, 3800, 7600, 4400)

CASES = [
    ("account_settings", "Account settings", ("alice.benchmark@example.test", "email", "email"), ("VGSecret-ACCOUNT-01", "credential", "password")),
    ("followup_options", "Follow-up options", ("Benchmark Alice", "person_name", "text"), ("+91 90000 11111", "phone", "tel")),
    ("benefits_center", "Benefits center", ("ABCPD1234Q", "government_identifier", "text"), ("12 Benchmark Road Bengaluru", "location", "text")),
    ("review_order", "Review order", ("4111111111111111", "financial", "text"), ("checkout@example.test", "email", "email")),
    ("claims_dashboard", "Claims dashboard", ("Benchmark Condition Asthma", "health", "text"), ("Benchmark Patient Five", "person_name", "text")),
    ("security_settings", "Security settings", ("DOB 14 Feb 1992", "quasi_identifier", "text"), ("+91 90000 22222", "phone", "tel")),
    ("usage_dashboard", "Usage dashboard", ("VG-API-KEY-SECRET-0007", "credential", "password"), ("developer@example.test", "email", "email")),
    ("travel_itinerary", "Travel itinerary", ("P1234567", "government_identifier", "text"), ("Airport Road Bengaluru", "location", "text")),
    ("student_timetable", "Student timetable", ("Student Benchmark Nine", "person_name", "text"), ("student9@example.test", "email", "email")),
    ("statement_history", "Statement history", ("5500000000000004", "financial", "text"), ("+91 90000 33333", "phone", "tel")),
    ("support_ticket", "Support ticket", ("support-user@example.test", "email", "email"), ("VGSecret-SUPPORT-11", "credential", "password")),
    ("appointment_details", "Appointment details", ("Benchmark Patient Twelve", "person_name", "text"), ("DOB 11 Jun 2007", "quasi_identifier", "text")),
]


def element(local_id: str, label: str, role: str, bbox, value=None, input_type=None, hint=None) -> dict:
    return {
        "local_id": local_id,
        "tag": "input" if role == "textbox" else "button",
        "role": role,
        "accessible_name": label,
        "visible_text": "" if role == "textbox" else label,
        **({"input_type": input_type} if input_type else {}),
        **({"raw_value": value} if value is not None else {}),
        "disabled": False,
        "bbox": list(bbox),
        "privacy_hints": [hint] if hint else [],
    }


def metadata(index: int, label: str, first, second) -> tuple[BrowserLocalCaptureMetadata, list[str], str]:
    target_id = f"vg_target_{index:02d}_0001"
    elements = [
        element(f"vg_sensitive_{index:02d}_0001", "Private field one", "textbox", S1, first[0], first[2], first[1]),
        element(f"vg_sensitive_{index:02d}_0002", "Private field two", "textbox", S2, second[0], second[2], second[1]),
        element(target_id, label, "button", TARGET),
        element(f"vg_home_{index:02d}_0001", "Home", "button", D1),
        element(f"vg_help_{index:02d}_0001", "Help", "button", D2),
    ]
    raw = {
        "schema": "veilgraph.browser-local-capture.v1",
        "capture_id": "VGC-" + f"{index:024X}",
        "captured_at": "2026-08-25T12:00:00+00:00",
        "tab_id": index,
        "task": f"Open the {label}",
        "audience_profile": "PUBLIC_RELEASE",
        "requested_privacy_level": 4,
        "expected_frame_count": 1,
        "captured_frame_count": 1,
        "failed_frame_ids": [],
        "visual_perception_status": "UNAVAILABLE",
        "visual_findings": [],
        "frames": [{
            "frame_id": 0,
            "is_top_frame": True,
            "origin": f"https://case{index}.example.test",
            "href": f"https://case{index}.example.test/app",
            "title": "Synthetic benchmark workspace",
            "viewport_width": 800,
            "viewport_height": 600,
            "eligible_element_count": len(elements),
            "captured_element_count": len(elements),
            "capture_truncated": False,
            "shadow_root_count": 0,
            "capture_elapsed_ms": 0,
            "inaccessible_descendant_frames": 0,
            "elements": elements,
        }],
    }
    return BrowserLocalCaptureMetadata.model_validate(raw), [first[0], second[0]], target_id


def center(bbox, width: int, height: int) -> tuple[int, int]:
    x0, y0, x1, y1 = bbox
    x = round((x0 + x1) / 2 * width / 10000)
    y = round((y0 + y1) / 2 * height / 10000)
    return max(0, min(width - 1, x)), max(0, min(height - 1, y))


def redacted(image: Image.Image, bbox) -> bool:
    pixel = image.getpixel(center(bbox, image.width, image.height))
    if isinstance(pixel, tuple):
        return max(pixel[:3]) < 50
    return pixel < 50


def browser_benchmark() -> dict[str, Any]:
    screenshot = png()
    gt_tp = gt_fp = gt_fn = 0
    rd_tp = rd_fp = rd_fn = 0
    leaks = failures = 0
    durations: list[float] = []
    details: list[dict[str, Any]] = []

    for index, case in enumerate(CASES, start=1):
        name, label, first, second = case
        meta, values, target_id = metadata(index, label, first, second)
        started = time.perf_counter()
        try:
            result = prepare_browser_release(meta, screenshot)
        except Exception as exc:
            gt_fn += 1
            rd_fn += 2
            failures += 1
            details.append({"case": name, "error": f"{type(exc).__name__}: {exc}"})
            continue
        elapsed = (time.perf_counter() - started) * 1000
        durations.append(elapsed)

        serialized = result.model_dump_json()
        leaked = [value for value in values if value in serialized]
        leaks += len(leaked)

        if result.authorization.payload.decision != "ALLOW_NETWORK_RELEASE":
            failures += 1

        required = set(result.minimization.required_anchor_ids)
        if target_id in required:
            gt_tp += 1
        else:
            gt_fn += 1
        gt_fp += len(required - {target_id})

        visual = result.payload.page.visual_context
        sensitive = [False, False]
        safe_redacted = True
        if visual is not None:
            image = Image.open(
                io.BytesIO(base64.b64decode(visual.image_base64, validate=True))
            ).convert("RGB")
            sensitive = [redacted(image, S1), redacted(image, S2)]
            safe_redacted = redacted(image, TARGET)

        for hit in sensitive:
            if hit:
                rd_tp += 1
            else:
                rd_fn += 1
        if safe_redacted:
            rd_fp += 1

        details.append({
            "case": name,
            "target_grounded": target_id in required,
            "required_anchor_ids": sorted(required),
            "network_release": result.authorization.payload.decision,
            "proof_score": result.verification.proof_score,
            "mandatory_gates": result.authorization.payload.mandatory_gates,
            "mandatory_passed": result.authorization.payload.mandatory_passed,
            "critical_failures": result.verification.critical_failures,
            "raw_sensitive_values_leaked": len(leaked),
            "sensitive_regions_redacted": sum(sensitive),
            "safe_target_preserved": not safe_redacted,
            "elapsed_ms": round(elapsed, 3),
        })

    gp = gt_tp / (gt_tp + gt_fp) if gt_tp + gt_fp else 0.0
    gr = gt_tp / (gt_tp + gt_fn) if gt_tp + gt_fn else 0.0
    rp = rd_tp / (rd_tp + rd_fp) if rd_tp + rd_fp else 0.0
    rr = rd_tp / (rd_tp + rd_fn) if rd_tp + rd_fn else 0.0

    return {
        "case_count": len(CASES),
        "screen_context_grounding": {
            "tp": gt_tp, "fp": gt_fp, "fn": gt_fn,
            "precision": gp, "recall": gr, "f1": f1(gp, gr),
        },
        "redaction_roi": {
            "tp": rd_tp, "fp": rd_fp, "fn": rd_fn,
            "precision": rp, "recall": rr, "f1": f1(rp, rr),
            "sensitive_rois": rd_tp + rd_fn,
            "safe_task_rois": len(CASES),
            "safe_task_regions_preserved": len(CASES) - rd_fp,
        },
        "release_safety": {
            "raw_value_leaks": leaks,
            "release_failures": failures,
        },
        "local_pipeline": {
            "median_ms": round(statistics.median(durations), 3) if durations else None,
            "p95_ms": round(percentile(durations, 0.95), 3) if durations else None,
            "peak_process_rss_mb": round(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                / (1024 * 1024 if sys.platform == "darwin" else 1024),
                3,
            ),
        },
        "cases": details,
    }


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def live_evidence() -> dict[str, Any]:
    LIVE.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(LIVE.glob("*.json")):
        try:
            wrapper = json.loads(path.read_text(encoding="utf-8"))
            result = wrapper["result"]
        except Exception:
            continue
        if result.get("contract") != "SECURE_AGENT_LOOP_V1" or result.get("status") != "COMPLETE":
            continue
        try:
            wall = (parse_iso(result["ended_at"]) - parse_iso(result["started_at"])).total_seconds() * 1000
        except Exception:
            continue
        records.append({
            "file": path.name,
            "browser_family": wrapper.get("browser_family", "unknown"),
            "wall_ms": wall,
            "step_count": result.get("step_count"),
        })

    chrome = [item for item in records if item["browser_family"] == "chrome"]
    firefox = [item for item in records if item["browser_family"] == "firefox"]
    walls = [item["wall_ms"] for item in chrome]
    return {
        "records": records,
        "chrome_complete_runs": len(chrome),
        "firefox_complete_runs": len(firefox),
        "chrome_p50_ms": round(percentile(walls, 0.50), 3) if walls else None,
        "chrome_p90_ms": round(percentile(walls, 0.90), 3) if walls else None,
        "chrome_p95_ms": round(percentile(walls, 0.95), 3) if walls else None,
    }


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    browser = browser_benchmark()
    pii = benchmark_curated(CORPUS)
    live = live_evidence()
    egress = load_json(OUT / "egress-witness-latest.json") or {}
    resources = load_json(OUT / "resources-chrome.json") or {}
    adversarial = load_json(OUT / "adversarial-report.json") or {}

    visual = browser["screen_context_grounding"]
    redaction = browser["redaction_roi"]
    pii_overall = pii["overall"]

    egress_pass = (
        egress.get("request_count", 0) >= 1
        and egress.get("all_requests_clean") is True
        and egress.get("total_raw_canary_hits", 1) == 0
        and egress.get("total_forbidden_raw_key_hits", 1) == 0
    )
    resource_measured = (
        resources.get("sample_count", 0) >= 20
        and resources.get("baseline_rss_mb") is not None
        and resources.get("peak_rss_mb") is not None
    )

    gates = {
        "visual_context_accuracy": visual["f1"] >= 0.90,
        "pii_precision_recall": pii_overall["precision"] >= 0.90 and pii_overall["recall"] >= 0.95,
        "redaction_precision": redaction["precision"] >= 0.95 and redaction["recall"] >= 0.95,
        "client_resource_measured": resource_measured,
        "e2e_latency_distribution": live["chrome_complete_runs"] >= 5,
        "external_egress_proof": egress_pass,
        "chrome_live_validation": live["chrome_complete_runs"] >= 5,
        "firefox_live_validation": live["firefox_complete_runs"] >= 1,
        "adversarial_closure": adversarial.get("overall_pass") is True,
        "curated_release_safety": (
            browser["release_safety"]["raw_value_leaks"] == 0
            and browser["release_safety"]["release_failures"] == 0
        ),
    }

    report = {
        "schema": "veilgraph.sih26171-scorecard.v1",
        "generated_at": utc_now(),
        "problem_statement": "SIH26171",
        "official_weights": WEIGHTS,
        "note": "Measured evidence only; this is not an organizer-issued official SIH score.",
        "metric_1_visual_context_accuracy": {
            "weight": 25,
            "status": "MEASURED_CURATED_BROWSER",
            **visual,
            "case_count": browser["case_count"],
            "claim_boundary": (
                "Task-relevant browser-screen grounding on the named curated cases. "
                "Not a universal CV-accuracy claim."
            ),
        },
        "metric_2_pii_precision_recall": {
            "weight": 20,
            "status": "MEASURED_VEILBENCH_CURATED",
            "case_count": pii["case_count"],
            "gold_span_count": pii["gold_span_count"],
            "precision": pii_overall["precision"],
            "recall": pii_overall["recall"],
            "f1": pii_overall["f1"],
            "macro_f1": pii["macro_f1"],
            "claim_boundary": "Applies to the frozen bundled VeilBench curated corpus.",
        },
        "metric_3_redaction_precision": {
            "weight": 20,
            "status": "MEASURED_CURATED_BROWSER_ROI",
            **redaction,
            "claim_boundary": (
                "ROI-level sensitive redaction and task-safe-region preservation. "
                "Separate irrelevant-context minimization is not counted as a redaction false positive."
            ),
        },
        "metric_4_client_resource_utilization": {
            "weight": 20,
            "status": "MEASURED_LIVE_BROWSER" if resource_measured else "LIVE_MEASUREMENT_REQUIRED",
            "browser_process": resources or None,
            "packaged_ultraface_model_bytes": MODEL.stat().st_size if MODEL.exists() else None,
            "packaged_ultraface_model_mb": round(MODEL.stat().st_size / 1024 / 1024, 3) if MODEL.exists() else None,
            "local_pipeline": browser["local_pipeline"],
            "claim_boundary": (
                "Live RSS/CPU is aggregate Chrome-process-tree measurement on this machine, "
                "not extension-only RSS. Local pipeline/model footprint is reported separately."
            ),
        },
        "metric_5_end_to_end_latency": {
            "weight": 15,
            "status": "MEASURED_LIVE" if live["chrome_complete_runs"] >= 5 else "LIVE_SAMPLES_REQUIRED",
            "chrome_complete_runs": live["chrome_complete_runs"],
            "p50_ms": live["chrome_p50_ms"],
            "p90_ms": live["chrome_p90_ms"],
            "p95_ms": live["chrome_p95_ms"],
            "minimum_distribution_samples": 5,
            "claim_boundary": "Only real COMPLETE Chrome SECURE_AGENT_LOOP_V1 runs are included.",
        },
        "cross_browser": {
            "chrome_complete_runs": live["chrome_complete_runs"],
            "firefox_complete_runs": live["firefox_complete_runs"],
        },
        "external_egress_privacy_proof": {
            "status": "LIVE_BOUNDARY_PROOF_PASS" if egress_pass else "LIVE_PROOF_REQUIRED_OR_FAILED",
            **egress,
        },
        "adversarial": adversarial,
        "curated_browser_cases": browser["cases"],
        "release_gates": gates,
        "scorecard_release_ready": all(gates.values()),
    }

    (OUT / "scorecard-latest.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    pct = lambda v: f"{v * 100:.2f}%"
    lines = [
        "# VeilGraph — SIH26171 Official-Metric Evidence Scorecard",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "> This is measured engineering evidence against the five published metric categories. "
        "It is not an organizer-issued official score.",
        "",
        "## 1. Visual context accuracy — 25%",
        f"- Precision: **{pct(visual['precision'])}**",
        f"- Recall: **{pct(visual['recall'])}**",
        f"- F1: **{pct(visual['f1'])}**",
        f"- Cases: **{browser['case_count']}**",
        "",
        "## 2. PII precision / recall — 20%",
        f"- Precision: **{pct(pii_overall['precision'])}**",
        f"- Recall: **{pct(pii_overall['recall'])}**",
        f"- F1: **{pct(pii_overall['f1'])}**",
        f"- Macro F1: **{pct(pii['macro_f1'])}**",
        "",
        "## 3. Redaction precision — 20%",
        f"- ROI precision: **{pct(redaction['precision'])}**",
        f"- ROI recall: **{pct(redaction['recall'])}**",
        f"- ROI F1: **{pct(redaction['f1'])}**",
        f"- Safe task regions preserved: **{redaction['safe_task_regions_preserved']}/{redaction['safe_task_rois']}**",
        "",
        "## 4. Client resource utilization — 20%",
        f"- Status: **{report['metric_4_client_resource_utilization']['status']}**",
        f"- Chrome baseline RSS: **{resources.get('baseline_rss_mb')} MB**",
        f"- Chrome peak RSS: **{resources.get('peak_rss_mb')} MB**",
        f"- Chrome peak delta: **{resources.get('peak_delta_rss_mb')} MB**",
        f"- Chrome p95 aggregate CPU: **{resources.get('p95_cpu_percent_sum')}%**",
        f"- UltraFace model: **{report['metric_4_client_resource_utilization']['packaged_ultraface_model_mb']} MB**",
        "",
        "## 5. End-to-end latency — 15%",
        f"- COMPLETE Chrome runs: **{live['chrome_complete_runs']}**",
        f"- p50: **{live['chrome_p50_ms']} ms**",
        f"- p90: **{live['chrome_p90_ms']} ms**",
        f"- p95: **{live['chrome_p95_ms']} ms**",
        "",
        "## External privacy boundary",
        f"- Witness requests: **{egress.get('request_count', 0)}**",
        f"- Raw canary hits: **{egress.get('total_raw_canary_hits', 'n/a')}**",
        f"- Forbidden raw-key hits: **{egress.get('total_forbidden_raw_key_hits', 'n/a')}**",
        f"- Status: **{'PASS' if egress_pass else 'PENDING/FAIL'}**",
        "",
        "## Cross-browser",
        f"- Chrome COMPLETE: **{live['chrome_complete_runs']}**",
        f"- Firefox COMPLETE: **{live['firefox_complete_runs']}**",
        "",
        "## Release gates",
    ]
    for name, ready in gates.items():
        lines.append(f"- {name}: **{'PASS' if ready else 'PENDING/FAIL'}**")
    lines += [
        "",
        f"# RELEASE_READY = {report['scorecard_release_ready']}",
        "",
    ]
    (OUT / "SCORECARD_LATEST.md").write_text("\n".join(lines), encoding="utf-8")

    # Judge dashboard is static and generated only from measured scorecard values.
    dashboard = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VeilGraph SIH26171 Evidence</title>
<style>
:root{{font-family:Inter,system-ui,sans-serif;color:#f6f7fb;background:#090c12}}
body{{margin:0;padding:36px;max-width:1280px;margin:auto}}
h1{{font-size:42px;margin:0 0 6px}} .sub{{color:#9aa4b2;margin-bottom:28px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}}
.card{{background:#111722;border:1px solid #263247;border-radius:18px;padding:22px}}
.big{{font-size:34px;font-weight:800;margin:8px 0}} .ok{{color:#6ee7a8}} .warn{{color:#f6c76b}}
.small{{color:#9aa4b2;font-size:13px;line-height:1.5}} code{{color:#9ed0ff}}
.flow{{margin-top:22px;padding:22px;border-radius:18px;background:#0d131d;border:1px solid #263247;line-height:1.9}}
</style></head><body>
<h1>VeilGraph</h1><div class="sub">SIH26171 · Privacy-preserving browser vision agent · measured evidence</div>
<div class="grid">
<div class="card"><b>Visual context · 25%</b><div class="big">{pct(visual['f1'])} F1</div><div class="small">{browser['case_count']} curated browser grounding cases</div></div>
<div class="card"><b>PII detection · 20%</b><div class="big">{pct(pii_overall['f1'])} F1</div><div class="small">P {pct(pii_overall['precision'])} · R {pct(pii_overall['recall'])}</div></div>
<div class="card"><b>Redaction · 20%</b><div class="big">{pct(redaction['f1'])} F1</div><div class="small">Sensitive ROI redaction with safe-task preservation</div></div>
<div class="card"><b>Client resources · 20%</b><div class="big">{resources.get('peak_delta_rss_mb')} MB Δ</div><div class="small">Aggregate Chrome process-tree peak delta; UltraFace {report['metric_4_client_resource_utilization']['packaged_ultraface_model_mb']} MB</div></div>
<div class="card"><b>E2E latency · 15%</b><div class="big">{live['chrome_p50_ms']} ms p50</div><div class="small">p90 {live['chrome_p90_ms']} · p95 {live['chrome_p95_ms']} · n={live['chrome_complete_runs']}</div></div>
<div class="card"><b>External egress</b><div class="big {'ok' if egress_pass else 'warn'}">{'ZERO RAW HITS' if egress_pass else 'PENDING'}</div><div class="small">{egress.get('request_count',0)} exact outbound reasoning requests observed</div></div>
<div class="card"><b>Cross-browser</b><div class="big">{live['chrome_complete_runs']} / {live['firefox_complete_runs']}</div><div class="small">Chrome COMPLETE / Firefox COMPLETE</div></div>
<div class="card"><b>Release state</b><div class="big {'ok' if report['scorecard_release_ready'] else 'warn'}">{'RELEASE READY' if report['scorecard_release_ready'] else 'EVIDENCE PENDING'}</div></div>
</div>
<div class="flow"><b>Enforced data path</b><br>
Raw screen → local DOM/accessibility/vision → sensitive-data fusion → Identity Exposure Graph →
task-minimal sanitizer → 12 mandatory privacy attacks → signed release authorization →
central Qwen reasoning → typed action → deterministic local validation →
high-impact confirmation → fresh recapture → repeat.
</div>
<p class="small">Claim boundaries and benchmark protocol are documented in the repository. No benchmark number is represented as an organizer-issued SIH score.</p>
</body></html>'''
    (OUT / "judge-dashboard.html").write_text(dashboard, encoding="utf-8")

    claims = {
        "schema": "veilgraph.sih26171-claim-registry.v1",
        "generated_at": utc_now(),
        "claims": [
            {"claim": "Raw capture is encrypted before localhost delivery to the paired companion", "status": "VALIDATED", "evidence": "LOCAL_COMPANION_ENCRYPTED_TRANSPORT_V1 + secure transport tests"},
            {"claim": "External reasoning requests contain zero controlled raw PrismCare canaries", "status": "VALIDATED" if egress_pass else "PENDING", "evidence": "egress-witness-latest.json"},
            {"claim": "Controlled Chrome multi-cycle secure task completes", "status": "VALIDATED" if live["chrome_complete_runs"] >= 1 else "PENDING", "evidence": "live-loop-samples"},
            {"claim": "Firefox controlled secure task completes", "status": "VALIDATED" if live["firefox_complete_runs"] >= 1 else "PENDING", "evidence": "live-loop-samples"},
            {"claim": "Five-metric scorecard is release-ready", "status": "VALIDATED" if report["scorecard_release_ready"] else "PENDING", "evidence": "scorecard-latest.json"},
            {"claim": "Universal anonymity / zero unknown bugs", "status": "NOT_CLAIMED", "evidence": "Out of scope; explicitly prohibited overclaim"},
            {"claim": "WebGPU live validation", "status": "NOT_CLAIMED", "evidence": "Live browser path is ONNX Runtime Web WASM on current validated machine"},
        ],
    }
    (OUT / "claim-registry.json").write_text(
        json.dumps(claims, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print("SIH26171_SCORECARD_V1")
    print(f"VISUAL_F1={visual['f1']:.6f}")
    print(f"PII_PRECISION={pii_overall['precision']:.6f}")
    print(f"PII_RECALL={pii_overall['recall']:.6f}")
    print(f"REDACTION_F1={redaction['f1']:.6f}")
    print(f"CHROME_COMPLETE={live['chrome_complete_runs']}")
    print(f"FIREFOX_COMPLETE={live['firefox_complete_runs']}")
    print(f"EGRESS_PASS={egress_pass}")
    print(f"RESOURCE_MEASURED={resource_measured}")
    print(f"RELEASE_READY={report['scorecard_release_ready']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
