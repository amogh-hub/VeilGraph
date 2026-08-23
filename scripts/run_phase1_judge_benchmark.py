#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import re
import sys
import time
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.core.enums import EntityType, FileType  # noqa: E402
from app.detection.direct_identifiers import normalize_value  # noqa: E402
from app.detection.pipeline import detect_all  # noqa: E402
from app.extraction.document_processor import process_document  # noqa: E402
from app.ingestion.validator import validate_upload  # noqa: E402

DATA_ROOT = ROOT / "competition" / "datasets"
OUTPUT_DIR = ROOT / "competition" / "phase1"
VISUAL_TYPE_ONLY = {EntityType.SIGNATURE_CANDIDATE.value, EntityType.FACE.value}


def _norm(entity_type: str, value: str) -> str:
    if entity_type in VISUAL_TYPE_ONLY:
        return "<visual-region>"
    try:
        return normalize_value(EntityType(entity_type), value)
    except Exception:
        text = unicodedata.normalize("NFKC", str(value)).casefold()
        return re.sub(r"\s+", " ", text).strip(" .,;:\t\r\n")


def _key(entity_type: str, value: str) -> tuple[str, str]:
    return entity_type, _norm(entity_type, value)


def _metrics(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    f2 = 5 * p * r / (4 * p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1, "f2": f2}


def _negative_metrics(false_positive_controls: int, total_controls: int) -> dict[str, float | int]:
    tn = max(0, total_controls - false_positive_controls)
    fpr = false_positive_controls / total_controls if total_controls else 0.0
    return {
        "negative_controls": total_controls,
        "false_positive_controls": false_positive_controls,
        "true_negative_controls": tn,
        "false_positive_rate": fpr,
        "definition": "Explicit-negative-control FPR: controls incorrectly emitted as the specified entity type / total labelled negative controls.",
    }


def _bbox_iou(a: tuple[float,float,float,float], b: tuple[float,float,float,float]) -> float:
    ax0, ay0, ax1, ay1 = a; bx0, by0, bx1, by1 = b
    ix0, iy0, ix1, iy1 = max(ax0,bx0), max(ay0,by0), min(ax1,bx1), min(ay1,by1)
    inter = max(0.0, ix1-ix0) * max(0.0, iy1-iy0)
    if inter <= 0: return 0.0
    aa=max(0.0,ax1-ax0)*max(0.0,ay1-ay0); bb=max(0.0,bx1-bx0)*max(0.0,by1-by0)
    return inter / (aa+bb-inter) if aa+bb-inter else 0.0


def _evidence_score(gold: dict[str, Any], detections: list[Any], document: Any) -> tuple[bool, str]:
    et = gold["entity_type"]; norm = _norm(et, gold["value"])
    candidates = [d for d in detections if d.entity_type.value == et and (_norm(et, d.plaintext) == norm or et in VISUAL_TYPE_ONLY)]
    if not candidates:
        return False, "missing"
    loc = gold.get("locator", {}); typ = loc.get("type")
    if typ == "char_span":
        gs, ge = int(loc["start"]), int(loc["end"])
        for d in candidates:
            ds, de = int(d.page_char_start), int(d.page_char_end)
            if ds < ge and de > gs:
                return True, "char-span"
        return False, "line-drift"
    if typ == "bbox":
        expected_page = int(loc.get("page", loc.get("frame", 0)))
        # PDF dataset manifests are 1-indexed; video/image frame/page locators are 0-indexed.
        if gold.get("format") in {"PDF"}:
            expected_page -= 1
        expected = (float(loc["x0"]), float(loc["y0"]), float(loc["x1"]), float(loc["y1"]))
        for d in candidates:
            if d.page_index == expected_page and _bbox_iou(tuple(d.rect), expected) >= 0.20:
                return True, "bbox"
        return False, "wrong-bbox-or-unit"
    if typ == "page_value":
        expected_page = max(0, int(loc.get("page", 1)) - 1)
        return (any(d.page_index == expected_page for d in candidates), "page")
    if typ == "docx_unit":
        unit = str(loc.get("unit", "")).casefold()
        # DOCX adapter assigns body/table, header, footer to stable evidence-unit pages.
        page_kinds = {0: "body", 1: "header", 2: "footer"}
        return (any(page_kinds.get(d.page_index) == unit or (unit == "table" and d.page_index == 0) for d in candidates), "docx-unit")
    if typ in {"cell", "xlsx_cell", "json_pointer"}:
        # Structured adapters use one virtual record per evidence page. Exact cell
        # geometry is scored by the dedicated geometry matrix; here require the
        # entity/value to resolve to a record-level evidence unit.
        return (any(d.page_index >= 0 for d in candidates), "record-unit")
    if typ in {"decoded_text_value", "source_value"}:
        return True, "decoded-text"
    return True, "semantic-only"


def evaluate_dataset(dataset_dir: Path) -> dict[str, Any]:
    manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    ground_truth = [json.loads(line) for line in (dataset_dir / "ground_truth.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    controls_path = dataset_dir / "negative_controls.jsonl"
    negative_controls = [json.loads(line) for line in controls_path.read_text(encoding="utf-8").splitlines() if line.strip()] if controls_path.exists() else []
    by_file: dict[str, list[dict[str,Any]]] = defaultdict(list)
    controls_by_file: dict[str, list[dict[str,Any]]] = defaultdict(list)
    for item in ground_truth: by_file[item["file"]].append(item)
    for item in negative_controls: controls_by_file[item["file"]].append(item)

    totals = [0,0,0]; per_entity: dict[str,list[int]] = defaultdict(lambda:[0,0,0]); per_format: dict[str,list[int]] = defaultdict(lambda:[0,0,0])
    negative_fp = 0; negative_total = len(negative_controls); negative_by_entity: dict[str,list[int]] = defaultdict(lambda:[0,0])
    file_reports=[]; evidence_total=evidence_ok=out_of_bounds=0; evidence_failures=defaultdict(int)
    started=time.perf_counter()

    for filename, gold_items in sorted(by_file.items()):
        path=dataset_dir/filename; data=path.read_bytes(); file_type, _media, _sha = validate_upload(data, filename)
        document=process_document(data, file_type, filename); detections=detect_all(document)

        # Detection quality is canonical entity/value quality. Repeated mentions are
        # evaluated separately as evidence geometry, preventing videos or repeated
        # headers from dominating precision/recall counts.
        gold_keys={_key(g["entity_type"],g["value"]) for g in gold_items}
        det_keys={_key(d.entity_type.value,d.plaintext) for d in detections}
        tp_keys=gold_keys & det_keys; fp_keys=det_keys-gold_keys; fn_keys=gold_keys-det_keys
        totals[0]+=len(tp_keys); totals[1]+=len(fp_keys); totals[2]+=len(fn_keys)
        for control in controls_by_file.get(filename, []):
            key = _key(control["entity_type"], control["value"])
            hit = key in det_keys
            negative_total_for_entity = negative_by_entity[control["entity_type"]]
            negative_total_for_entity[1] += 1
            if hit:
                negative_fp += 1
                negative_total_for_entity[0] += 1
        fmt=gold_items[0]["format"] if gold_items else file_type.value
        for k in tp_keys: per_entity[k[0]][0]+=1; per_format[fmt][0]+=1
        for k in fp_keys: per_entity[k[0]][1]+=1; per_format[fmt][1]+=1
        for k in fn_keys: per_entity[k[0]][2]+=1; per_format[fmt][2]+=1

        for gold in gold_items:
            evidence_total += 1
            ok, reason = _evidence_score(gold,detections,document)
            if ok: evidence_ok += 1
            else: evidence_failures[reason]+=1
        for d in detections:
            if d.page_index < 0 or d.page_index >= len(document.pages):
                out_of_bounds += 1; continue
            page=document.pages[d.page_index]
            x0,y0,x1,y1=d.rect
            if x0 < -1 or y0 < -1 or x1 > page.width+1 or y1 > page.height+1 or x1 <= x0 or y1 <= y0:
                out_of_bounds += 1

        file_reports.append({
            "file":filename,"format":fmt,"file_type":file_type.value,
            "gold_unique":len(gold_keys),"detected_unique":len(det_keys),
            **_metrics(len(tp_keys),len(fp_keys),len(fn_keys)),
            "false_positive_examples":[{"entity_type":a,"normalized_value":b} for a,b in sorted(fp_keys)[:10]],
            "false_negative_examples":[{"entity_type":a,"normalized_value":b} for a,b in sorted(fn_keys)[:10]],
        })

    return {
        "dataset_id":manifest["dataset_id"],"dataset_version":manifest["version"],"split_role":manifest["split_role"],
        "untouched_holdout":manifest["untouched_holdout"],"tuning_allowed":manifest["tuning_allowed"],
        "detection":{**_metrics(*totals), "false_discovery_rate": totals[1] / (totals[0] + totals[1]) if totals[0] + totals[1] else 0.0},
        "negative_control_fpr":{
            **_negative_metrics(negative_fp, negative_total),
            "per_entity": {k: _negative_metrics(v[0], v[1]) for k, v in sorted(negative_by_entity.items())},
        },
        "per_entity":{k:_metrics(*v) for k,v in sorted(per_entity.items())},
        "per_format":{k:_metrics(*v) for k,v in sorted(per_format.items())},
        "evidence":{
            "ground_truth_mentions":evidence_total,"correct_evidence_mentions":evidence_ok,
            "evidence_accuracy":evidence_ok/evidence_total if evidence_total else 0.0,
            "out_of_bounds_detections":out_of_bounds,"failures":dict(sorted(evidence_failures.items())),
            "note":"Evidence score checks exact character/page/frame/bbox when the manifest provides it; structured record and decoded-text locators use source-unit correctness. Dedicated geometry regression remains authoritative for renderer alignment.",
        },
        "files":file_reports,"elapsed_seconds":round(time.perf_counter()-started,3),
    }


def _markdown(report: dict[str,Any]) -> str:
    lines=["# VeilGraph Phase 1 Judge-Readiness Benchmark","","Detection quality uses unique entity/value pairs per file; repeated mentions are scored under Evidence Quality so long videos/repeated headers cannot dominate the metric.",""]
    for ds in report["datasets"]:
        d=ds["detection"]; e=ds["evidence"]
        lines += [f"## {ds['dataset_id']}","",f"- Precision: **{d['precision']:.4f}**",f"- Recall: **{d['recall']:.4f}**",f"- F1: **{d['f1']:.4f}**",f"- F2: **{d['f2']:.4f}**",f"- Explicit-negative-control FPR: **{ds['negative_control_fpr']['false_positive_rate']:.4f}** ({ds['negative_control_fpr']['false_positive_controls']}/{ds['negative_control_fpr']['negative_controls']})",f"- Evidence accuracy: **{e['evidence_accuracy']:.4f}**",f"- Out-of-bounds detections: **{e['out_of_bounds_detections']}**","","### Per format","","| Format | P | R | F1 | F2 |","|---|---:|---:|---:|---:|"]
        for fmt,m in ds["per_format"].items(): lines.append(f"| {fmt} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['f2']:.3f} |")
        lines += ["","### Per entity","","| Entity | P | R | F1 | F2 |","|---|---:|---:|---:|---:|"]
        for ent,m in ds["per_entity"].items(): lines.append(f"| {ent} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['f2']:.3f} |")
        lines.append("")
    lines += ["## Scientific boundary","","Showcase and Chaos are development/regression datasets. They are not external holdouts and must never be cited as untouched generalization evidence.",""]
    return "\n".join(lines)


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    datasets=[evaluate_dataset(DATA_ROOT/"judge_showcase_v1"),evaluate_dataset(DATA_ROOT/"judge_chaos_v1")]
    report={"schema":"veilgraph.phase1-judge-readiness.v1","generated_at_unix":int(time.time()),"datasets":datasets}
    (OUTPUT_DIR/"JUDGE_READINESS_RESULTS.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    (OUTPUT_DIR/"JUDGE_READINESS_REPORT.md").write_text(_markdown(report),encoding="utf-8")
    for ds in datasets:
        d=ds["detection"]; e=ds["evidence"]
        print(f"{ds['dataset_id']}: P={d['precision']:.4f} R={d['recall']:.4f} F1={d['f1']:.4f} F2={d['f2']:.4f} FPR={ds['negative_control_fpr']['false_positive_rate']:.4f} evidence={e['evidence_accuracy']:.4f}")
    print(f"Wrote {OUTPUT_DIR/'JUDGE_READINESS_RESULTS.json'}")
    return 0

if __name__ == '__main__': raise SystemExit(main())
