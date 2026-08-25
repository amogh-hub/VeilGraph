#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STOP = False


def handle_stop(*_args) -> None:
    global STOP
    STOP = True


def sample(filter_text: str) -> dict:
    proc = subprocess.run(
        ["ps", "-axo", "rss=,pcpu=,command="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    rss_kb = 0
    cpu = 0.0
    processes = 0
    needle = filter_text.casefold()
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            rss = int(parts[0])
            pct = float(parts[1])
        except ValueError:
            continue
        command = parts[2]
        if needle not in command.casefold():
            continue
        if "crashpad_handler" in command.casefold():
            continue
        rss_kb += rss
        cpu += pct
        processes += 1
    return {
        "rss_mb": rss_kb / 1024,
        "cpu_percent_sum": cpu,
        "process_count": processes,
    }


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=["chrome", "firefox"], required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--baseline-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    filter_text = "Google Chrome" if args.browser == "chrome" else "Firefox"
    output = args.output or (
        ROOT / "artifacts" / "sih26171" / f"resources-{args.browser}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    started = time.monotonic()
    records: list[dict] = []

    print(f"RESOURCE_SAMPLER_{args.browser.upper()}: READY", flush=True)

    try:
        while not STOP:
            item = sample(filter_text)
            item["elapsed_seconds"] = round(time.monotonic() - started, 3)
            records.append(item)
            time.sleep(max(0.1, args.interval))
    finally:
        baseline = [
            item["rss_mb"]
            for item in records
            if item["elapsed_seconds"] <= args.baseline_seconds and item["rss_mb"] > 0
        ]
        all_rss = [item["rss_mb"] for item in records if item["rss_mb"] > 0]
        all_cpu = [item["cpu_percent_sum"] for item in records]
        baseline_rss = statistics.median(baseline) if baseline else None
        peak_rss = max(all_rss) if all_rss else None

        result = {
            "schema": "veilgraph.sih26171-browser-resource-sample.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "browser": args.browser,
            "measurement": "aggregate browser-process tree sampled via macOS ps",
            "sample_count": len(records),
            "interval_seconds": args.interval,
            "baseline_window_seconds": args.baseline_seconds,
            "baseline_rss_mb": round(baseline_rss, 3) if baseline_rss is not None else None,
            "peak_rss_mb": round(peak_rss, 3) if peak_rss is not None else None,
            "peak_delta_rss_mb": (
                round(max(0.0, peak_rss - baseline_rss), 3)
                if peak_rss is not None and baseline_rss is not None
                else None
            ),
            "median_cpu_percent_sum": (
                round(statistics.median(all_cpu), 3) if all_cpu else None
            ),
            "p95_cpu_percent_sum": (
                round(percentile(all_cpu, 0.95), 3) if all_cpu else None
            ),
            "peak_cpu_percent_sum": round(max(all_cpu), 3) if all_cpu else None,
            "max_process_count": max((item["process_count"] for item in records), default=0),
            "claim_boundary": (
                "Aggregate browser-process measurement on this machine. "
                "It is not represented as extension-only RSS."
            ),
        }
        temp = output.with_suffix(".tmp")
        temp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(output)
        print(f"RESOURCE_EVIDENCE={output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
