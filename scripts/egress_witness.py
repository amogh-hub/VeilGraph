#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "artifacts" / "sih26171" / "egress-witness-latest.json"
MAX_REQUEST_BYTES = 16 * 1024 * 1024

RAW_CANARIES = {
    "patient_name": "Aarav Mehta",
    "patient_identifier": "PC-BLR-482917",
    "patient_email": "aarav.mehta.demo@example.test",
    "patient_phone": "+91 90000 48291",
    "patient_dob": "14 Feb 1992",
    "patient_location": "Indiranagar, Bengaluru",
    "patient_employer": "Synthetic Orbit Labs",
    "relationship_canary": "VG-CANARY-RELATION-7F91A2",
}

FORBIDDEN_RAW_KEYS = {
    "raw_value",
    "rawValue",
    "screenshotDataUrl",
    "screenshot_data_url",
    "visual_findings",
    "visualFindings",
    "frames",
    "metadata",
}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(walk_keys(child))
    return keys

def inspect_external_request(body: bytes) -> dict[str, Any]:
    decoded = body.decode("utf-8", errors="replace")
    canary_hits = [label for label, raw in RAW_CANARIES.items() if raw in decoded]
    parsed: Any = None
    parse_error = None
    try:
        parsed = json.loads(decoded)
    except Exception as exc:
        parse_error = type(exc).__name__

    keys = walk_keys(parsed) if parsed is not None else set()
    forbidden_key_hits = sorted(keys & FORBIDDEN_RAW_KEYS)

    request_schema = None
    payload_schema = None
    decision = None
    authorization_id = None
    payload_sha256 = None
    sanitized_visual_sha256 = None
    visual_context_present = False

    if isinstance(parsed, dict):
        request_schema = parsed.get("schema")
        payload = parsed.get("payload")
        authorization = parsed.get("authorization")

        if isinstance(payload, dict):
            payload_schema = payload.get("schema")
            page = payload.get("page")
            if isinstance(page, dict):
                visual = page.get("visual_context")
                if isinstance(visual, dict):
                    visual_context_present = True
                    sanitized_visual_sha256 = visual.get("sanitized_sha256")

        if isinstance(authorization, dict):
            auth_payload = authorization.get("payload")
            if isinstance(auth_payload, dict):
                decision = auth_payload.get("decision")
                authorization_id = auth_payload.get("authorization_id")
                payload_sha256 = auth_payload.get("payload_sha256")

    clean = (
        parse_error is None
        and request_schema == "veilgraph.browser-reasoning-request.v1"
        and payload_schema == "veilgraph.browser-release-payload.v1"
        and decision == "ALLOW_NETWORK_RELEASE"
        and not canary_hits
        and not forbidden_key_hits
    )

    return {
        "observed_at": utc_now(),
        "request_bytes": len(body),
        "request_sha256": hashlib.sha256(body).hexdigest(),
        "json_parse_error": parse_error,
        "request_schema": request_schema,
        "payload_schema": payload_schema,
        "authorization_decision": decision,
        "authorization_id": authorization_id,
        "payload_sha256": payload_sha256,
        "visual_context_present": visual_context_present,
        "sanitized_visual_sha256": sanitized_visual_sha256,
        "raw_canary_count": len(canary_hits),
        "raw_canary_hit_labels": canary_hits,
        "forbidden_raw_key_count": len(forbidden_key_hits),
        "forbidden_raw_keys": forbidden_key_hits,
        "clean_external_request": clean,
    }

class State:
    def __init__(self, upstream: str, evidence: Path) -> None:
        self.upstream = upstream
        self.evidence = evidence
        self.lock = threading.Lock()
        self.records: list[dict[str, Any]] = []
        evidence.parent.mkdir(parents=True, exist_ok=True)

        if evidence.exists():
            try:
                prior = json.loads(evidence.read_text(encoding="utf-8"))
                records = prior.get("requests", [])
                if isinstance(records, list):
                    self.records = [item for item in records if isinstance(item, dict)]
            except Exception:
                self.records = []

    def record(self, item: dict[str, Any]) -> None:
        with self.lock:
            self.records.append(item)
            document = {
                "schema": "veilgraph.sih26171-egress-witness.v1",
                "generated_at": utc_now(),
                "witness": "independent HTTP boundary proxy",
                "upstream": self.upstream,
                "request_count": len(self.records),
                "all_requests_clean": bool(self.records)
                and all(record["clean_external_request"] for record in self.records),
                "total_raw_canary_hits": sum(record["raw_canary_count"] for record in self.records),
                "total_forbidden_raw_key_hits": sum(
                    record["forbidden_raw_key_count"] for record in self.records
                ),
                "canary_labels_checked": sorted(RAW_CANARIES),
                "raw_request_bodies_persisted": False,
                "requests": list(self.records),
            }
            temp = self.evidence.with_suffix(".tmp")
            temp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temp.replace(self.evidence)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            if self.evidence.exists():
                return json.loads(self.evidence.read_text(encoding="utf-8"))
            return {
                "schema": "veilgraph.sih26171-egress-witness.v1",
                "request_count": 0,
                "all_requests_clean": False,
                "requests": [],
            }

STATE: State | None = None

class Handler(BaseHTTPRequestHandler):
    server_version = "VeilGraphEgressWitness/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))

    def extension_origin(self) -> str | None:
        origin = self.headers.get("Origin", "").strip()
        if origin.startswith("moz-extension://") or origin.startswith("chrome-extension://"):
            return origin
        return None

    def send_cors(self) -> None:
        origin = self.extension_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, Cache-Control, Accept, Authorization, X-Request-ID",
            )
            self.send_header("Access-Control-Max-Age", "600")

    def send_json(self, status: int, payload: Any) -> None:
        encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_cors()
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self) -> None:
        if self.path not in {"/api/v1/browser/reason", "/evidence"}:
            self.send_json(404, {"detail": "unsupported witness path"})
            return
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.send_cors()
        self.end_headers()

    def do_GET(self) -> None:
        assert STATE is not None
        if self.path == "/evidence":
            self.send_json(200, STATE.snapshot())
        else:
            self.send_json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        assert STATE is not None
        if self.path != "/api/v1/browser/reason":
            self.send_json(404, {"detail": "unsupported witness path"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"detail": "invalid content length"})
            return

        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"detail": "reasoning request exceeds witness limit"})
            return

        body = self.rfile.read(length)
        finding = inspect_external_request(body)

        request = urllib.request.Request(
            STATE.upstream,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
            },
        )

        upstream_status = 502
        response_body = b'{"detail":"upstream unavailable"}'
        try:
            with urllib.request.urlopen(request, timeout=190) as response:
                upstream_status = response.status
                response_body = response.read(MAX_REQUEST_BYTES)
        except urllib.error.HTTPError as exc:
            upstream_status = exc.code
            response_body = exc.read(MAX_REQUEST_BYTES)
        except Exception as exc:
            finding["upstream_error"] = type(exc).__name__

        finding["upstream_status"] = upstream_status
        STATE.record(finding)

        self.send_response(upstream_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_cors()
        self.end_headers()
        self.wfile.write(response_body)

def main() -> int:
    global STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument(
        "--upstream",
        default="http://127.0.0.1:8001/api/v1/browser/reason",
    )
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    args = parser.parse_args()

    STATE = State(args.upstream, args.evidence)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("VEILGRAPH_EGRESS_WITNESS_V1_1: READY", flush=True)
    print(f"LISTEN=http://{args.host}:{args.port}/api/v1/browser/reason", flush=True)
    print(f"UPSTREAM={args.upstream}", flush=True)
    print(f"PRESERVED_RECORDS={len(STATE.records)}", flush=True)
    print("RAW_REQUEST_BODY_PERSISTENCE=DISABLED", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
