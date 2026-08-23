#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
OUT = ROOT / "competition" / "phase3" / "SECURE_ONLINE_ACCEPTANCE.json"
PYTHON = Path(sys.executable)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def make_cert(tmp: Path) -> tuple[Path, Path]:
    sys.path.insert(0, str(BACKEND))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp / "tls.key", tmp / "tls.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_path, 0o600)
    return key_path, cert_path


def request(url: str, token: str | None = None) -> tuple[int, dict]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    context = ssl._create_unverified_context()  # local ephemeral self-signed acceptance certificate only
    try:
        with urllib.request.urlopen(req, context=context, timeout=4) as res:
            return int(res.status), json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        return int(exc.code), json.loads(raw) if raw else {}


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    token = "VG-PHASE3-ONLINE-ACCEPTANCE-" + "7" * 40
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="veilgraph-online-") as td:
        tmp = Path(td)
        key_path, cert_path = make_cert(tmp)
        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(BACKEND),
            "VEILGRAPH_OFFLINE_MODE": "false",
            "VEILGRAPH_BIND_HOST": "127.0.0.1",
            "VEILGRAPH_BIND_PORT": str(port),
            "VEILGRAPH_ONLINE_API_TOKEN": token,
            "VEILGRAPH_ONLINE_REQUIRE_HTTPS": "true",
            "VEILGRAPH_TRUST_PROXY_HEADERS": "false",
            "VEILGRAPH_DATABASE_PATH": str(tmp / "acceptance.db"),
            "VEILGRAPH_WORKSPACE_ROOT": str(tmp / "jobs"),
            "VEILGRAPH_SIGNING_KEY_PATH": str(tmp / "signing.key"),
            "VEILGRAPH_RETENTION_WORKER_ENABLED": "false",
        })
        cmd = [str(PYTHON), "-m", "uvicorn", "main:app", "--app-dir", str(BACKEND), "--host", "127.0.0.1", "--port", str(port), "--ssl-keyfile", str(key_path), "--ssl-certfile", str(cert_path), "--log-level", "warning"]
        proc = subprocess.Popen(cmd, env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            base = f"https://127.0.0.1:{port}/api/v1/status"
            deadline = time.time() + 12
            ready = False
            while time.time() < deadline:
                try:
                    status, _ = request(base)
                    if status in {200, 401}:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.2)
            if not ready:
                raise RuntimeError("TLS server did not become ready")
            unauthorized_status, unauthorized_body = request(base)
            authorized_status, authorized_body = request(base, token)
            checks = {
                "tls_socket_established": True,
                "unauthorized_rejected": unauthorized_status == 401,
                "authorized_bearer_accepted": authorized_status == 200,
                "online_mode_reported": authorized_body.get("offline_mode") is False,
                "external_model_calls_zero": authorized_body.get("external_model_calls") in {0, "DISABLED"},
            }
            report = {
                "schema": "veilgraph.secure-online-acceptance.v1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "transport": "real local TLS socket using an ephemeral self-signed acceptance certificate",
                "server": "uvicorn",
                "bind_host": "127.0.0.1",
                "authentication": "Bearer token",
                "checks": checks,
                "unauthorized_status": unauthorized_status,
                "authorized_status": authorized_status,
                "status_payload": authorized_body,
                "all_passed": all(checks.values()),
                "boundary": "This proves VeilGraph secure-online application behavior over TLS. Public production deployment still requires an organisation-managed DNS/TLS/reverse-proxy environment.",
            }
            OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            print(f"Wrote {OUT}")
            return 0 if report["all_passed"] else 1
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
