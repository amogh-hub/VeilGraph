from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import increment_non_local_inbound, router
from app.core.config import settings
from app.core.database import db
from app.ops.admission import AdmissionController, AdmissionRejected, is_heavy_request
from app.ops.metrics import runtime_metrics
from app.ops.routes import bind_admission_snapshot, router as ops_router
from app.security.deployment import authorize_request, validate_online_configuration
from app.security.network_guard import install_egress_guard
from app.security.retention import (
    destroy_unrecoverable_jobs_after_restart,
    retention_worker,
    stop_retention_worker,
)


def _configured_token() -> str | None:
    value = settings.online_api_token
    return value.get_secret_value() if value is not None else None


_admission = AdmissionController(
    settings.max_concurrent_heavy_requests,
    settings.heavy_request_queue_timeout_seconds,
)
bind_admission_snapshot(_admission.snapshot)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings.workspace_root.chmod(0o700)
    validate_online_configuration(
        offline_mode=settings.offline_mode,
        api_token=_configured_token(),
        require_https=settings.online_require_https,
        trust_proxy_headers=settings.trust_proxy_headers,
        trusted_proxy_networks=settings.trusted_proxy_networks,
    )
    db.init_schema()
    if settings.offline_mode:
        install_egress_guard()

    # Job keys live only in RAM. Any active DB job surviving a prior process has
    # therefore lost its decryption key and is erased immediately rather than
    # leaving undecryptable sensitive ciphertext around until the TTL elapses.
    destroy_unrecoverable_jobs_after_restart()

    retention_task: asyncio.Task[None] | None = None
    if settings.retention_worker_enabled:
        retention_task = asyncio.create_task(retention_worker(), name="veilgraph-retention-worker")
    try:
        yield
    finally:
        await stop_retention_worker(retention_task)


app = FastAPI(
    title="VeilGraph",
    version=settings.version,
    description=(
        "Local-first privacy compiler with Identity Exposure Graph, L1–L5 transformations, "
        "fail-closed adversarial verification, cryptographic retention expiry, signed proof "
        "packages and Phase-2 production/security/scale controls."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Accept", "Authorization", "X-Request-ID"],
)


@app.middleware("http")
async def production_boundary_metrics_and_headers(request: Request, call_next):
    client_host = request.client.host if request.client else "unknown"
    decision = authorize_request(
        offline_mode=settings.offline_mode,
        client_host=client_host,
        headers=request.headers,
        url_scheme=request.url.scheme,
        configured_token=_configured_token(),
        require_https=settings.online_require_https,
        trust_proxy_headers=settings.trust_proxy_headers,
        trusted_proxy_networks=settings.trusted_proxy_networks,
    )
    if not decision.allowed:
        if settings.offline_mode:
            increment_non_local_inbound()
        return JSONResponse(status_code=decision.status_code, content={"detail": decision.detail})

    token = runtime_metrics.begin(request.url.path)
    request_id = request.headers.get("x-request-id") or secrets.token_hex(12)
    status_code = 500
    try:
        if is_heavy_request(request.method, request.url.path):
            try:
                async with _admission.slot():
                    response = await call_next(request)
            except AdmissionRejected:
                runtime_metrics.admission_rejected()
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "Server is at its configured heavy-operation concurrency limit"},
                    headers={"Retry-After": "1"},
                )
        else:
            response = await call_next(request)
        status_code = response.status_code
    except Exception:
        status_code = 500
        raise
    finally:
        elapsed_ms = runtime_metrics.end(token, status_code)

    response.headers["X-Request-ID"] = request_id
    response.headers["Server-Timing"] = f"app;dur={elapsed_ms:.2f}"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self' http://127.0.0.1:8000 http://localhost:8000; "
        "img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    if not settings.offline_mode:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(router)
app.include_router(ops_router)
