from __future__ import annotations

from fastapi import FastAPI

from app.browser.reasoning import router as reasoning_router
from app.core.config import settings


app = FastAPI(
    title="VeilGraph Sanitized Reasoning Server",
    version=settings.version,
    description=(
        "Dedicated reasoning surface for SIH26171. It accepts only a task-minimized "
        "BrowserReleasePayload carrying a trusted signed ALLOW_NETWORK_RELEASE authorization "
        "and returns a schema-validated typed BrowserActionPlan."
    ),
)

app.include_router(reasoning_router)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "product": "VeilGraph",
        "service": "sanitized-reasoning",
        "contract": "SANITIZED_REASONING_ACTION_V1",
        "enabled": settings.reasoning_enabled,
        "model_configured": bool(settings.reasoning_ollama_model.strip()),
        "trusted_signer_configured": bool((settings.reasoning_trusted_signer_sha256 or "").strip()),
    }
