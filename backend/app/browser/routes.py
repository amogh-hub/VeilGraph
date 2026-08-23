from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import ValidationError

from app.browser.local_analysis import BrowserAnalysisError, analyse_browser_capture
from app.browser.models import BrowserLocalAnalysisResponse, BrowserLocalCaptureMetadata
from app.core.config import settings

router = APIRouter(prefix="/api/v1/browser", tags=["browser-agent"])

_ALLOWED_SCREENSHOT_MEDIA = {"image/png", "image/jpeg"}


async def _read_bounded(upload: UploadFile, limit: int) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"Browser screenshot exceeds {limit} bytes")
    return data


@router.post("/analyse-capture", response_model=BrowserLocalAnalysisResponse)
async def analyse_capture(
    metadata: str = Form(...),
    screenshot: UploadFile = File(...),
) -> BrowserLocalAnalysisResponse:
    """Analyse raw browser context locally without authorizing external release.

    Raw metadata/screenshot bytes are processed in-memory and are not persisted by
    this endpoint. The returned result is local analysis evidence only.
    """

    if len(metadata.encode("utf-8")) > settings.max_browser_metadata_bytes:
        raise HTTPException(status_code=413, detail="Browser capture metadata is too large")
    if (screenshot.content_type or "").casefold() not in _ALLOWED_SCREENSHOT_MEDIA:
        raise HTTPException(status_code=415, detail="Browser screenshot must be PNG or JPEG")
    try:
        parsed = BrowserLocalCaptureMetadata.model_validate_json(metadata)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Invalid browser capture metadata") from exc

    screenshot_bytes = await _read_bounded(screenshot, settings.max_browser_screenshot_bytes)
    try:
        return analyse_browser_capture(parsed, screenshot_bytes)
    except BrowserAnalysisError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
