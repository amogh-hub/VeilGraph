from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import ValidationError

from app.browser.local_analysis import BrowserAnalysisError, analyse_browser_capture
from app.browser.privacy_pipeline import BrowserPreparationError, prepare_browser_release
from app.browser.pairing import create_pairing_attestation
from app.browser.models import (
    BrowserLocalAnalysisResponse,
    BrowserLocalCaptureMetadata,
    BrowserPairingAttestation,
    BrowserPairingRequest,
    BrowserReleasePreparationResponse,
)
from app.core.config import settings

router = APIRouter(prefix="/api/v1/browser", tags=["browser-agent"])

_ALLOWED_SCREENSHOT_MEDIA = {"image/png", "image/jpeg"}


async def _read_bounded(upload: UploadFile, limit: int) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"Browser screenshot exceeds {limit} bytes")
    return data



@router.post("/pair", response_model=BrowserPairingAttestation)
def pair_local_companion(request: BrowserPairingRequest) -> BrowserPairingAttestation:
    """Return a short-lived challenge attestation for explicit extension pairing.

    This endpoint does not authorize network release. It only proves that the
    localhost companion possesses its persistent device signing key so the
    extension can pin that identity and detect later key substitution.
    """

    return create_pairing_attestation(request.challenge)

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

@router.post("/prepare-release", response_model=BrowserReleasePreparationResponse)
async def prepare_release(
    metadata: str = Form(...),
    screenshot: UploadFile = File(...),
) -> BrowserReleasePreparationResponse:
    """Build, attack and sign the exact candidate external browser payload.

    Caller-supplied verification results are never accepted. Raw DOM/screenshot
    material is processed only on the localhost companion. The returned
    authorization is bound to the sanitized payload byte-for-byte.
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
        return prepare_browser_release(parsed, screenshot_bytes)
    except (BrowserAnalysisError, BrowserPreparationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
