from __future__ import annotations

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from pydantic import ValidationError

from app.browser.evidence import LoopEvidenceError, record_secure_loop_evidence
from app.browser.local_analysis import (
    BrowserAnalysisError,
    analyse_browser_capture,
)
from app.browser.privacy_pipeline import (
    BrowserPreparationError,
    prepare_browser_release,
)
from app.browser.pairing import (
    consume_transport_ciphertext,
    create_pairing_attestation,
    create_transport_session,
)
from app.browser.models import (
    BrowserLocalAnalysisResponse,
    BrowserLocalCaptureMetadata,
    BrowserPairingAttestation,
    BrowserPairingRequest,
    BrowserReleasePreparationResponse,
    BrowserTransportSessionAttestation,
    BrowserTransportSessionRequest,
)
from app.core.config import settings


router = APIRouter(
    prefix="/api/v1/browser",
    tags=["browser-agent"],
)

_ALLOWED_SCREENSHOT_MEDIA = {
    "image/png",
    "image/jpeg",
}


async def _read_bounded(
    upload: UploadFile,
    limit: int,
) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Browser screenshot exceeds {limit} bytes"
            ),
        )
    return data


async def _read_request_bounded(
    request: Request,
    limit: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0

    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Encrypted browser transport body is too large"
                ),
            )
        chunks.append(chunk)

    return b"".join(chunks)


def _safe_validation_errors(
    exc: ValidationError,
) -> dict:
    """Return field/type diagnostics without echoing captured values."""
    return {
        "message": "Invalid browser capture metadata",
        "errors": [
            {
                "loc": ".".join(
                    str(part)
                    for part in error["loc"]
                ),
                "type": error["type"],
                "msg": error["msg"],
            }
            for error in exc.errors()[:12]
        ],
    }


def _validate_screenshot_magic(
    content_type: str,
    screenshot_bytes: bytes,
) -> None:
    if content_type == "image/png":
        if not screenshot_bytes.startswith(
            b"\x89PNG\r\n\x1a\n"
        ):
            raise HTTPException(
                status_code=422,
                detail="Encrypted PNG capture has invalid signature",
            )
        return

    if content_type == "image/jpeg":
        if not screenshot_bytes.startswith(b"\xff\xd8\xff"):
            raise HTTPException(
                status_code=422,
                detail="Encrypted JPEG capture has invalid signature",
            )
        return

    raise HTTPException(
        status_code=415,
        detail="Browser screenshot must be PNG or JPEG",
    )


def _parse_capture_metadata(
    metadata: str,
) -> BrowserLocalCaptureMetadata:
    if len(metadata.encode("utf-8")) > (
        settings.max_browser_metadata_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail="Browser capture metadata is too large",
        )

    try:
        return BrowserLocalCaptureMetadata.model_validate_json(
            metadata
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=_safe_validation_errors(exc),
        ) from exc


async def _decrypt_secure_capture(
    request: Request,
    *,
    endpoint: str,
) -> tuple[
    BrowserLocalCaptureMetadata,
    bytes,
]:
    session_id = (
        request.headers.get(
            "x-veilgraph-transport-session",
            "",
        )
        .strip()
    )
    iv_b64url = (
        request.headers.get(
            "x-veilgraph-transport-iv",
            "",
        )
        .strip()
    )

    if not session_id or not iv_b64url:
        raise HTTPException(
            status_code=401,
            detail=(
                "Encrypted browser transport headers are required"
            ),
        )

    ciphertext_limit = (
        settings.max_browser_metadata_bytes
        + settings.max_browser_screenshot_bytes
        + 64
    )

    ciphertext = await _read_request_bounded(
        request,
        ciphertext_limit,
    )

    try:
        plaintext = consume_transport_ciphertext(
            session_id=session_id,
            endpoint=endpoint,
            iv_b64url=iv_b64url,
            ciphertext=ciphertext,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    # Binary envelope:
    # [4-byte metadata length][1-byte mime][metadata][image]
    if len(plaintext) < 6:
        raise HTTPException(
            status_code=422,
            detail="Encrypted browser capture envelope is truncated",
        )

    metadata_length = int.from_bytes(
        plaintext[:4],
        "big",
    )
    mime_code = plaintext[4]

    if (
        metadata_length <= 0
        or metadata_length
        > settings.max_browser_metadata_bytes
    ):
        raise HTTPException(
            status_code=422,
            detail="Encrypted browser metadata length is invalid",
        )

    metadata_end = 5 + metadata_length
    if metadata_end >= len(plaintext):
        raise HTTPException(
            status_code=422,
            detail="Encrypted browser capture envelope is malformed",
        )

    metadata_bytes = plaintext[
        5:metadata_end
    ]
    screenshot_bytes = plaintext[
        metadata_end:
    ]

    if len(screenshot_bytes) > (
        settings.max_browser_screenshot_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail="Browser screenshot is too large",
        )

    try:
        metadata = metadata_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail="Encrypted browser metadata is not UTF-8",
        ) from exc

    content_type = {
        1: "image/png",
        2: "image/jpeg",
    }.get(mime_code)

    if content_type is None:
        raise HTTPException(
            status_code=415,
            detail="Encrypted browser screenshot media type is invalid",
        )

    _validate_screenshot_magic(
        content_type,
        screenshot_bytes,
    )

    return (
        _parse_capture_metadata(metadata),
        screenshot_bytes,
    )


@router.post(
    "/pair",
    response_model=BrowserPairingAttestation,
)
def pair_local_companion(
    request: BrowserPairingRequest,
) -> BrowserPairingAttestation:
    """Explicit TOFU pairing for the persistent companion identity."""
    return create_pairing_attestation(
        request.challenge
    )


@router.post(
    "/transport-session",
    response_model=BrowserTransportSessionAttestation,
)
def browser_transport_session(
    request: BrowserTransportSessionRequest,
) -> BrowserTransportSessionAttestation:
    """Authenticate an ephemeral encrypted channel before raw upload."""
    try:
        return create_transport_session(
            challenge=request.challenge,
            client_public_key_b64=(
                request.client_public_key_b64
            ),
            endpoint=request.endpoint,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@router.post(
    "/secure/analyse-capture",
    response_model=BrowserLocalAnalysisResponse,
)
async def secure_analyse_capture(
    request: Request,
) -> BrowserLocalAnalysisResponse:
    parsed, screenshot_bytes = (
        await _decrypt_secure_capture(
            request,
            endpoint="analyse-capture",
        )
    )

    try:
        return analyse_browser_capture(
            parsed,
            screenshot_bytes,
        )
    except BrowserAnalysisError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@router.post(
    "/secure/prepare-release",
    response_model=BrowserReleasePreparationResponse,
)
async def secure_prepare_release(
    request: Request,
) -> BrowserReleasePreparationResponse:
    parsed, screenshot_bytes = (
        await _decrypt_secure_capture(
            request,
            endpoint="prepare-release",
        )
    )

    try:
        return prepare_browser_release(
            parsed,
            screenshot_bytes,
        )
    except (
        BrowserAnalysisError,
        BrowserPreparationError,
    ) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc



@router.post("/evidence/loop")
def record_loop_evidence(payload: dict) -> dict:
    """Persist sanitized COMPLETE-loop evidence for local benchmark aggregation.

    This endpoint accepts only the loop trace/status object emitted by the
    extension UI. Raw captures, screenshot payloads and controlled private
    canaries are rejected by ``record_secure_loop_evidence``.
    """
    try:
        return record_secure_loop_evidence(payload)
    except LoopEvidenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------------------------------------------------------------
# Legacy localhost endpoints.
#
# Kept temporarily for deterministic compatibility tests and tooling.
# The production extension no longer uses these routes; its raw capture
# path uses /transport-session + /secure/* exclusively.
# ---------------------------------------------------------------------

@router.post(
    "/analyse-capture",
    response_model=BrowserLocalAnalysisResponse,
)
async def analyse_capture(
    metadata: str = Form(...),
    screenshot: UploadFile = File(...),
) -> BrowserLocalAnalysisResponse:
    if (
        screenshot.content_type or ""
    ).casefold() not in _ALLOWED_SCREENSHOT_MEDIA:
        raise HTTPException(
            status_code=415,
            detail="Browser screenshot must be PNG or JPEG",
        )

    parsed = _parse_capture_metadata(metadata)
    screenshot_bytes = await _read_bounded(
        screenshot,
        settings.max_browser_screenshot_bytes,
    )

    try:
        return analyse_browser_capture(
            parsed,
            screenshot_bytes,
        )
    except BrowserAnalysisError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@router.post(
    "/prepare-release",
    response_model=BrowserReleasePreparationResponse,
)
async def prepare_release(
    metadata: str = Form(...),
    screenshot: UploadFile = File(...),
) -> BrowserReleasePreparationResponse:
    if (
        screenshot.content_type or ""
    ).casefold() not in _ALLOWED_SCREENSHOT_MEDIA:
        raise HTTPException(
            status_code=415,
            detail="Browser screenshot must be PNG or JPEG",
        )

    parsed = _parse_capture_metadata(metadata)
    screenshot_bytes = await _read_bounded(
        screenshot,
        settings.max_browser_screenshot_bytes,
    )

    try:
        return prepare_browser_release(
            parsed,
            screenshot_bytes,
        )
    except (
        BrowserAnalysisError,
        BrowserPreparationError,
    ) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
