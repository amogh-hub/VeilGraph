from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from app.browser.models import (
    BrowserAction,
    BrowserActionPlan,
    BrowserReasoningEvidence,
    BrowserReasoningRequest,
    BrowserReasoningResponse,
    BrowserReleasePayload,
)
from app.browser.release_gate import release_payload_sha256, verify_network_authorization
from app.core.config import settings


router = APIRouter(prefix="/api/v1/browser", tags=["browser-reasoning"])

_HIGH_IMPACT_TERMS = {
    "submit", "confirm", "send", "pay", "purchase", "buy", "checkout", "delete",
    "remove", "transfer", "book", "reserve", "save", "sign", "agree", "authorize",
}
_TARGET_ROLES = {
    "CLICK": {"button", "link", "menuitem", "checkbox", "radio", "option"},
    "TYPE": {"textbox", "combobox"},
    "SELECT": {"combobox", "checkbox", "radio", "option", "menuitem"},
}
_DIRECT_PATTERNS = (
    re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I),
    re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])", re.I),
    re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)"),
    re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    re.compile(r"(?<!\d)(?:\+?\d[\s().-]*){10,15}(?!\d)"),
)

_replay_lock = threading.Lock()
_consumed_authorizations: dict[str, float] = {}


class BrowserReasoningError(ValueError):
    def __init__(self, detail: str, *, status_code: int = 422) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def reset_reasoning_replay_cache_for_tests() -> None:
    with _replay_lock:
        _consumed_authorizations.clear()


def _origin_tuple(value: str) -> tuple[str, str, int | None]:
    parsed = urlparse(value)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port


def _consume_authorization(request: BrowserReasoningRequest, now: datetime) -> None:
    auth = request.authorization.payload
    now_ts = now.timestamp()
    expires = auth.expires_at.timestamp()
    with _replay_lock:
        expired = [key for key, expiry in _consumed_authorizations.items() if expiry < now_ts]
        for key in expired:
            _consumed_authorizations.pop(key, None)
        if auth.authorization_id in _consumed_authorizations:
            raise BrowserReasoningError("network authorization has already been consumed", status_code=409)
        _consumed_authorizations[auth.authorization_id] = expires


def _validate_authorized_release(request: BrowserReasoningRequest, *, now: datetime) -> None:
    if not settings.reasoning_enabled:
        raise BrowserReasoningError("sanitized reasoning service is disabled", status_code=503)
    if not settings.reasoning_ollama_model.strip():
        raise BrowserReasoningError("reasoning model is not configured", status_code=503)
    trusted = (settings.reasoning_trusted_signer_sha256 or "").strip().casefold()
    if not trusted:
        raise BrowserReasoningError("reasoning server has no trusted VeilGraph signer configured", status_code=503)

    auth = request.authorization.payload
    if auth.signer.public_key_sha256.casefold() != trusted:
        raise BrowserReasoningError("VeilGraph signer fingerprint is not trusted by this reasoning server", status_code=403)
    if not verify_network_authorization(request.authorization, request.payload, now=now, require_allow=True):
        raise BrowserReasoningError("signed network authorization is invalid, expired, denied or bound to another payload", status_code=403)

    if (
        auth.proof_score != 100
        or auth.critical_failures != 0
        or auth.mandatory_gates < 12
        or auth.mandatory_passed != auth.mandatory_gates
        or request.payload.privacy_level < request.payload.network_privacy_floor
        or request.payload.residual_identity_exposure > 25
    ):
        raise BrowserReasoningError("authorized release does not satisfy server-side privacy invariants", status_code=403)

    _consume_authorization(request, now)


def _semantic_prompt_payload(payload: BrowserReleasePayload) -> dict:
    obj = payload.model_dump(mode="json", by_alias=True)
    page = dict(obj["page"])
    visual = page.get("visual_context")
    if isinstance(visual, dict):
        visual_meta = dict(visual)
        visual_meta.pop("image_base64", None)
        page["visual_context"] = visual_meta
    obj["page"] = page
    return obj


def _system_prompt() -> str:
    return (
        "You are the centralized reasoning component of VeilGraph, a privacy-governed browser agent. "
        "You receive ONLY locally sanitized and task-minimized browser context. Never infer, reconstruct, "
        "guess, or request hidden identity or redacted values. Produce only a typed BrowserActionPlan. "
        "Use target_id values exactly as provided. Never emit CSS selectors, XPath, JavaScript, eval code, "
        "shell commands, raw DOM, or arbitrary executable text. Use at most 8 actions. If the task cannot "
        "be safely planned from the supplied context, return the smallest safe READ/WAIT-style plan rather "
        "than inventing missing page state. High-impact actions such as submit, confirm, send, payment, "
        "purchase, deletion, transfer, booking, signing, or agreement must set requires_confirmation=true."
    )


def _call_ollama(payload: BrowserReleasePayload) -> str:
    endpoint = settings.reasoning_ollama_base_url.rstrip("/") + "/api/chat"
    schema = BrowserActionPlan.model_json_schema()
    semantic = _semantic_prompt_payload(payload)
    prompt = (
        "Plan the next browser actions for this sanitized payload.\n"
        "The JSON schema below is mandatory and the response must contain no prose outside the JSON object.\n"
        f"SCHEMA:\n{json.dumps(schema, sort_keys=True, separators=(',', ':'))}\n"
        f"SANITIZED_PAYLOAD:\n{json.dumps(semantic, sort_keys=True, separators=(',', ':'))}"
    )
    user_message: dict[str, object] = {"role": "user", "content": prompt}
    visual = payload.page.visual_context
    if visual is not None:
        user_message["images"] = [visual.image_base64]

    body = {
        "model": settings.reasoning_ollama_model,
        "messages": [
            {"role": "system", "content": _system_prompt()},
            user_message,
        ],
        "stream": False,
        "format": schema,
        "options": {"temperature": 0},
    }

    try:
        response = httpx.post(
            endpoint,
            json=body,
            timeout=settings.reasoning_timeout_seconds,
            follow_redirects=False,
            headers={"Cache-Control": "no-store"},
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        raise BrowserReasoningError(f"reasoning model request failed: {exc}", status_code=502) from exc

    content = data.get("message", {}).get("content") if isinstance(data, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise BrowserReasoningError("reasoning model returned no structured action plan", status_code=502)
    return content


def _contains_direct_identifier(value: str) -> bool:
    return any(pattern.search(value) for pattern in _DIRECT_PATTERNS)


def _high_impact(payload: BrowserReleasePayload, action: BrowserAction) -> bool:
    parts = [payload.task, action.reason, action.value or "", action.url or ""]
    if action.target_id:
        target = next((item for item in payload.page.elements if item.element_id == action.target_id), None)
        if target:
            parts.extend((target.label, target.text, target.role))
    words = set(re.findall(r"[a-z]+", " ".join(parts).casefold()))
    return bool(words & _HIGH_IMPACT_TERMS)


def validate_action_plan(plan: BrowserActionPlan, payload: BrowserReleasePayload) -> BrowserActionPlan:
    if plan.session_id != payload.session_id or plan.task_id != payload.task_id:
        raise BrowserReasoningError("action plan is not bound to the authorized session/task", status_code=502)
    if len(plan.actions) > settings.reasoning_max_actions:
        raise BrowserReasoningError("action plan exceeds configured maximum action count", status_code=502)

    elements = {item.element_id: item for item in payload.page.elements}
    normalized: list[BrowserAction] = []

    for action in plan.actions:
        target = elements.get(action.target_id) if action.target_id else None
        if action.target_id and target is None:
            raise BrowserReasoningError(f"model invented unavailable target_id {action.target_id}", status_code=502)
        if target is not None and target.disabled and action.action != "READ":
            raise BrowserReasoningError(f"model targeted disabled element {action.target_id}", status_code=502)

        allowed_roles = _TARGET_ROLES.get(action.action)
        if allowed_roles is not None and target is not None and target.role.casefold() not in allowed_roles:
            raise BrowserReasoningError(
                f"{action.action} is incompatible with target role {target.role}",
                status_code=502,
            )

        if action.value and _contains_direct_identifier(action.value):
            raise BrowserReasoningError("model-generated action value contains direct-identifier-like data", status_code=502)

        if action.action == "NAVIGATE" and action.url:
            parsed = urlparse(action.url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise BrowserReasoningError("NAVIGATE URL must be an absolute HTTP(S) URL", status_code=502)
            if _origin_tuple(action.url) != _origin_tuple(payload.page.origin):
                raise BrowserReasoningError("cross-origin NAVIGATE is not permitted by SANITIZED_REASONING_ACTION_V1", status_code=502)

        requires_confirmation = action.requires_confirmation or _high_impact(payload, action)
        normalized.append(action.model_copy(update={"requires_confirmation": requires_confirmation}))

    return plan.model_copy(update={"actions": normalized})


def reason_sanitized_release(
    request: BrowserReasoningRequest,
    *,
    now: datetime | None = None,
) -> BrowserReasoningResponse:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    _validate_authorized_release(request, now=current)

    started = time.monotonic()
    raw = _call_ollama(request.payload)
    try:
        plan = BrowserActionPlan.model_validate_json(raw)
    except ValidationError as exc:
        raise BrowserReasoningError(f"reasoning model violated typed action schema: {exc}", status_code=502) from exc

    validated = validate_action_plan(plan, request.payload)
    elapsed_ms = max(0, round((time.monotonic() - started) * 1000))

    return BrowserReasoningResponse(
        plan=validated,
        evidence=BrowserReasoningEvidence(
            model=settings.reasoning_ollama_model,
            elapsed_ms=elapsed_ms,
            payload_sha256=release_payload_sha256(request.payload),
            visual_context_used=request.payload.page.visual_context is not None,
            structured_output_validated=True,
            target_ids_validated=True,
            authorization_verified=True,
            signer_trusted=True,
            replay_protected=True,
        ),
    )


@router.post("/reason", response_model=BrowserReasoningResponse)
def reason_browser(request: BrowserReasoningRequest) -> BrowserReasoningResponse:
    """Reason only over an exact sanitized payload carrying a trusted signed ALLOW."""
    try:
        return reason_sanitized_release(request)
    except BrowserReasoningError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
