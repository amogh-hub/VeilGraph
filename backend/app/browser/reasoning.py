from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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


class _CompactReasoningDecision(BaseModel):
    """Minimal model-controlled decision.

    The model chooses only an action and, when required, an authorized element
    index. VeilGraph deterministically restores the exact target ID, confidence,
    session/task binding, confirmation policy and final BrowserActionPlan.
    """

    model_config = ConfigDict(extra="forbid")

    # DONE means the task is already complete.
    a: Literal["DONE", "CLICK", "SCROLL", "TYPE", "SELECT", "NAVIGATE", "READ", "WAIT"]

    # Index into the already-authorized, task-minimized element list.
    i: int | None = Field(default=None, ge=0, le=31)

    v: str | None = Field(default=None, max_length=1024)
    u: str | None = Field(default=None, max_length=2048)
    d: int | None = Field(default=None, ge=-10_000, le=10_000)
    w: int | None = Field(default=None, ge=0, le=5_000)

    @model_validator(mode="after")
    def validate_decision_shape(self):
        targeted = {"CLICK", "TYPE", "SELECT", "READ"}

        if self.a == "DONE":
            if any(value is not None for value in (self.i, self.v, self.u, self.d, self.w)):
                raise ValueError("DONE must not contain action parameters")
            return self

        if self.a in targeted:
            if self.i is None:
                raise ValueError(f"{self.a} requires element index i")
        elif self.i is not None:
            raise ValueError(f"{self.a} must not contain element index i")

        return self


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


_SEMANTIC_FAST_ACTION_TERMS = {
    "open", "click", "tap", "press", "go", "navigate", "visit",
}

_SEMANTIC_FAST_STOPWORDS = {
    "a", "an", "the", "to", "my", "me", "please", "page", "website", "site",
    "open", "click", "tap", "press", "go", "navigate", "visit",
}

_VISUAL_DEPENDENT_TERMS = {
    "image", "picture", "photo", "icon", "logo", "visual",
    "color", "colour",
    "left", "right", "top", "bottom",
    "above", "below", "beside", "near",
    "looks", "look", "appears", "visible",
}


def _semantic_fast_path_eligible(payload: BrowserReleasePayload) -> bool:
    """Conservatively decide whether remote visual reasoning adds task utility.

    Full-resolution visual privacy analysis has already happened locally before
    this function is reached. This decision only controls whether the already
    sanitized raster is additionally supplied to the reasoning model.
    """

    elements = payload.page.elements

    # V1 intentionally handles only the safest/simple case:
    # one exact low-impact clickable semantic target.
    if len(elements) != 1:
        return False

    target = elements[0]
    if target.disabled:
        return False

    if target.role.casefold() not in {"button", "link", "menuitem"}:
        return False

    if payload.task_utility_score < 90:
        return False

    if payload.minimization_basis_points < 9000:
        return False

    task_words = set(re.findall(r"[a-z0-9]+", payload.task.casefold()))

    if not (task_words & _SEMANTIC_FAST_ACTION_TERMS):
        return False

    # Never remove visual reasoning for explicitly visual/spatial instructions.
    if task_words & _VISUAL_DEPENDENT_TERMS:
        return False

    # Keep high-impact flows on the multimodal path.
    if task_words & _HIGH_IMPACT_TERMS:
        return False

    meaning_words = task_words - _SEMANTIC_FAST_STOPWORDS
    if not meaning_words:
        return False

    target_words = set(
        re.findall(
            r"[a-z0-9]+",
            f"{target.label} {target.text} {target.role}".casefold(),
        )
    )

    # Every meaningful task token must be represented by the one released
    # semantic target. Partial/ambiguous matches stay multimodal.
    if not meaning_words.issubset(target_words):
        return False

    return True


def _reasoning_uses_visual(payload: BrowserReleasePayload) -> bool:
    return (
        payload.page.visual_context is not None
        and not _semantic_fast_path_eligible(payload)
    )


def _system_prompt() -> str:
    return (
        "You are the centralized reasoning component of VeilGraph, a privacy-governed browser agent. "
        "You receive ONLY locally sanitized and task-minimized browser context. Never infer, reconstruct, "
        "guess, or request hidden identity or redacted values. Produce only a typed BrowserActionPlan. "
        "Use target_id values exactly as provided. Never emit CSS selectors, XPath, JavaScript, eval code, "
        "shell commands, raw DOM, or arbitrary executable text. Plan only the NEXT ONE action because VeilGraph "
        "re-observes the page after every action. Return exactly one action unless the task is already complete. "
        "Omit unused optional action fields. Keep action reason to at most 6 words and summary empty. "
        "confidence_basis_points uses the 0..10000 basis-point scale, not 0..100. If the task cannot "
        "be safely planned from the supplied context, return the smallest safe READ/WAIT-style plan rather "
        "than inventing missing page state. High-impact actions such as submit, confirm, send, payment, "
        "purchase, deletion, transfer, booking, signing, or agreement must set requires_confirmation=true."
    )


def _call_ollama(payload: BrowserReleasePayload) -> str:
    endpoint = settings.reasoning_ollama_base_url.rstrip("/") + "/api/chat"
    schema = _CompactReasoningDecision.model_json_schema()
    use_visual = _reasoning_uses_visual(payload)
    semantic = _semantic_prompt_payload(payload)

    # The signed BrowserReleasePayload remains unchanged. We only remove
    # visual metadata from the model prompt when the deterministic semantic
    # fast-path proves that the sanitized raster adds no task utility.
    if not use_visual:
        semantic_page = semantic.get("page")
        if isinstance(semantic_page, dict):
            semantic_page.pop("visual_context", None)
    # Model targets elements by array index rather than repeating or inventing
    # opaque vg_* identifiers.
    prompt = (
        "Choose only the NEXT browser action. Return compact JSON only. "
        "a is DONE, CLICK, SCROLL, TYPE, SELECT, NAVIGATE, READ, or WAIT. "
        "For CLICK/TYPE/SELECT/READ set i to the zero-based index in page.elements. "
        "Use v=value, u=url, d=scroll_delta_y, w=wait_ms only when required. "
        "Omit every unused key. Never infer hidden values.\n"
        f"SANITIZED_PAYLOAD:\n{json.dumps(semantic, sort_keys=True, separators=(',', ':'))}"
    )
    user_message: dict[str, object] = {"role": "user", "content": prompt}
    visual = payload.page.visual_context
    if visual is not None and use_visual:
        user_message["images"] = [visual.image_base64]

    body = {
        "model": settings.reasoning_ollama_model,
        "messages": [
            {"role": "system", "content": _system_prompt()},
            user_message,
        ],
        "stream": False,
        "format": schema,
        "options": {
            "temperature": 0,
            "num_ctx": settings.reasoning_context_tokens,
        },
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

        # Temporary local latency diagnostics. Contains only numeric/model
        # performance metadata and payload sizes; never logs sanitized values,
        # prompts, images, DOM text, task text, or identifiers.
        visual = payload.page.visual_context
        timing = {
            "ollama_total_ms": round(data.get("total_duration", 0) / 1e6, 1),
            "ollama_load_ms": round(data.get("load_duration", 0) / 1e6, 1),
            "prompt_tokens": data.get("prompt_eval_count"),
            "prompt_eval_ms": round(data.get("prompt_eval_duration", 0) / 1e6, 1),
            "output_tokens": data.get("eval_count"),
            "generation_ms": round(data.get("eval_duration", 0) / 1e6, 1),
            "reasoning_route": "VLM" if use_visual else "SEMANTIC_FAST_PATH",
            "semantic_json_bytes": len(
                json.dumps(
                    semantic,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            "released_elements": len(payload.page.elements),
            "visual_context": use_visual,
            "visual_width": visual.width if use_visual and visual is not None else None,
            "visual_height": visual.height if use_visual and visual is not None else None,
            "visual_encoded_bytes": (
                len(visual.image_base64.encode("ascii"))
                if use_visual and visual is not None
                else 0
            ),
        }
        print("VEILGRAPH_OLLAMA_TIMING " + json.dumps(timing, sort_keys=True), flush=True)

    except Exception as exc:
        raise BrowserReasoningError(f"reasoning model request failed: {exc}", status_code=502) from exc

    content = data.get("message", {}).get("content") if isinstance(data, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise BrowserReasoningError("reasoning model returned no structured action decision", status_code=502)

    try:
        decision = _CompactReasoningDecision.model_validate_json(content)

        if decision.a == "DONE":
            plan = BrowserActionPlan(
                session_id=payload.session_id,
                task_id=payload.task_id,
                actions=[],
                complete=True,
                summary="",
            )
        else:
            target_id = None
            if decision.i is not None:
                if decision.i >= len(payload.page.elements):
                    raise BrowserReasoningError(
                        "reasoning model selected unavailable element index",
                        status_code=502,
                    )
                target_id = payload.page.elements[decision.i].element_id

            # Confidence is deterministic evidence, not a model assertion.
            # Use the conservative minimum of task utility and minimization.
            confidence_basis_points = min(
                payload.task_utility_score * 100,
                payload.minimization_basis_points,
            )

            action = BrowserAction(
                action=decision.a,
                target_id=target_id,
                value=decision.v,
                url=decision.u,
                scroll_delta_y=decision.d,
                wait_ms=decision.w,
                confidence_basis_points=confidence_basis_points,
                reason="Model selected next action",
                requires_confirmation=False,
            )

            plan = BrowserActionPlan(
                session_id=payload.session_id,
                task_id=payload.task_id,
                actions=[action],
                complete=False,
                summary="",
            )

    except ValidationError as exc:
        raise BrowserReasoningError(
            f"reasoning model violated compact action schema: {exc}",
            status_code=502,
        ) from exc

    # Preserve the existing downstream contract. The rest of VeilGraph still
    # receives a normal BrowserActionPlan and performs its independent
    # deterministic validation afterward.
    return plan.model_dump_json(by_alias=True, exclude_none=True)


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
            visual_context_used=_reasoning_uses_visual(request.payload),
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
