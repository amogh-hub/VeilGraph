from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import TestStatus


BROWSER_RELEASE_SCHEMA = "veilgraph.browser-release-payload.v1"
BROWSER_AUTH_SCHEMA = "veilgraph.browser-network-authorization.v1"


class BrowserPublicElement(BaseModel):
    """Allow-listed, sanitized semantic UI element safe for external reasoning.

    This model intentionally has no generic attributes/dataset/style/value fields.
    Internal capture objects must be transformed into this allow-list rather than
    serialized wholesale.
    """

    model_config = ConfigDict(extra="forbid")

    element_id: str = Field(min_length=8, max_length=96, pattern=r"^vg_[A-Za-z0-9_-]+$")
    role: str = Field(min_length=1, max_length=64)
    label: str = Field(default="", max_length=256)
    text: str = Field(default="", max_length=512)
    control_type: str | None = Field(default=None, max_length=64)
    disabled: bool = False
    checked: bool | None = None
    selected: bool | None = None
    # Viewport-normalized coordinates in basis points (0..10000). Integers
    # avoid cross-runtime JSON float canonicalization ambiguity in signed payloads.
    bbox: tuple[int, int, int, int] | None = None

    @field_validator("bbox")
    @classmethod
    def validate_bbox(cls, value: tuple[int, int, int, int] | None):
        if value is None:
            return None
        x0, y0, x1, y1 = value
        if not all(0 <= item <= 10_000 for item in value):
            raise ValueError("bbox coordinates must be viewport basis points in [0, 10000]")
        if x1 < x0 or y1 < y0:
            raise ValueError("bbox must have non-negative width and height")
        return value


class BrowserPublicPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    origin: str = Field(min_length=1, max_length=512)
    page_class: str = Field(default="web", max_length=64)
    title: str = Field(default="", max_length=256)
    elements: list[BrowserPublicElement] = Field(default_factory=list, max_length=500)


class BrowserReleasePayload(BaseModel):
    """The only page-context object eligible for external transmission."""

    model_config = ConfigDict(extra="forbid")

    schema_id: Literal[BROWSER_RELEASE_SCHEMA] = Field(
        default=BROWSER_RELEASE_SCHEMA,
        alias="schema",
        serialization_alias="schema",
    )
    session_id: str = Field(min_length=16, max_length=96)
    task_id: str = Field(min_length=16, max_length=96)
    task: str = Field(min_length=1, max_length=1000)
    page: BrowserPublicPage
    privacy_level: int = Field(ge=1, le=5)
    network_privacy_floor: int = Field(ge=1, le=5)
    identity_exposure_before: int = Field(ge=0, le=100)
    residual_identity_exposure: int = Field(ge=0, le=100)
    task_utility_score: int = Field(ge=0, le=100)
    minimization_basis_points: int = Field(ge=0, le=10_000)

    @field_validator("network_privacy_floor")
    @classmethod
    def floor_is_valid(cls, value: int):
        return value


class BrowserGateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    status: TestStatus
    detail: str = Field(min_length=1, max_length=1000)
    attack_class: str = Field(min_length=1, max_length=128)
    severity: Literal["critical", "high", "medium"]
    mandatory: bool = True


class BrowserVerificationSummary(BaseModel):
    """Trusted local verifier output consumed by the deterministic release gate."""

    model_config = ConfigDict(extra="forbid")

    tests: list[BrowserGateResult] = Field(min_length=1, max_length=64)
    proof_score: int = Field(ge=0, le=100)
    critical_failures: int = Field(ge=0)
    policy_floor_satisfied: bool
    forbidden_raw_fields_present: bool
    payload_commitment_valid: bool
    critical_exposure_present: bool = False


class BrowserSigner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BrowserNetworkAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal[BROWSER_AUTH_SCHEMA] = Field(
        default=BROWSER_AUTH_SCHEMA,
        alias="schema",
        serialization_alias="schema",
    )
    authorization_id: str = Field(pattern=r"^VGN-[A-F0-9]{20}$")
    decision: Literal["ALLOW_NETWORK_RELEASE", "DENY_NETWORK_RELEASE"]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_id: str
    task_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=24, max_length=128)
    proof_score: int = Field(ge=0, le=100)
    mandatory_gates: int = Field(ge=0)
    mandatory_passed: int = Field(ge=0)
    critical_failures: int = Field(ge=0)
    identity_exposure_before: int = Field(ge=0, le=100)
    residual_identity_exposure: int = Field(ge=0, le=100)
    task_utility_score: int = Field(ge=0, le=100)
    signer: BrowserSigner
    disclaimer: str


class BrowserNetworkAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: BrowserNetworkAuthorizationPayload
    signature_algorithm: Literal["Ed25519"] = "Ed25519"
    signature_b64: str

class BrowserLocalElement(BaseModel):
    """Raw/local-only semantic element captured by the extension.

    This model must never be used as an external network payload.
    """

    model_config = ConfigDict(extra="forbid")

    local_id: str = Field(min_length=8, max_length=96, pattern=r"^vg_[A-Za-z0-9_-]+$")
    tag: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=64)
    accessible_name: str = Field(default="", max_length=512)
    visible_text: str = Field(default="", max_length=1024)
    input_type: str | None = Field(default=None, max_length=64)
    raw_value: str | None = Field(default=None, max_length=4096)
    disabled: bool = False
    checked: bool | None = None
    selected: bool | None = None
    bbox: tuple[int, int, int, int]
    privacy_hints: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("bbox")
    @classmethod
    def validate_local_bbox(cls, value: tuple[int, int, int, int]):
        x0, y0, x1, y1 = value
        if not all(0 <= item <= 10_000 for item in value):
            raise ValueError("bbox coordinates must be viewport basis points in [0, 10000]")
        if x1 < x0 or y1 < y0:
            raise ValueError("bbox must have non-negative width and height")
        return value


class BrowserLocalFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    frame_id: int = Field(ge=0)
    is_top_frame: bool
    origin: str = Field(min_length=1, max_length=512)
    href: str = Field(min_length=1, max_length=4096)
    title: str = Field(default="", max_length=512)
    viewport_width: int = Field(ge=1, le=16_384)
    viewport_height: int = Field(ge=1, le=16_384)
    elements: list[BrowserLocalElement] = Field(default_factory=list, max_length=2000)
    inaccessible_descendant_frames: int = Field(default=0, ge=0, le=256)


class BrowserLocalVisualFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    type: Literal["FACE", "QR_CODE", "TEXT_REGION", "PASSWORD_FIELD", "SENSITIVE_REGION", "OTHER"]
    confidence_basis_points: int = Field(ge=0, le=10_000)
    bbox: tuple[int, int, int, int]
    label: str | None = Field(default=None, max_length=256)


class BrowserLocalCaptureMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal["veilgraph.browser-local-capture.v1"] = Field(
        default="veilgraph.browser-local-capture.v1",
        alias="schema",
        serialization_alias="schema",
    )
    captured_at: datetime
    tab_id: int = Field(ge=0)
    task: str = Field(min_length=1, max_length=1000)
    audience_profile: str = Field(default="PUBLIC_RELEASE", max_length=64)
    requested_privacy_level: int = Field(default=4, ge=1, le=5)
    frames: list[BrowserLocalFrame] = Field(min_length=1, max_length=64)
    visual_perception_status: Literal["READY", "UNAVAILABLE", "ERROR"]
    visual_findings: list[BrowserLocalVisualFinding] = Field(default_factory=list, max_length=1000)


class BrowserDetectionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    mentions: int = Field(ge=1)
    sources: list[str]
    pending_review: bool


class BrowserLocalAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal["veilgraph.browser-local-analysis.v1"] = Field(
        default="veilgraph.browser-local-analysis.v1",
        alias="schema",
        serialization_alias="schema",
    )
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    screenshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_elements: int = Field(ge=0)
    credential_fields: int = Field(ge=0)
    detections: list[BrowserDetectionSummary]
    pending_reviews: int = Field(ge=0)
    identity_exposure_graph: dict
    risk_before: int = Field(ge=0, le=100)
    residual_risk_preview: int = Field(ge=0, le=100)
    utility_preview: int = Field(ge=0, le=100)
    visual_perception_status: Literal["READY", "UNAVAILABLE", "ERROR"]
    readiness: Literal["READY_FOR_SANITIZATION", "NEEDS_REVIEW", "VISUAL_COVERAGE_INCOMPLETE"]
    note: str
