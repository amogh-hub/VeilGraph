from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class BrowserPublicVisualContext(BaseModel):
    """Sanitized raster context eligible for external reasoning.

    The raw screenshot is never represented by this type. ``image_base64`` must
    be a newly encoded, flattened image produced after local redaction.
    """

    model_config = ConfigDict(extra="forbid")

    mime_type: Literal["image/webp", "image/png"]
    width: int = Field(ge=1, le=16_384)
    height: int = Field(ge=1, le=16_384)
    image_base64: str = Field(min_length=8, max_length=12 * 1024 * 1024)
    sanitized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted_regions: int = Field(ge=0, le=5000)


class BrowserPublicPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    origin: str = Field(min_length=1, max_length=512)
    page_class: str = Field(default="web", max_length=64)
    title: str = Field(default="", max_length=256)
    elements: list[BrowserPublicElement] = Field(default_factory=list, max_length=500)
    visual_context: BrowserPublicVisualContext | None = None


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


class BrowserPairingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class BrowserPairingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal["veilgraph.browser-companion-pairing.v1"] = Field(
        default="veilgraph.browser-companion-pairing.v1", alias="schema", serialization_alias="schema"
    )
    challenge: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    purpose: Literal["PAIR_LOCAL_VEILGRAPH_COMPANION"] = "PAIR_LOCAL_VEILGRAPH_COMPANION"
    issued_at: datetime
    expires_at: datetime
    signer: BrowserSigner


class BrowserPairingAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: BrowserPairingPayload
    signature_algorithm: Literal["Ed25519"] = "Ed25519"
    signature_b64: str


class BrowserReleasePreparationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal["veilgraph.browser-release-preparation.v1"] = Field(
        default="veilgraph.browser-release-preparation.v1", alias="schema", serialization_alias="schema"
    )
    analysis: "BrowserLocalAnalysisResponse"
    payload: BrowserReleasePayload
    verification: BrowserVerificationSummary
    authorization: BrowserNetworkAuthorization

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
    device_pixel_ratio_basis_points: int = Field(default=10_000, ge=1_000, le=80_000)
    scroll_x: int = Field(default=0, ge=-10_000_000, le=10_000_000)
    scroll_y: int = Field(default=0, ge=-10_000_000, le=10_000_000)
    document_width: int = Field(default=1, ge=1, le=10_000_000)
    document_height: int = Field(default=1, ge=1, le=10_000_000)
    elements: list[BrowserLocalElement] = Field(default_factory=list, max_length=2000)
    eligible_element_count: int = Field(default=0, ge=0, le=1_000_000)
    captured_element_count: int = Field(default=0, ge=0, le=2000)
    capture_truncated: bool = False
    shadow_root_count: int = Field(default=0, ge=0, le=100_000)
    capture_elapsed_ms: int = Field(default=0, ge=0, le=120_000)
    inaccessible_descendant_frames: int = Field(default=0, ge=0, le=256)

    @model_validator(mode="after")
    def validate_element_accounting(self):
        if self.captured_element_count and self.captured_element_count != len(self.elements):
            raise ValueError("captured_element_count must match the number of captured elements")
        if self.eligible_element_count and self.eligible_element_count < len(self.elements):
            raise ValueError("eligible_element_count cannot be smaller than captured elements")
        if self.capture_truncated and self.eligible_element_count <= len(self.elements):
            raise ValueError("capture_truncated requires eligible elements beyond the capture limit")
        return self


class BrowserLocalVisualFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    type: Literal["FACE", "QR_CODE", "TEXT_REGION", "PASSWORD_FIELD", "SENSITIVE_REGION", "OTHER"]
    confidence_basis_points: int = Field(ge=0, le=10_000)
    bbox: tuple[int, int, int, int]
    label: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=128)
    modalities: list[Literal["DOM", "ACCESSIBILITY", "VISUAL"]] = Field(default_factory=list, max_length=3)
    related_element_ids: list[str] = Field(default_factory=list, max_length=64)


class BrowserVisualCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal[
        "SCREENSHOT_DECODE",
        "FACE_DETECTION",
        "QR_DETECTION",
        "TEXT_REGION_DETECTION",
        "DOM_SENSITIVE_PROJECTION",
        "OCR_TEXT_EXTRACTION",
    ]
    status: Literal["READY", "UNAVAILABLE", "ERROR"]
    backend: str = Field(min_length=1, max_length=128)
    required: bool = True
    detail: str = Field(min_length=1, max_length=512)


class BrowserVisualStageTimings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    screenshot_decode_ms: int = Field(default=0, ge=0, le=120_000)
    dom_projection_ms: int = Field(default=0, ge=0, le=120_000)
    face_detection_ms: int = Field(default=0, ge=0, le=120_000)
    qr_detection_ms: int = Field(default=0, ge=0, le=120_000)
    text_region_ms: int = Field(default=0, ge=0, le=120_000)
    fusion_ms: int = Field(default=0, ge=0, le=120_000)


class BrowserCaptureTimings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    frame_dom_ms: int = Field(default=0, ge=0, le=120_000)
    screenshot_capture_ms: int = Field(default=0, ge=0, le=120_000)
    visual_perception_ms: int = Field(default=0, ge=0, le=120_000)
    total_local_ms: int = Field(default=0, ge=0, le=120_000)


class BrowserCaptureCoverageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal["DOM", "ACCESSIBILITY", "VISUAL", "TEXT_REGIONS", "FACE", "QR"]
    status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    required: bool = True
    detail: str = Field(min_length=1, max_length=512)


class BrowserVisualPerceptionReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    model_id: str = Field(min_length=1, max_length=128)
    backend: str = Field(min_length=1, max_length=128)
    elapsed_ms: int = Field(ge=0, le=120_000)
    image_width: int = Field(ge=0, le=16_384)
    image_height: int = Field(ge=0, le=16_384)
    capabilities: list[BrowserVisualCapability] = Field(default_factory=list, max_length=32)
    finding_count: int = Field(ge=0, le=10_000)
    stage_timings_ms: BrowserVisualStageTimings = Field(default_factory=BrowserVisualStageTimings)


class BrowserLocalCaptureMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_id: Literal["veilgraph.browser-local-capture.v1"] = Field(
        default="veilgraph.browser-local-capture.v1",
        alias="schema",
        serialization_alias="schema",
    )
    capture_id: str | None = Field(default=None, min_length=8, max_length=96, pattern=r"^VGC-[A-F0-9]+$")
    captured_at: datetime
    tab_id: int = Field(ge=0)
    task: str = Field(min_length=1, max_length=1000)
    audience_profile: str = Field(default="PUBLIC_RELEASE", max_length=64)
    requested_privacy_level: int = Field(default=4, ge=1, le=5)
    frames: list[BrowserLocalFrame] = Field(min_length=1, max_length=64)
    expected_frame_count: int | None = Field(default=None, ge=1, le=256)
    captured_frame_count: int | None = Field(default=None, ge=1, le=64)
    failed_frame_ids: list[int] = Field(default_factory=list, max_length=256)
    capture_timings: BrowserCaptureTimings | None = None
    coverage: list[BrowserCaptureCoverageItem] = Field(default_factory=list, max_length=16)
    visual_perception_status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    visual_perception_report: BrowserVisualPerceptionReport | None = None
    visual_findings: list[BrowserLocalVisualFinding] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_frame_geometry_contract(self):
        frame_ids = [frame.frame_id for frame in self.frames]
        if len(frame_ids) != len(set(frame_ids)):
            raise ValueError("browser capture frame_id values must be unique")
        top_frames = [frame for frame in self.frames if frame.is_top_frame]
        if len(top_frames) != 1 or top_frames[0].frame_id != 0:
            raise ValueError("browser capture must contain exactly one top frame with frame_id=0")
        if not self.frames[0].is_top_frame or self.frames[0].frame_id != 0:
            raise ValueError("top frame must be first so screenshot pixel geometry remains unambiguous")
        if self.captured_frame_count is not None and self.captured_frame_count != len(self.frames):
            raise ValueError("captured_frame_count must match the number of captured frames")
        if self.expected_frame_count is not None and self.expected_frame_count < len(self.frames):
            raise ValueError("expected_frame_count cannot be smaller than captured frames")
        if self.expected_frame_count is not None and self.captured_frame_count is not None:
            if self.captured_frame_count + len(set(self.failed_frame_ids)) > self.expected_frame_count:
                raise ValueError("captured + failed frame accounting exceeds expected_frame_count")
        coverage_names = [item.name for item in self.coverage]
        if len(coverage_names) != len(set(coverage_names)):
            raise ValueError("browser capture coverage names must be unique")
        return self


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
    browser_visual_perception_status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    local_companion_visual_status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    visual_perception_status: Literal["READY", "PARTIAL", "UNAVAILABLE", "ERROR"]
    visual_capabilities: list[BrowserVisualCapability] = Field(default_factory=list, max_length=64)
    ocr_lines: int = Field(ge=0)
    visual_findings_count: int = Field(ge=0)
    capture_id: str | None = None
    expected_frames: int = Field(ge=1)
    captured_frames: int = Field(ge=1)
    failed_frames: int = Field(ge=0)
    capture_timings: BrowserCaptureTimings | None = None
    browser_capture_coverage: list[BrowserCaptureCoverageItem] = Field(default_factory=list, max_length=16)
    readiness: Literal["READY_FOR_SANITIZATION", "NEEDS_REVIEW", "VISUAL_COVERAGE_INCOMPLETE"]
    note: str

BrowserReleasePreparationResponse.model_rebuild()
