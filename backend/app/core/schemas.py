from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .enums import (
    AudienceProfile,
    DetectionSource,
    EntityType,
    FileType,
    GraphEdgeType,
    GraphNodeKind,
    JobStatus,
    OutputStatus,
    PrivacyLevel,
    ReviewStatus,
    SensitivityLevel,
    TestStatus,
    TransformationType,
)


class JobCreate(BaseModel):
    purpose: str = Field(min_length=1, max_length=200)
    recipient: str = Field(min_length=1, max_length=200)
    audience_profile: AudienceProfile = AudienceProfile.PUBLIC_RELEASE
    privacy_level: PrivacyLevel = PrivacyLevel.CONTEXT_GENERALIZATION
    retention_seconds: int = Field(default=3600, ge=60, le=86400)


class JobResponse(BaseModel):
    id: str
    purpose: str
    recipient: str
    audience_profile: AudienceProfile
    privacy_level: PrivacyLevel
    retention_seconds: int
    expires_at: datetime
    status: JobStatus
    created_at: datetime
    updated_at: datetime


class FileResponse(BaseModel):
    id: str
    job_id: str
    original_filename: str
    file_type: FileType
    media_type: str
    sha256: str
    page_count: int
    status: str
    created_at: datetime


class CanonicalEntityResponse(BaseModel):
    id: str
    job_id: str
    file_id: str
    entity_type: EntityType
    fingerprint: str
    placeholder: str
    sensitivity: SensitivityLevel
    transformation: TransformationType
    mention_count: int


class EntityMentionResponse(BaseModel):
    id: str
    canonical_entity_id: str
    page_index: int
    page_char_start: int
    page_char_end: int
    x0: float
    y0: float
    x1: float
    y1: float
    confidence: float
    source: DetectionSource
    review_status: ReviewStatus
    context_label: str | None = None


class EntityWithMentions(BaseModel):
    entity: CanonicalEntityResponse
    mentions: list[EntityMentionResponse]


class DocxEvidenceUnitResponse(BaseModel):
    page_index: int
    kind: str
    part_name: str
    label: str



class VideoEvidenceUnitResponse(BaseModel):
    page_index: int
    frame_index: int
    timestamp_seconds: float
    label: str
    is_evidence: bool = False
    security_scanned: bool = True
    full_ocr_selected: bool = False
    security_promoted: bool = False


class AnalysisResponse(BaseModel):
    job_id: str
    file_id: str
    file_type: FileType
    page_count: int
    scanned_pages: int
    canonical_entities: int
    mentions: int
    direct_identifier_mentions: int
    quasi_identifier_mentions: int
    visual_mentions: int
    pending_reviews: int
    privacy_ir_schema: str
    privacy_ir_units: int
    privacy_ir_commitment_sha256: str
    structured_format: str | None = None
    structured_records: int = 0
    structured_fields: int = 0
    structured_sheets: int = 0
    structured_cells: int = 0
    structured_schema_sha256: str | None = None
    docx_text_parts: int = 0
    docx_media_images: int = 0
    docx_units: list[DocxEvidenceUnitResponse] = Field(default_factory=list)
    video_duration_seconds: float = 0.0
    video_fps: float = 0.0
    video_width: int = 0
    video_height: int = 0
    video_total_frames: int = 0
    video_sampled_frames: int = 0
    video_security_frames_analyzed: int = 0
    video_security_detection_frames: int = 0
    video_novel_security_frames: int = 0
    video_security_coverage_percent: float = 0.0
    video_security_policy: str | None = None
    video_has_audio: bool = False
    video_audio_policy: str | None = None
    video_units: list[VideoEvidenceUnitResponse] = Field(default_factory=list)
    status: JobStatus


class ReviewRequest(BaseModel):
    action: ReviewStatus


class ReviewResponse(BaseModel):
    mention_id: str
    review_status: ReviewStatus
    pending_reviews: int
    job_status: JobStatus




class PrivacyLevelPreviewResponse(BaseModel):
    privacy_level: PrivacyLevel
    supported: bool
    risk_before: int = Field(ge=0, le=100)
    residual_risk: int = Field(ge=0, le=100)
    utility_score: int = Field(ge=0, le=100)
    label: str
    limitation: str | None = None


class PrivacyRecommendationResponse(BaseModel):
    recommended_level: PrivacyLevel
    minimum_level: PrivacyLevel
    policy_floor_enforced: bool
    override_allowed: bool
    reasons: list[str]
    previews: list[PrivacyLevelPreviewResponse]
    methodology: str
    disclaimer: str


class TransformRequest(BaseModel):
    privacy_level: PrivacyLevel = PrivacyLevel.CONTEXT_GENERALIZATION


class TransformResponse(BaseModel):
    output_id: str
    job_id: str
    file_id: str
    privacy_level: PrivacyLevel
    transformations_applied: int
    output_media_type: str
    download_name: str
    risk_before: int
    residual_risk: int
    utility_score: int
    status: OutputStatus
    synthetic_twin: dict[str, Any] | None = None


class VerificationTestResult(BaseModel):
    name: str
    status: TestStatus
    detail: str
    attack_class: str
    severity: Literal["critical", "high", "medium"]


class VerificationResponse(BaseModel):
    output_id: str
    status: OutputStatus
    tests: list[VerificationTestResult]
    passed: int
    failed: int
    inconclusive: int
    proof_score: int = Field(ge=0, le=100)
    attack_coverage: int
    critical_failures: int
    risk_before: int = Field(ge=0, le=100)
    residual_risk: int = Field(ge=0, le=100)
    utility_score: int = Field(ge=0, le=100)
    release_decision: Literal["ALLOW_RELEASE", "BLOCK_RELEASE"]
    verified_at: datetime
    synthetic_twin: dict[str, Any] | None = None


class SignerResponse(BaseModel):
    algorithm: str
    public_key_b64: str
    public_key_sha256: str


class CertificatePayloadResponse(BaseModel):
    schema_id: str = Field(alias="schema", serialization_alias="schema")
    certificate_id: str
    product: str
    product_version: str
    issued_at: str
    verified_at: str
    job_commitment_sha256: str
    output_sha256: str
    input_sha256: str
    manifest_sha256: str
    graph_sha256: str
    verification_sha256: str
    privacy_level: int
    audience_profile: str
    proof_score: int
    attack_coverage: int
    critical_failures: int
    release_decision: str
    risk_before: int
    residual_risk: int
    utility_score: int
    audit_head_at_certification: str
    audit_events_at_certification: int
    signer: SignerResponse
    disclaimer: str


class CertificateResponse(BaseModel):
    payload: CertificatePayloadResponse
    signature_algorithm: str
    signature_b64: str
    signature_valid: bool


class AuditEventResponse(BaseModel):
    sequence: int
    event_type: str
    timestamp: datetime
    details: dict[str, Any]
    prev_hash: str
    event_hash: str


class AuditLedgerResponse(BaseModel):
    job_id: str
    valid: bool
    event_count: int
    chain_head: str
    error: str | None = None
    events: list[AuditEventResponse]


class DestructionReceiptPayloadResponse(BaseModel):
    schema_id: str = Field(alias="schema", serialization_alias="schema")
    product: str
    product_version: str
    issued_at: str
    job_commitment_sha256: str
    trigger: str
    audit_integrity_valid: bool
    retention_deadline: str
    final_audit_head: str
    final_audit_event_count: int
    deleted_workspace_files: int
    cleared_plaintext_entities: int
    destroyed_outputs: int
    deleted_database_rows: dict[str, int]
    signer: SignerResponse
    scope_note: str


class DestructionReceiptResponse(BaseModel):
    payload: DestructionReceiptPayloadResponse
    signature_algorithm: str
    signature_b64: str
    signature_valid: bool


class DestructionResponse(BaseModel):
    job_id: str
    status: JobStatus
    trigger: str
    deleted_workspace_files: int
    cleared_plaintext_entities: int
    destroyed_outputs: int
    deleted_database_rows: dict[str, int]
    note: str
    destruction_receipt: DestructionReceiptResponse


class OfflineStatusResponse(BaseModel):
    offline_mode: bool
    backend_address: str
    processing_location: str
    external_model_calls: str
    automatic_retention: bool
    retention_sweep_seconds: float
    restart_key_loss_policy: str
    bundled_components: list[str]
    non_local_inbound_requests: int
    local_api_requests: int
    device_signer_fingerprint: str
    certificate_algorithm: str
    statement: str


class PolicyRuleResponse(BaseModel):
    entity_type: EntityType
    action: Literal["MASK", "PROTECT", "REMOVE", "GENERALIZE", "PSEUDONYMIZE", "SYNTHESIZE", "RETAIN"]
    replacement_preview: str
    rationale: str


class PolicyResponse(BaseModel):
    audience_profile: AudienceProfile
    privacy_level: PrivacyLevel
    name: str
    objective: str
    rules: list[PolicyRuleResponse]


class GraphNodeResponse(BaseModel):
    id: str
    kind: GraphNodeKind
    label: str
    entity_id: str | None = None
    entity_type: EntityType | None = None
    sensitivity: SensitivityLevel | None = None
    mention_count: int = 0
    review_state: str = "approved"
    page_indexes: list[int] = Field(default_factory=list)


class GraphEdgeResponse(BaseModel):
    id: str
    source: str
    target: str
    edge_type: GraphEdgeType
    weight: int
    explanation: str


class RiskPathResponse(BaseModel):
    node_ids: list[str]
    score: int
    reason: str


class RiskBreakdownResponse(BaseModel):
    direct: int
    quasi_identifier: int
    relationship: int
    combination_bonus: int


class RiskSummaryResponse(BaseModel):
    before: int
    after: int
    reduction: int
    utility_score: int
    band_before: str
    band_after: str
    breakdown_before: RiskBreakdownResponse
    breakdown_after: RiskBreakdownResponse
    disclaimer: str


class ExposureGraphResponse(BaseModel):
    job_id: str
    file_id: str
    graph_version: str
    graph_sha256: str
    policy: PolicyResponse
    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]
    high_risk_paths: list[RiskPathResponse]
    risk: RiskSummaryResponse
