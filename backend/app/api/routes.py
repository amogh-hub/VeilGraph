from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
import secrets
from dataclasses import replace
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.audit.ledger import append_event, verify_ledger
from app.core.config import settings
from app.core.database import db, utc_now
from app.core.enums import (
    AudienceProfile,
    DetectionSource,
    EntityType,
    FileType,
    JobStatus,
    OutputStatus,
    PrivacyLevel,
    ReviewStatus,
    SensitivityLevel,
    TestStatus,
    TransformationType,
)
from app.core.schemas import (
    AnalysisResponse,
    AuditLedgerResponse,
    CanonicalEntityResponse,
    CertificateResponse,
    DestructionResponse,
    EntityMentionResponse,
    EntityWithMentions,
    ExposureGraphResponse,
    FileResponse,
    JobCreate,
    JobResponse,
    OfflineStatusResponse,
    PrivacyRecommendationResponse,
    ReviewRequest,
    ReviewResponse,
    TransformRequest,
    TransformResponse,
    VerificationResponse,
    VerificationTestResult,
)
from app.detection.direct_identifiers import normalize_value
from app.detection.docx_context import detect_docx_structural_context
from app.detection.video_context import detect_video_structural_context
from app.detection.pipeline import detect_all
from app.extraction.document_processor import DocumentProcessingError, process_document
from app.graph.exposure_graph import build_exposure_graph
from app.ir.privacy_ir import build_privacy_ir, privacy_ir_summary, to_processed_document
from app.ingestion.validator import ValidationError, sanitize_filename, validate_upload
from app.policy.compiler import DIRECT_TYPES, QUASI_TYPES, VISUAL_TYPES, action_for, replacement_for_policy
from app.policy.recommendation import recommend_privacy_level
from app.presentation.preview import annotated_preview, plain_preview
from app.presentation.annotated_export import build_annotation_evidence, build_annotated_export
from app.proof.certificate import (
    build_proof_bundle,
    certificate_pdf,
    issue_certificate,
    verify_certificate,
)
from app.proof.package import build_proof_package, issue_bundle_receipt
from app.security.signing import canonical_json_bytes, public_key_b64, sign_payload, signer_fingerprint
from app.security.workspace import WorkspaceError, create_workspace, get_workspace
from app.security.retention import destroy_job_with_receipt, retention_deadline_iso, stored_destruction_response
from app.transformation.sanitizer import ProtectionInstruction, instruction_manifest, sanitize_document
from app.transformation.synthetic_twin import synthesize_structured_twin
from app.transformation.synthetic_export import SUPPORTED_SYNTHETIC_EXPORT_FORMATS, export_synthetic_representation
from app.verification.red_team import proof_score, run_red_team

router = APIRouter(prefix="/api/v1")

_local_api_requests = 0
_non_local_inbound_requests = 0


def increment_local_request() -> None:
    global _local_api_requests
    _local_api_requests += 1


def increment_non_local_inbound() -> None:
    global _non_local_inbound_requests
    _non_local_inbound_requests += 1


def _job_or_404(job_id: str) -> dict[str, Any]:
    job = db.fetchone("SELECT * FROM jobs WHERE id=?", (job_id,))
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] == JobStatus.DESTROYED.value:
        raise HTTPException(status_code=410, detail="Job has been destroyed")
    return job


def _file_or_404(job_id: str, file_id: str) -> dict[str, Any]:
    file_row = db.fetchone("SELECT * FROM files WHERE id=? AND job_id=?", (file_id, job_id))
    if file_row is None:
        raise HTTPException(status_code=404, detail="File not found for this job")
    return file_row


def _output_or_404(job_id: str, output_id: str) -> dict[str, Any]:
    output = db.fetchone("SELECT * FROM outputs WHERE id=? AND job_id=?", (output_id, job_id))
    if output is None:
        raise HTTPException(status_code=404, detail="Output not found for this job")
    return output


def _certificate_or_404(job_id: str, output_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    row = db.fetchone(
        "SELECT * FROM proof_certificates WHERE job_id=? AND output_id=?",
        (job_id, output_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Proof certificate has not been issued for this output")
    certificate = json.loads(row["certificate_json"])
    return row, certificate


def _job_response(job: dict[str, Any]) -> JobResponse:
    return JobResponse(
        id=job["id"],
        purpose=job["purpose"],
        recipient=job["recipient"],
        audience_profile=AudienceProfile(job.get("audience_profile", AudienceProfile.PUBLIC_RELEASE.value)),
        privacy_level=PrivacyLevel(job["privacy_level"]),
        retention_seconds=int(job["retention_seconds"]),
        expires_at=retention_deadline_iso(job),
        status=JobStatus(job["status"]),
        created_at=job["created_at"],
        updated_at=job["updated_at"],
    )


def _placeholder(entity_type: EntityType, index: int) -> str:
    return f"{entity_type.value}_{index:03d}"


def _pending_reviews(job_id: str, file_id: str | None = None) -> int:
    if file_id:
        query = (
            "SELECT COUNT(*) AS count FROM mentions m JOIN canonical_entities c ON c.id=m.canonical_entity_id "
            "WHERE c.job_id=? AND c.file_id=? AND m.review_status=?"
        )
        params: tuple[Any, ...] = (job_id, file_id, ReviewStatus.PENDING.value)
    else:
        query = (
            "SELECT COUNT(*) AS count FROM mentions m JOIN canonical_entities c ON c.id=m.canonical_entity_id "
            "WHERE c.job_id=? AND m.review_status=?"
        )
        params = (job_id, ReviewStatus.PENDING.value)
    row = db.fetchone(query, params)
    return int(row["count"] if row else 0)


def _entity_rows(job_id: str, file_id: str) -> list[dict[str, Any]]:
    return db.fetchall(
        """SELECT c.*, COUNT(m.id) AS mention_count
        FROM canonical_entities c LEFT JOIN mentions m ON m.canonical_entity_id=c.id
        WHERE c.job_id=? AND c.file_id=? GROUP BY c.id ORDER BY c.entity_type,c.placeholder""",
        (job_id, file_id),
    )


def _mentions_by_entity(entities: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {
        entity["id"]: db.fetchall(
            "SELECT * FROM mentions WHERE canonical_entity_id=? ORDER BY page_index,y0,x0",
            (entity["id"],),
        )
        for entity in entities
    }


def _graph(job: dict[str, Any], file_row: dict[str, Any], level: PrivacyLevel) -> dict[str, Any]:
    entities = _entity_rows(job["id"], file_row["id"])
    return build_exposure_graph(job, file_row, entities, _mentions_by_entity(entities), level)


@router.get("/status", response_model=OfflineStatusResponse)
def offline_status() -> OfflineStatusResponse:
    increment_local_request()
    return OfflineStatusResponse(
        offline_mode=settings.offline_mode,
        backend_address=f"{settings.bind_host}:{settings.bind_port}",
        processing_location="This device",
        external_model_calls="DISABLED",
        automatic_retention=bool(settings.retention_worker_enabled),
        retention_sweep_seconds=float(settings.retention_sweep_seconds),
        restart_key_loss_policy="ERASE_UNRECOVERABLE_JOBS",
        bundled_components=[
            "PyMuPDF",
            "orientation-aware local Tesseract OCR for rotated scans",
            "OpenCV QR and face detectors",
            "deterministic direct and quasi-identifier detectors",
            "native TXT / Markdown / canonical safe-RTF adapters through Universal Privacy IR",
            "secure DOCX WordprocessingML adapter with paragraph/table/header/footer and embedded-image protection",
            "Stage-2 MP4/MOV video adapter with every-physical-frame change screening, OCR on representative/novel security frames, temporal region interpolation and fail-closed audio stripping",
            "output-bound annotated evidence exports kept separate from clean release artifacts",
            "schema-aware CSV / JSON / XLSX adapters with record-level Privacy IR",
            "Identity Exposure Graph compiler",
            "audience-specific privacy policy compiler",
            "job-scoped stable pseudonym generator",
            "12-channel non-video Levels 1–4, 13-channel video and 15-channel Level 5 fail-closed Privacy Red Team",
            "weighted proof scoring and utility preservation checks",
            "SHA-256 tamper-evident audit ledger",
            "Ed25519 signed privacy proof certificates",
            "portable offline proof bundles with manifest and Identity Exposure Graph",
            "signed bundle receipts and independently verifiable complete proof packages",
            "pre-ingestion encrypted-PDF, render-budget and pixel-budget guards",
            "header-safe filename normalization",
            "signed destruction receipts",
            "automatic retention expiry with persisted Ed25519 destruction tombstones",
            "fail-safe orphan ciphertext deletion after RAM-key loss/restart",
        ],
        non_local_inbound_requests=_non_local_inbound_requests,
        local_api_requests=_local_api_requests,
        device_signer_fingerprint=signer_fingerprint(),
        certificate_algorithm="Ed25519",
        statement=(
            "VeilGraph Slice E compiles privacy locally, attacks the protected artifact through format-specific fail-closed release gates, "
            "then binds the result to a tamper-evident audit chain and Ed25519-signed proof certificate. "
            "The residual exposure and proof scores are calibrated product indicators, not legal guarantees of anonymity."
        ),
    )


@router.post("/jobs", response_model=JobResponse, status_code=201)
def create_job(payload: JobCreate) -> JobResponse:
    job_id = str(uuid.uuid4())
    try:
        create_workspace(job_id)
    except WorkspaceError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    now = utc_now()
    row = {
        "id": job_id,
        "purpose": payload.purpose,
        "recipient": payload.recipient,
        "audience_profile": payload.audience_profile.value,
        "privacy_level": int(payload.privacy_level),
        "retention_seconds": payload.retention_seconds,
        "status": JobStatus.CREATED.value,
        "created_at": now,
        "updated_at": now,
    }
    db.insert_job(row)
    append_event(job_id, "JOB_CREATED", {
        "purpose_sha256": hashlib.sha256(payload.purpose.encode("utf-8")).hexdigest(),
        "recipient_sha256": hashlib.sha256(payload.recipient.encode("utf-8")).hexdigest(),
        "audience_profile": payload.audience_profile.value,
        "privacy_level": int(payload.privacy_level),
        "retention_seconds": payload.retention_seconds,
    })
    increment_local_request()
    return _job_response(row)


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str) -> JobResponse:
    job = db.fetchone("SELECT * FROM jobs WHERE id=?", (job_id,))
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    increment_local_request()
    return _job_response(job)


@router.get("/jobs/{job_id}/destruction-receipt", response_model=DestructionResponse)
def destruction_receipt(job_id: str) -> DestructionResponse:
    job = db.fetchone("SELECT id FROM jobs WHERE id=?", (job_id,))
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    response = stored_destruction_response(job_id)
    if response is None:
        raise HTTPException(status_code=404, detail="Job has not been destroyed")
    increment_local_request()
    return DestructionResponse.model_validate(response)


@router.post("/jobs/{job_id}/files", response_model=FileResponse, status_code=201)
async def upload_file(job_id: str, file: UploadFile = File(...)) -> FileResponse:
    _job_or_404(job_id)
    data = await file.read()
    safe_filename = sanitize_filename(file.filename or "input")
    try:
        file_type, media_type, sha256 = validate_upload(data, safe_filename)
        workspace = get_workspace(job_id)
    except (ValidationError, WorkspaceError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    file_id = str(uuid.uuid4())
    encrypted_name = f"original-{file_id}.vgenc"
    workspace.write_encrypted(encrypted_name, data)
    now = utc_now()
    row = {
        "id": file_id,
        "job_id": job_id,
        "original_filename": safe_filename,
        "file_type": file_type.value,
        "media_type": media_type,
        "encrypted_name": encrypted_name,
        "sha256": sha256,
        "page_count": 0,
        "scanned_pages": 0,
        "status": "UPLOADED",
        "created_at": now,
    }
    db.insert_file(row)
    db.update_job_status(job_id, JobStatus.UPLOADED.value)
    append_event(job_id, "FILE_UPLOADED", {
        "file_id": file_id,
        "filename": row["original_filename"],
        "file_type": file_type.value,
        "media_type": media_type,
        "size_bytes": len(data),
        "input_sha256": sha256,
    })
    increment_local_request()
    return FileResponse(**{key: row[key] for key in FileResponse.model_fields})


def _merge_docx_product_detections(base, extra):
    """Merge post-holdout format-specific evidence without touching Broad PII v3.

    The frozen detector pipeline remains byte-identical to the pre-holdout
    manifest. Product adapters enrich DOCX/video analysis only.
    """
    merged = list(base)
    for candidate in extra:
        duplicate_index = None
        for index, existing in enumerate(merged):
            if existing.page_index != candidate.page_index or existing.entity_type != candidate.entity_type:
                continue
            same_value = normalize_value(candidate.entity_type, candidate.plaintext) == normalize_value(existing.entity_type, existing.plaintext)
            if not same_value:
                continue
            ax0, ay0, ax1, ay1 = existing.rect
            bx0, by0, bx1, by1 = candidate.rect
            ix0, iy0 = max(ax0, bx0), max(ay0, by0)
            ix1, iy1 = min(ax1, bx1), min(ay1, by1)
            intersection = max(0.0, ix1 - ix0) * max(0.0, iy1 - iy0)
            area_a = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0)
            area_b = max(0.0, bx1 - bx0) * max(0.0, by1 - by0)
            union = area_a + area_b - intersection
            iou = intersection / union if union else 0.0
            if iou >= 0.35:
                duplicate_index = index
                break
        if duplicate_index is None:
            merged.append(candidate)
        elif candidate.confidence > merged[duplicate_index].confidence:
            merged[duplicate_index] = candidate
    return sorted(merged, key=lambda item: (item.page_index, item.rect[1], item.rect[0], item.entity_type.value))


_FORMAT_TITLE_TERMS = frozenset({
    "support", "case", "brief", "video", "privacy", "demo", "record",
    "report", "evidence", "document", "service", "portal", "workflow",
    "dataset", "release", "application", "form", "summary", "note",
})


def _stabilize_format_context(detections, file_type: FileType):
    """Preserve accepted DOCX/video semantics around the frozen v4 detector.

    Broad PII v4 is intentionally frozen after the TAB evaluation, so product
    compatibility repairs live outside that frozen detector surface. Format
    adapters have stronger layout evidence for full location fields, and generic
    title phrases must not become human-review PERSON_NAME candidates merely
    because a heading begins with words such as ``Citizen``.
    """
    if file_type not in {FileType.DOCX, FileType.VIDEO, FileType.TEXT}:
        return list(detections)

    structural_prefix = (
        "docx-structural:location" if file_type == FileType.DOCX
        else "video-structural:location" if file_type == FileType.VIDEO
        else None
    )
    structural_locations = [
        item for item in detections
        if structural_prefix is not None
        and item.entity_type == EntityType.LOCALITY
        and (item.context_label or "").startswith(structural_prefix)
    ]

    result = []
    for item in detections:
        label = item.context_label or ""

        # The format adapter owns a complete labelled location such as
        # ``Bengaluru, Karnataka``. Suppress v4 component duplicates that are
        # fully contained by that stronger structural span.
        if item.entity_type == EntityType.LOCALITY and label.startswith("broad-pii-v4:"):
            contained = any(
                structural.page_index == item.page_index
                and structural.page_char_start <= item.page_char_start
                and structural.page_char_end >= item.page_char_end
                for structural in structural_locations
            )
            if contained:
                continue

        # v4's prose context is deliberately recall-oriented. On structured
        # media headings this can interpret title text (e.g. ``Support Video``)
        # as a person after a leading ``Citizen`` token. Only suppress phrases
        # that are overwhelmingly document-title vocabulary; real names such as
        # ``Citizen John Smith`` remain untouched.
        semantic_title_candidate = (
            label == "broad-pii-v4:person-context"
            or label.startswith("semantic-ner-v3:person_name:")
        )
        if item.entity_type == EntityType.PERSON_NAME and semantic_title_candidate:
            words = [
                token.strip(".,;:()[]{}-_/\\").casefold()
                for token in item.plaintext.split()
                if token.strip(".,;:()[]{}-_/\\")
            ]
            generic_terms = sum(word in _FORMAT_TITLE_TERMS for word in words)
            # A single all-uppercase generic heading noun (for example RECORD)
            # is structural vocabulary, not a person's identity. The v5 detector
            # remains frozen; this product adapter prevents that title artifact
            # from becoming a canonical identity and poisoning fail-closed release
            # verification when the same ordinary word appears later in prose.
            singleton_generic_heading = (
                len(words) == 1
                and generic_terms == 1
                and item.plaintext.strip().isupper()
            )
            generic_title_phrase = len(words) >= 2 and generic_terms >= max(1, len(words) - 1)
            if singleton_generic_heading or generic_title_phrase:
                continue

        result.append(item)
    return result


def _filter_video_geometry_only_qr(detections):
    """Drop video-only geometry hallucinations without modifying the frozen visual detector.

    The pre-holdout visual detector intentionally treats undecoded QR geometry as
    fail-closed evidence for documents/images. Text-heavy video security frames can
    repeatedly trigger those geometry-only candidates, so the Stage-2 adapter keeps
    decoded QR findings but suppresses undecoded geometry-only candidates for VIDEO.
    """
    return [
        item
        for item in detections
        if not (
            item.source == DetectionSource.VISUAL
            and item.entity_type == EntityType.QR_CODE
            and item.plaintext.startswith("UNDECODED_QR_CANDIDATE_")
        )
    ]


def _collapse_video_temporal_reviews(detections):
    """Require one human decision per repeated video identity track.

    OCR samples can recover the same person on every evidence frame. Presenting
    eleven identical review clicks is noise, not safer review. The first
    high-confidence occurrence remains fail-closed PENDING; later occurrences
    are linked to that same canonical value and remain policy-queued.
    """
    seen: set[tuple[str, str]] = set()
    result = []
    for item in detections:
        if item.review_status != ReviewStatus.PENDING or item.entity_type != EntityType.PERSON_NAME:
            result.append(item)
            continue
        normalized = normalize_value(item.entity_type, item.plaintext)
        key = (item.entity_type.value, normalized)
        if key in seen:
            result.append(replace(item, review_status=ReviewStatus.NOT_REQUIRED, context_label=(item.context_label or "video") + ":temporal-linked"))
        else:
            seen.add(key)
            result.append(item)
    return result


@router.post("/jobs/{job_id}/files/{file_id}/analyse", response_model=AnalysisResponse)
def analyse_file(job_id: str, file_id: str) -> AnalysisResponse:
    _job_or_404(job_id)
    file_row = _file_or_404(job_id, file_id)
    existing = db.fetchone("SELECT COUNT(*) AS count FROM canonical_entities WHERE file_id=?", (file_id,))
    if existing and existing["count"]:
        raise HTTPException(status_code=409, detail="File has already been analysed")
    try:
        workspace = get_workspace(job_id)
        original = workspace.read_encrypted(file_row["encrypted_name"])
        file_type = FileType(file_row["file_type"])
        processed = process_document(original, file_type, file_row["original_filename"])
        privacy_ir = build_privacy_ir(processed)
        ir_summary = privacy_ir_summary(privacy_ir)
        analysis_document = to_processed_document(privacy_ir)
        detections = detect_all(analysis_document)
        if file_type == FileType.TEXT:
            detections = _stabilize_format_context(detections, file_type)
        elif file_type == FileType.DOCX:
            detections = _merge_docx_product_detections(detections, detect_docx_structural_context(analysis_document))
            detections = _stabilize_format_context(detections, file_type)
        elif file_type == FileType.VIDEO:
            detections = _filter_video_geometry_only_qr(detections)
            detections = _merge_docx_product_detections(detections, detect_video_structural_context(analysis_document))
            detections = _stabilize_format_context(detections, file_type)
            detections = _collapse_video_temporal_reviews(detections)
    except (WorkspaceError, DocumentProcessingError, ValueError) as exc:
        db.update_job_status(job_id, JobStatus.FAILED.value)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    counters: dict[EntityType, int] = defaultdict(int)
    canonical_by_fingerprint: dict[str, dict[str, Any]] = {}
    direct_count = quasi_count = visual_count = pending = 0
    for detection in detections:
        if detection.source == DetectionSource.VISUAL:
            normalized = detection.plaintext
            visual_count += 1
        else:
            normalized = normalize_value(detection.entity_type, detection.plaintext)
            if detection.entity_type in QUASI_TYPES:
                quasi_count += 1
            else:
                direct_count += 1
        fingerprint = workspace.fingerprint(f"{detection.entity_type.value}:{normalized}")
        canonical = canonical_by_fingerprint.get(fingerprint)
        if canonical is None:
            counters[detection.entity_type] += 1
            entity_id = str(uuid.uuid4())
            canonical = {
                "id": entity_id,
                "job_id": job_id,
                "file_id": file_id,
                "entity_type": detection.entity_type.value,
                "fingerprint": fingerprint,
                "placeholder": _placeholder(detection.entity_type, counters[detection.entity_type]),
                "sensitivity": detection.sensitivity.value,
                "transformation": detection.transformation.value,
            }
            db.insert_canonical_entity(canonical)
            workspace.remember_plaintext(entity_id, detection.plaintext)
            canonical_by_fingerprint[fingerprint] = canonical
        db.insert_mention({
            "id": str(uuid.uuid4()),
            "canonical_entity_id": canonical["id"],
            "page_index": detection.page_index,
            "page_char_start": detection.page_char_start,
            "page_char_end": detection.page_char_end,
            "x0": detection.rect[0], "y0": detection.rect[1], "x1": detection.rect[2], "y1": detection.rect[3],
            "confidence": detection.confidence,
            "source": detection.source.value,
            "review_status": detection.review_status.value,
            "context_label": detection.context_label,
        })
        if detection.review_status == ReviewStatus.PENDING:
            pending += 1

    status = JobStatus.HUMAN_REVIEW_REQUIRED if pending else JobStatus.ANALYSED
    db.execute(
        "UPDATE files SET page_count=?, scanned_pages=?, status=? WHERE id=?",
        (processed.page_count, processed.scanned_pages, "ANALYSED", file_id),
    )
    db.update_job_status(job_id, status.value)
    append_event(job_id, "ANALYSIS_COMPLETED", {
        "file_id": file_id,
        "page_count": processed.page_count,
        "scanned_pages": processed.scanned_pages,
        "canonical_entities": len(canonical_by_fingerprint),
        "mentions": len(detections),
        "direct_mentions": direct_count,
        "quasi_mentions": quasi_count,
        "visual_mentions": visual_count,
        "pending_reviews": pending,
        "privacy_ir": ir_summary,
    })
    increment_local_request()
    return AnalysisResponse(
        job_id=job_id,
        file_id=file_id,
        file_type=file_type,
        page_count=processed.page_count,
        scanned_pages=processed.scanned_pages,
        canonical_entities=len(canonical_by_fingerprint),
        mentions=len(detections),
        direct_identifier_mentions=direct_count,
        quasi_identifier_mentions=quasi_count,
        visual_mentions=visual_count,
        pending_reviews=pending,
        privacy_ir_schema=privacy_ir.schema,
        privacy_ir_units=privacy_ir.unit_count,
        privacy_ir_commitment_sha256=privacy_ir.commitment_sha256,
        structured_format=ir_summary.get("structured_format"),
        structured_records=int(ir_summary.get("structured_records", 0)),
        structured_fields=int(ir_summary.get("structured_fields", 0)),
        structured_sheets=int(ir_summary.get("structured_sheets", 0)),
        structured_cells=int(ir_summary.get("structured_cells", 0)),
        structured_schema_sha256=ir_summary.get("structured_schema_sha256"),
        docx_text_parts=int(ir_summary.get("docx_text_parts", 0)),
        docx_media_images=int(ir_summary.get("docx_media_images", 0)),
        docx_units=[
            {
                "page_index": int(item.get("page_index", 0)),
                "kind": str(item.get("kind", "TEXT")),
                "part_name": str(item.get("part_name", "")),
                "label": str(item.get("label", "DOCX part")),
            }
            for item in ir_summary.get("docx_page_map", [])
            if isinstance(item, dict)
        ],
        video_duration_seconds=float(ir_summary.get("video_duration_seconds", 0.0)),
        video_fps=float(ir_summary.get("video_fps", 0.0)),
        video_width=int(ir_summary.get("video_width", 0)),
        video_height=int(ir_summary.get("video_height", 0)),
        video_total_frames=int(ir_summary.get("video_total_frames", 0)),
        video_sampled_frames=int(ir_summary.get("video_sampled_frames", 0)),
        video_security_frames_analyzed=int(ir_summary.get("video_security_frames_analyzed", 0)),
        video_security_detection_frames=int(ir_summary.get("video_security_detection_frames", 0)),
        video_novel_security_frames=max(
            0,
            int(ir_summary.get("video_security_detection_frames", 0))
            - int(ir_summary.get("video_sampled_frames", 0)),
        ),
        video_security_coverage_percent=float(ir_summary.get("video_security_coverage_percent", 0.0)),
        video_security_policy=ir_summary.get("video_security_policy"),
        video_has_audio=bool(ir_summary.get("video_has_audio", False)),
        video_audio_policy=ir_summary.get("video_audio_policy"),
        video_units=[
            {
                "page_index": int(item.get("page_index", 0)),
                "frame_index": int(item.get("frame_index", 0)),
                "timestamp_seconds": float(item.get("timestamp_seconds", 0.0)),
                "label": str(item.get("label", "00:00.0")),
                "is_evidence": bool(item.get("is_evidence", False)),
                "security_scanned": bool(item.get("security_scanned", True)),
                "full_ocr_selected": bool(item.get("full_ocr_selected", False)),
                "security_promoted": bool(item.get("full_ocr_selected", False))
                and not bool(item.get("is_evidence", False)),
            }
            for item in ir_summary.get("video_frame_map", [])
            if isinstance(item, dict)
        ],
        status=status,
    )


@router.get("/jobs/{job_id}/files/{file_id}/entities", response_model=list[EntityWithMentions])
def list_entities(job_id: str, file_id: str) -> list[EntityWithMentions]:
    _job_or_404(job_id)
    _file_or_404(job_id, file_id)
    entities = _entity_rows(job_id, file_id)
    response: list[EntityWithMentions] = []
    for entity in entities:
        mentions = db.fetchall("SELECT * FROM mentions WHERE canonical_entity_id=? ORDER BY page_index,y0,x0", (entity["id"],))
        response.append(EntityWithMentions(
            entity=CanonicalEntityResponse(
                id=entity["id"], job_id=entity["job_id"], file_id=entity["file_id"],
                entity_type=EntityType(entity["entity_type"]), fingerprint=entity["fingerprint"],
                placeholder=entity["placeholder"], sensitivity=SensitivityLevel(entity["sensitivity"]),
                transformation=TransformationType(entity["transformation"]), mention_count=entity["mention_count"],
            ),
            mentions=[EntityMentionResponse(
                id=item["id"], canonical_entity_id=item["canonical_entity_id"], page_index=item["page_index"],
                page_char_start=item["page_char_start"], page_char_end=item["page_char_end"],
                x0=item["x0"], y0=item["y0"], x1=item["x1"], y1=item["y1"], confidence=item["confidence"],
                source=DetectionSource(item["source"]), review_status=ReviewStatus(item["review_status"]),
                context_label=item.get("context_label"),
            ) for item in mentions],
        ))
    increment_local_request()
    return response


@router.get("/jobs/{job_id}/files/{file_id}/graph", response_model=ExposureGraphResponse)
def exposure_graph(
    job_id: str,
    file_id: str,
    privacy_level: PrivacyLevel | None = Query(default=None),
) -> ExposureGraphResponse:
    job = _job_or_404(job_id)
    file_row = _file_or_404(job_id, file_id)
    level = privacy_level or PrivacyLevel(job["privacy_level"])
    increment_local_request()
    return ExposureGraphResponse.model_validate(_graph(job, file_row, level))


@router.get("/jobs/{job_id}/files/{file_id}/privacy-recommendation", response_model=PrivacyRecommendationResponse)
def privacy_recommendation(job_id: str, file_id: str) -> PrivacyRecommendationResponse:
    job = _job_or_404(job_id)
    file_row = _file_or_404(job_id, file_id)
    entity_rows = _entity_rows(job_id, file_id)
    entity_types = {EntityType(row["entity_type"]) for row in entity_rows}

    baseline = _graph(job, file_row, PrivacyLevel.DIRECT_MASKING)
    risk_before = int(baseline["risk"]["before"])
    decision = recommend_privacy_level(
        purpose=str(job["purpose"]),
        recipient=str(job["recipient"]),
        audience=AudienceProfile(job["audience_profile"]),
        file_type=FileType(file_row["file_type"]),
        risk_before=risk_before,
        entity_types=entity_types,
    )

    labels = {
        PrivacyLevel.DIRECT_MASKING: "Direct masking",
        PrivacyLevel.SENSITIVE_ENTITY_PROTECTION: "Opaque pseudonymization",
        PrivacyLevel.CONTEXT_GENERALIZATION: "Context generalization",
        PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION: "Relationship-safe pseudonymization",
        PrivacyLevel.SYNTHETIC_TWIN: "Synthetic Twin",
    }
    previews = []
    for level in PrivacyLevel:
        supported = level != PrivacyLevel.SYNTHETIC_TWIN or FileType(file_row["file_type"]) == FileType.DATASET
        if supported:
            graph = _graph(job, file_row, level)
            previews.append({
                "privacy_level": level,
                "supported": True,
                "risk_before": int(graph["risk"]["before"]),
                "residual_risk": int(graph["risk"]["after"]),
                "utility_score": int(graph["risk"]["utility_score"]),
                "label": labels[level],
                "limitation": None,
            })
        else:
            previews.append({
                "privacy_level": level,
                "supported": False,
                "risk_before": risk_before,
                "residual_risk": risk_before,
                "utility_score": 0,
                "label": labels[level],
                "limitation": "L5 Synthetic Twin is intentionally limited to structured CSV/JSON/XLSX datasets.",
            })

    increment_local_request()
    enforced = bool(settings.enforce_policy_floors)
    return PrivacyRecommendationResponse.model_validate({
        "recommended_level": decision.recommended_level,
        "minimum_level": decision.minimum_level,
        "policy_floor_enforced": enforced,
        "override_allowed": not enforced,
        "reasons": list(decision.reasons),
        "previews": previews,
        "methodology": "Deterministic purpose + recipient + audience + file-type + detected-sensitivity + Identity Exposure recommendation; no external model call.",
        "disclaimer": "This is an explainable product recommendation and privacy/utility estimate, not a legal or mathematical anonymity guarantee. The Privacy Red Team remains the release gate.",
    })


@router.get("/jobs/{job_id}/files/{file_id}/preview")
def original_preview(job_id: str, file_id: str, page: int = Query(default=0, ge=0)) -> Response:
    _job_or_404(job_id)
    file_row = _file_or_404(job_id, file_id)
    mentions = db.fetchall(
        """SELECT m.*, c.entity_type, c.placeholder FROM mentions m
        JOIN canonical_entities c ON c.id=m.canonical_entity_id
        WHERE c.job_id=? AND c.file_id=? AND m.page_index=? ORDER BY m.y0,m.x0""",
        (job_id, file_id, page),
    )
    try:
        original = get_workspace(job_id).read_encrypted(file_row["encrypted_name"])
        preview = annotated_preview(original, FileType(file_row["file_type"]), page, mentions)
    except (WorkspaceError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    increment_local_request()
    return Response(preview, media_type="image/png", headers={"Content-Disposition": "inline"})


@router.get("/jobs/{job_id}/outputs/{output_id}/preview")
def protected_preview(job_id: str, output_id: str, page: int = Query(default=0, ge=0)) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    file_row = _file_or_404(job_id, output["file_id"])
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
        preview = plain_preview(protected, FileType(file_row["file_type"]), page)
    except (WorkspaceError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    increment_local_request()
    return Response(preview, media_type="image/png", headers={"Content-Disposition": "inline"})


@router.post("/jobs/{job_id}/mentions/{mention_id}/review", response_model=ReviewResponse)
def review_mention(job_id: str, mention_id: str, payload: ReviewRequest) -> ReviewResponse:
    _job_or_404(job_id)
    if payload.action not in {ReviewStatus.PROTECT, ReviewStatus.IGNORE}:
        raise HTTPException(status_code=400, detail="Review action must be PROTECT or IGNORE")
    mention = db.fetchone(
        """SELECT m.*, c.file_id FROM mentions m JOIN canonical_entities c ON c.id=m.canonical_entity_id
        WHERE m.id=? AND c.job_id=?""",
        (mention_id, job_id),
    )
    if mention is None:
        raise HTTPException(status_code=404, detail="Mention not found for this job")
    db.execute("UPDATE mentions SET review_status=? WHERE id=?", (payload.action.value, mention_id))
    pending = _pending_reviews(job_id, mention["file_id"])
    status = JobStatus.HUMAN_REVIEW_REQUIRED if pending else JobStatus.ANALYSED
    db.update_job_status(job_id, status.value)
    entity_meta = db.fetchone(
        "SELECT c.entity_type,c.placeholder FROM canonical_entities c JOIN mentions m ON m.canonical_entity_id=c.id WHERE m.id=?",
        (mention_id,),
    ) or {}
    append_event(job_id, "HUMAN_REVIEW_RECORDED", {
        "mention_id": mention_id,
        "entity_type": entity_meta.get("entity_type", "UNKNOWN"),
        "placeholder": entity_meta.get("placeholder", "UNKNOWN"),
        "decision": payload.action.value,
        "pending_reviews": pending,
    })
    increment_local_request()
    return ReviewResponse(mention_id=mention_id, review_status=payload.action, pending_reviews=pending, job_status=status)


def _ordinal_map(rows: list[dict[str, Any]]) -> dict[str, int]:
    grouped: dict[EntityType, list[tuple[str, str]]] = defaultdict(list)
    seen: set[str] = set()
    for row in rows:
        if row["entity_id"] in seen:
            continue
        seen.add(row["entity_id"])
        grouped[EntityType(row["entity_type"])].append((row["placeholder"], row["entity_id"]))
    result: dict[str, int] = {}
    for items in grouped.values():
        for index, (_placeholder_value, entity_id) in enumerate(sorted(items)):
            result[entity_id] = index
    return result


@router.post("/jobs/{job_id}/files/{file_id}/transform", response_model=TransformResponse)
def transform_file(job_id: str, file_id: str, payload: TransformRequest) -> TransformResponse:
    job = _job_or_404(job_id)
    file_row = _file_or_404(job_id, file_id)
    pending = _pending_reviews(job_id, file_id)
    if pending:
        raise HTTPException(status_code=409, detail=f"{pending} candidate(s) require review before transformation")
    if settings.enforce_policy_floors:
        entity_types = {EntityType(row["entity_type"]) for row in _entity_rows(job_id, file_id)}
        risk_before = int(_graph(job, file_row, PrivacyLevel.DIRECT_MASKING)["risk"]["before"])
        decision = recommend_privacy_level(
            purpose=str(job["purpose"]), recipient=str(job["recipient"]),
            audience=AudienceProfile(job["audience_profile"]), file_type=FileType(file_row["file_type"]),
            risk_before=risk_before, entity_types=entity_types,
        )
        if payload.privacy_level < decision.minimum_level:
            raise HTTPException(
                status_code=409,
                detail=f"Organisational privacy floor requires Level {int(decision.minimum_level)} or higher for this job.",
            )
    rows = db.fetchall(
        """SELECT m.*, c.id AS entity_id, c.entity_type, c.placeholder
        FROM mentions m JOIN canonical_entities c ON c.id=m.canonical_entity_id
        WHERE c.job_id=? AND c.file_id=? AND m.review_status != ? ORDER BY c.entity_type,c.placeholder,m.page_index,m.y0,m.x0""",
        (job_id, file_id, ReviewStatus.IGNORE.value),
    )
    ignored_visual_rows = db.fetchall(
        """SELECT m.page_index,m.x0,m.y0,m.x1,m.y1,m.confidence,c.entity_type
        FROM mentions m JOIN canonical_entities c ON c.id=m.canonical_entity_id
        WHERE c.job_id=? AND c.file_id=? AND m.review_status=?
          AND c.entity_type IN (?,?,?)
        ORDER BY m.page_index,m.y0,m.x0""",
        (
            job_id,
            file_id,
            ReviewStatus.IGNORE.value,
            EntityType.QR_CODE.value,
            EntityType.FACE.value,
            EntityType.SIGNATURE_CANDIDATE.value,
        ),
    )
    reviewed_ignored_visual_regions = [
        {
            "entity_type": row["entity_type"],
            "page_index": int(row["page_index"]),
            "rect": [float(row["x0"]), float(row["y0"]), float(row["x1"]), float(row["y1"])],
            "confidence": float(row["confidence"]),
        }
        for row in ignored_visual_rows
    ]
    if not rows:
        raise HTTPException(status_code=400, detail="No approved identity exposures are available for transformation")
    audience = AudienceProfile(job["audience_profile"])
    if payload.privacy_level == PrivacyLevel.SYNTHETIC_TWIN and FileType(file_row["file_type"]) != FileType.DATASET:
        raise HTTPException(
            status_code=422,
            detail="Level 5 Synthetic Twin currently requires a structured CSV, JSON or XLSX dataset so schema/statistical utility can be measured and verified.",
        )
    ordinals = _ordinal_map(rows)
    expected_entity_ids: set[str] = set()
    synthetic_report: dict[str, Any] | None = None
    try:
        workspace = get_workspace(job_id)
        original = workspace.read_encrypted(file_row["encrypted_name"])
        instructions: list[ProtectionInstruction] = []
        for row in rows:
            entity_type = EntityType(row["entity_type"])
            action = action_for(entity_type, payload.privacy_level, audience)
            if action == "RETAIN":
                continue
            plaintext = workspace.get_plaintext(row["entity_id"])
            if plaintext is None:
                raise WorkspaceError(f"Plaintext for {row['placeholder']} is unavailable; re-analyse the job")
            replacement = replacement_for_policy(
                entity_type, plaintext, payload.privacy_level, audience, ordinals[row["entity_id"]]
            )
            expected_entity_ids.add(row["entity_id"])
            instructions.append(ProtectionInstruction(
                entity_id=row["entity_id"], mention_id=row["id"], entity_type=entity_type,
                page_index=row["page_index"], rect=(row["x0"], row["y0"], row["x1"], row["y1"]),
                replacement=replacement,
                char_start=int(row["page_char_start"]),
                char_end=int(row["page_char_end"]),
            ))
        if not instructions:
            raise ValueError("The selected policy retained every active entity; no protected output can be created")
        if payload.privacy_level == PrivacyLevel.SYNTHETIC_TWIN:
            twin = synthesize_structured_twin(original, instructions, file_row["original_filename"], release_salt=secrets.token_bytes(32))
            protected, output_media_type, _default_name = twin.data, twin.media_type, f"synthetic-twin{twin.extension}"
            instructions = [
                replace(item, replacement=twin.replacement_by_mention.get(item.mention_id, item.replacement))
                for item in instructions
            ]
            synthetic_report = twin.report
            report = {
                "transformations": len(instructions),
                "output_sha256": hashlib.sha256(protected).hexdigest(),
                "method": "Level 5 schema-aware Synthetic Twin generation",
                "structured_format": synthetic_report.get("schema", "veilgraph.synthetic-twin.v1"),
                "synthetic_twin": synthetic_report,
            }
        else:
            protected, output_media_type, _default_name, report = sanitize_document(
                original, FileType(file_row["file_type"]), instructions, file_row["original_filename"]
            )
    except (WorkspaceError, ValueError) as exc:
        db.update_job_status(job_id, JobStatus.FAILED.value)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Persist the selected level so subsequent graph views and the audit manifest agree.
    db.execute("UPDATE jobs SET privacy_level=?, updated_at=? WHERE id=?", (int(payload.privacy_level), utc_now(), job_id))
    job["privacy_level"] = int(payload.privacy_level)
    graph = _graph(job, file_row, payload.privacy_level)
    if synthetic_report is not None:
        graph["risk"]["utility_score"] = int(synthetic_report.get("utility_score", graph["risk"]["utility_score"]))
        privacy_residual = max(1, 100 - int(synthetic_report.get("privacy_score", 0)))
        graph["risk"]["after"] = min(int(graph["risk"]["after"]), privacy_residual)
        graph["risk"]["reduction"] = max(0, int(graph["risk"]["before"]) - int(graph["risk"]["after"]))
        graph["risk"]["band_after"] = "low" if graph["risk"]["after"] < 25 else "moderate" if graph["risk"]["after"] < 50 else "high" if graph["risk"]["after"] < 75 else "critical"
        graph_without_hash = dict(graph)
        graph_without_hash.pop("graph_sha256", None)
        graph["graph_sha256"] = hashlib.sha256(json.dumps(graph_without_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    output_id = str(uuid.uuid4())
    encrypted_name = f"output-{output_id}.vgenc"
    workspace.write_encrypted(encrypted_name, protected)
    base = file_row["original_filename"].rsplit(".", 1)[0] or "protected"
    if output_media_type == "application/pdf":
        suffix = ".pdf"
    elif output_media_type == "image/png":
        suffix = ".png"
    elif output_media_type.startswith("text/markdown"):
        suffix = ".md"
    elif output_media_type == "application/rtf":
        suffix = ".rtf"
    elif output_media_type.startswith("text/plain"):
        suffix = ".txt"
    elif output_media_type.startswith("text/csv"):
        suffix = ".csv"
    elif output_media_type == "application/json":
        suffix = ".json"
    elif output_media_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        suffix = ".xlsx"
    elif output_media_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        suffix = ".docx"
    elif output_media_type == "video/mp4":
        suffix = ".mp4"
    else:
        suffix = ".bin"
    download_name = f"{base}-level{int(payload.privacy_level)}-protected{suffix}"
    output_sha256 = hashlib.sha256(protected).hexdigest()
    annotation_evidence = build_annotation_evidence(
        rows=rows,
        instructions=instructions,
        privacy_level=payload.privacy_level,
        audience=audience,
        output_sha256=output_sha256,
    )
    now = utc_now()
    manifest = {
        "file_type": file_row["file_type"],
        "input_sha256": file_row["sha256"],
        "privacy_level": int(payload.privacy_level),
        "audience_profile": audience.value,
        "expected_entity_ids": sorted(expected_entity_ids),
        "reviewed_ignored_visual_regions": reviewed_ignored_visual_regions,
        "instructions": instruction_manifest(instructions),
        "transform_report": report,
        "synthetic_twin": synthetic_report,
        "annotation_evidence": annotation_evidence,
        "identity_exposure_graph": graph,
    }
    db.insert_output({
        "id": output_id, "job_id": job_id, "file_id": file_id, "encrypted_name": encrypted_name,
        "sha256": output_sha256, "media_type": output_media_type,
        "download_name": download_name, "status": OutputStatus.CREATED.value, "manifest": manifest, "created_at": now,
    })
    db.update_job_status(job_id, JobStatus.TRANSFORMED.value)
    append_event(job_id, "TRANSFORMATION_COMPLETED", {
        "file_id": file_id,
        "output_id": output_id,
        "privacy_level": int(payload.privacy_level),
        "audience_profile": audience.value,
        "transformations_applied": len(instructions),
        "output_sha256": output_sha256,
        "graph_sha256": graph.get("graph_sha256", ""),
        "risk_before": graph["risk"]["before"],
        "residual_risk": graph["risk"]["after"],
        "utility_score": graph["risk"]["utility_score"],
        "synthetic_twin": synthetic_report,
    })
    increment_local_request()
    return TransformResponse(
        output_id=output_id, job_id=job_id, file_id=file_id, privacy_level=payload.privacy_level,
        transformations_applied=len(instructions), output_media_type=output_media_type, download_name=download_name,
        risk_before=graph["risk"]["before"], residual_risk=graph["risk"]["after"],
        utility_score=graph["risk"]["utility_score"], status=OutputStatus.CREATED,
        synthetic_twin=synthetic_report,
    )


def _instructions_from_manifest(manifest: dict[str, Any]) -> list[ProtectionInstruction]:
    return [ProtectionInstruction(
        entity_id=item["entity_id"], mention_id=item["mention_id"], entity_type=EntityType(item["entity_type"]),
        page_index=int(item["page_index"]), rect=tuple(float(value) for value in item["rect"]), replacement=item["replacement"],
        char_start=int(item["char_start"]) if item.get("char_start") is not None else None,
        char_end=int(item["char_end"]) if item.get("char_end") is not None else None,
    ) for item in manifest["instructions"]]


@router.post("/jobs/{job_id}/outputs/{output_id}/verify", response_model=VerificationResponse)
def verify_output(job_id: str, output_id: str) -> VerificationResponse:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    file_row = _file_or_404(job_id, output["file_id"])
    try:
        workspace = get_workspace(job_id)
        protected = workspace.read_encrypted(output["encrypted_name"])
        original = workspace.read_encrypted(file_row["encrypted_name"])
        manifest = json.loads(output["manifest_json"])
        instructions = _instructions_from_manifest(manifest)
        transformed_entity_ids = {item.entity_id for item in instructions}
        known_values: list[tuple[EntityType, str]] = []
        for entity in db.fetchall("SELECT * FROM canonical_entities WHERE job_id=? AND file_id=?", (job_id, output["file_id"])):
            entity_type = EntityType(entity["entity_type"])
            if entity["id"] not in transformed_entity_ids or entity_type in VISUAL_TYPES:
                continue
            plaintext = workspace.get_plaintext(entity["id"])
            if plaintext is not None:
                known_values.append((entity_type, plaintext))
        tests = run_red_team(
            original, protected, FileType(file_row["file_type"]), known_values, instructions,
            expected_entity_ids=set(manifest.get("expected_entity_ids", [])),
            privacy_level=PrivacyLevel(manifest["privacy_level"]),
            reviewed_ignored_visual_regions=list(manifest.get("reviewed_ignored_visual_regions", [])),
            synthetic_twin=manifest.get("synthetic_twin"),
        )
    except (WorkspaceError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=f"Verification could not start: {exc}") from exc

    passed = sum(item.status == TestStatus.PASS for item in tests)
    failed = sum(item.status == TestStatus.FAIL for item in tests)
    inconclusive = sum(item.status == TestStatus.INCONCLUSIVE for item in tests)
    score = proof_score(tests)
    critical_failures = sum(
        item.severity == "critical" and item.status != TestStatus.PASS
        for item in tests
    )
    status = (
        OutputStatus.VERIFIED_SAFE
        if tests and passed == len(tests) and score == 100 and critical_failures == 0
        else OutputStatus.RELEASE_BLOCKED
    )
    graph_risk = manifest.get("identity_exposure_graph", {}).get("risk", {})
    risk_before = int(graph_risk.get("before", 0))
    residual_risk = int(graph_risk.get("after", 0))
    utility_score = int(graph_risk.get("utility_score", 0))
    release_decision = "ALLOW_RELEASE" if status == OutputStatus.VERIFIED_SAFE else "BLOCK_RELEASE"
    synthetic_report = manifest.get("synthetic_twin")
    verification_payload = {
        "tests": [
            {
                "name": item.name,
                "status": item.status.value,
                "detail": item.detail,
                "attack_class": item.attack_class,
                "severity": item.severity,
            }
            for item in tests
        ],
        "passed": passed,
        "failed": failed,
        "inconclusive": inconclusive,
        "proof_score": score,
        "attack_coverage": len(tests),
        "critical_failures": critical_failures,
        "risk_before": risk_before,
        "residual_risk": residual_risk,
        "utility_score": utility_score,
        "release_decision": release_decision,
        "synthetic_twin": synthetic_report,
    }
    verified_at = utc_now()
    db.update_output_verification(output_id, status.value, verification_payload, verified_at=verified_at)
    db.update_job_status(job_id, JobStatus.VERIFIED.value if status == OutputStatus.VERIFIED_SAFE else JobStatus.BLOCKED.value)
    append_event(job_id, "VERIFICATION_COMPLETED", {
        "output_id": output_id,
        "status": status.value,
        "proof_score": score,
        "attack_coverage": len(tests),
        "passed": passed,
        "failed": failed,
        "inconclusive": inconclusive,
        "critical_failures": critical_failures,
        "release_decision": release_decision,
        "verification_sha256": hashlib.sha256(canonical_json_bytes(verification_payload)).hexdigest(),
    })
    if status == OutputStatus.VERIFIED_SAFE:
        audit_snapshot = verify_ledger(job_id)
        certificate = issue_certificate(
            job_id=job_id,
            output=output,
            manifest=manifest,
            verification=verification_payload,
            verified_at=verified_at,
            audit_snapshot=audit_snapshot,
        )
        certificate_sha = hashlib.sha256(canonical_json_bytes(certificate)).hexdigest()
        db.upsert_certificate({
            "id": certificate["payload"]["certificate_id"],
            "job_id": job_id,
            "output_id": output_id,
            "certificate": certificate,
            "certificate_sha256": certificate_sha,
            "created_at": certificate["payload"]["issued_at"],
        })
        append_event(job_id, "PROOF_CERTIFICATE_ISSUED", {
            "output_id": output_id,
            "certificate_id": certificate["payload"]["certificate_id"],
            "certificate_sha256": certificate_sha,
            "signer_fingerprint": certificate["payload"]["signer"]["public_key_sha256"],
        })
    increment_local_request()
    return VerificationResponse(
        output_id=output_id,
        status=status,
        tests=[
            VerificationTestResult(
                name=item.name,
                status=item.status,
                detail=item.detail,
                attack_class=item.attack_class,
                severity=item.severity,
            )
            for item in tests
        ],
        passed=passed,
        failed=failed,
        inconclusive=inconclusive,
        proof_score=score,
        attack_coverage=len(tests),
        critical_failures=critical_failures,
        risk_before=risk_before,
        residual_risk=residual_risk,
        utility_score=utility_score,
        release_decision=release_decision,
        verified_at=verified_at,
        synthetic_twin=synthetic_report,
    )


@router.get("/jobs/{job_id}/audit", response_model=AuditLedgerResponse)
def audit_ledger(job_id: str) -> AuditLedgerResponse:
    _job_or_404(job_id)
    ledger = verify_ledger(job_id)
    increment_local_request()
    return AuditLedgerResponse.model_validate(ledger)


@router.get("/jobs/{job_id}/outputs/{output_id}/certificate", response_model=CertificateResponse)
def proof_certificate(job_id: str, output_id: str) -> CertificateResponse:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Certificate unavailable until every mandatory proof gate passes")
    _row, certificate = _certificate_or_404(job_id, output_id)
    increment_local_request()
    return CertificateResponse.model_validate({**certificate, "signature_valid": verify_certificate(certificate)})


@router.get("/jobs/{job_id}/outputs/{output_id}/certificate.pdf")
def proof_certificate_pdf(job_id: str, output_id: str) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Certificate unavailable until verification succeeds")
    _row, certificate = _certificate_or_404(job_id, output_id)
    verification = json.loads(output["verification_json"] or "{}")
    pdf_bytes = certificate_pdf(certificate, verification)
    increment_local_request()
    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{certificate["payload"]["certificate_id"]}.pdf"'},
    )


@router.get("/jobs/{job_id}/outputs/{output_id}/proof-bundle")
def proof_bundle(job_id: str, output_id: str) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Proof bundle unavailable until every mandatory proof gate passes")
    _row, certificate = _certificate_or_404(job_id, output_id)
    if not verify_certificate(certificate):
        raise HTTPException(status_code=500, detail="Stored proof certificate signature is invalid")
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
    except WorkspaceError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    verification = json.loads(output["verification_json"] or "{}")
    ledger = verify_ledger(job_id)
    if not ledger["valid"]:
        raise HTTPException(status_code=423, detail="Audit ledger integrity check failed; proof export blocked")
    pdf_bytes = certificate_pdf(certificate, verification)
    manifest = json.loads(output["manifest_json"] or "{}")
    graph = manifest.get("identity_exposure_graph", {})
    bundle = build_proof_bundle(
        protected=protected,
        protected_name=output["download_name"],
        certificate=certificate,
        certificate_pdf_bytes=pdf_bytes,
        audit_ledger=ledger,
        verification=verification,
        manifest=manifest,
        identity_exposure_graph=graph,
    )
    append_event(job_id, "PROOF_BUNDLE_EXPORTED", {
        "output_id": output_id,
        "certificate_id": certificate["payload"]["certificate_id"],
        "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
    })
    increment_local_request()
    return Response(
        bundle,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{certificate["payload"]["certificate_id"]}-proof-bundle.zip"'},
    )


@router.get("/jobs/{job_id}/outputs/{output_id}/proof-package")
def proof_package(job_id: str, output_id: str) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Proof package unavailable until every mandatory proof gate passes")
    _row, certificate = _certificate_or_404(job_id, output_id)
    if not verify_certificate(certificate):
        raise HTTPException(status_code=500, detail="Stored proof certificate signature is invalid")
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
    except WorkspaceError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    verification = json.loads(output["verification_json"] or "{}")
    manifest = json.loads(output["manifest_json"] or "{}")
    graph = manifest.get("identity_exposure_graph", {})
    certification_ledger = verify_ledger(job_id)
    if not certification_ledger["valid"]:
        raise HTTPException(status_code=423, detail="Audit ledger integrity check failed; proof export blocked")
    pdf_bytes = certificate_pdf(certificate, verification)
    bundle = build_proof_bundle(
        protected=protected,
        protected_name=output["download_name"],
        certificate=certificate,
        certificate_pdf_bytes=pdf_bytes,
        audit_ledger=certification_ledger,
        verification=verification,
        manifest=manifest,
        identity_exposure_graph=graph,
    )
    bundle_sha = hashlib.sha256(bundle).hexdigest()
    append_event(job_id, "PROOF_BUNDLE_EXPORTED", {
        "output_id": output_id,
        "certificate_id": certificate["payload"]["certificate_id"],
        "bundle_sha256": bundle_sha,
        "export_mode": "SIGNED_PROOF_PACKAGE",
    })
    export_ledger = verify_ledger(job_id)
    if not export_ledger["valid"]:
        raise HTTPException(status_code=423, detail="Audit ledger became invalid during proof export")
    receipt = issue_bundle_receipt(
        bundle_sha256=bundle_sha,
        bundle_size_bytes=len(bundle),
        certificate=certificate,
        audit_snapshot=export_ledger,
    )
    package = build_proof_package(
        proof_bundle=bundle,
        certificate=certificate,
        bundle_receipt=receipt,
        export_audit_ledger=export_ledger,
    )
    increment_local_request()
    return Response(
        package,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{certificate["payload"]["certificate_id"]}-complete-proof-package.zip"',
            "X-VeilGraph-Bundle-SHA256": bundle_sha,
            "X-VeilGraph-Receipt-ID": receipt["payload"]["receipt_id"],
        },
    )


@router.get("/jobs/{job_id}/outputs/{output_id}/annotated-export")
def annotated_output_export(job_id: str, output_id: str) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Annotated evidence is unavailable until every mandatory verification gate passes")
    _row, certificate = _certificate_or_404(job_id, output_id)
    if not verify_certificate(certificate):
        raise HTTPException(status_code=500, detail="Stored proof certificate signature is invalid")
    file_row = _file_or_404(job_id, output["file_id"])
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
    except WorkspaceError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    manifest = json.loads(output["manifest_json"] or "{}")
    annotation = manifest.get("annotation_evidence")
    if not isinstance(annotation, dict):
        raise HTTPException(status_code=500, detail="Output has no bound annotation evidence manifest")
    try:
        package = build_annotated_export(
            protected=protected,
            protected_name=output["download_name"],
            file_type=FileType(file_row["file_type"]),
            page_count=int(file_row.get("page_count", 0)),
            annotation=annotation,
            certificate=certificate,
        )
    except ValueError as exc:
        raise HTTPException(status_code=423, detail=f"Annotated export binding failed: {exc}") from exc
    append_event(job_id, "ANNOTATED_EVIDENCE_EXPORTED", {
        "output_id": output_id,
        "annotation_sha256": annotation.get("annotation_sha256", ""),
        "annotated_export_sha256": hashlib.sha256(package).hexdigest(),
        "source_plaintext_included": False,
    })
    increment_local_request()
    cert_id = certificate["payload"]["certificate_id"]
    return Response(
        package,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{cert_id}-annotated-evidence.zip"'},
    )


@router.get("/jobs/{job_id}/outputs/{output_id}/download")
def download_output(job_id: str, output_id: str) -> Response:
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Release blocked: output has not passed every mandatory verification test")
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
    except WorkspaceError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    append_event(job_id, "PROTECTED_ARTIFACT_DOWNLOADED", {
        "output_id": output_id,
        "output_sha256": output["sha256"],
        "download_name": output["download_name"],
    })
    increment_local_request()
    return Response(
        protected, media_type=output["media_type"],
        headers={"Content-Disposition": f'attachment; filename="{output["download_name"]}"'},
    )


def _synthetic_export_or_423(job_id: str, output_id: str, target_format: str):
    _job_or_404(job_id)
    output = _output_or_404(job_id, output_id)
    if output["status"] != OutputStatus.VERIFIED_SAFE.value:
        raise HTTPException(status_code=423, detail="Synthetic format export is unavailable until the Level 5 output is VERIFIED_SAFE")
    manifest = json.loads(output["manifest_json"] or "{}")
    if int(manifest.get("privacy_level", 0)) != int(PrivacyLevel.SYNTHETIC_TWIN) or not isinstance(manifest.get("synthetic_twin"), dict):
        raise HTTPException(status_code=422, detail="Synthetic format export requires a verified Level 5 Synthetic Twin output")
    target = str(target_format).strip().casefold().lstrip(".")
    if target not in SUPPORTED_SYNTHETIC_EXPORT_FORMATS:
        raise HTTPException(status_code=422, detail=f"Synthetic export format must be one of: {', '.join(SUPPORTED_SYNTHETIC_EXPORT_FORMATS)}")
    try:
        protected = get_workspace(job_id).read_encrypted(output["encrypted_name"])
        artifact = export_synthetic_representation(protected, output["download_name"], target)
    except (WorkspaceError, ValueError) as exc:
        raise HTTPException(status_code=410 if isinstance(exc, WorkspaceError) else 422, detail=str(exc)) from exc
    return output, manifest, artifact


def _synthetic_export_receipt(output: dict[str, Any], artifact) -> dict[str, Any]:
    payload = {
        "schema": "veilgraph.synthetic-format-export-receipt.v1",
        "product": "VeilGraph",
        "product_version": settings.version,
        "source_output_id": output["id"],
        "source_output_sha256": output["sha256"],
        "source_level": 5,
        "source_verification_status": output["status"],
        "target_format": artifact.report["target_format"],
        "export_sha256": artifact.report["export_sha256"],
        "export_size_bytes": artifact.report["export_size_bytes"],
        "record_count": artifact.report["record_count"],
        "field_count": artifact.report["field_count"],
        "semantic_boundary": artifact.report["semantic_boundary"],
        "signer": {
            "algorithm": "Ed25519",
            "public_key_b64": public_key_b64(),
            "public_key_sha256": signer_fingerprint(),
        },
    }
    return {
        "payload": payload,
        "signature_algorithm": "Ed25519",
        "signature_b64": sign_payload(payload),
    }


@router.get("/jobs/{job_id}/outputs/{output_id}/synthetic-export")
def synthetic_format_export(job_id: str, output_id: str, format: str = Query(..., min_length=3, max_length=5)) -> Response:
    output, _manifest, artifact = _synthetic_export_or_423(job_id, output_id, format)
    base = output["download_name"].rsplit(".", 1)[0]
    filename = f"{base}-synthetic-export{artifact.extension}"
    append_event(job_id, "SYNTHETIC_FORMAT_EXPORTED", {
        "output_id": output_id,
        "source_output_sha256": output["sha256"],
        "target_format": artifact.report["target_format"],
        "export_sha256": artifact.report["export_sha256"],
        "source_plaintext_included": False,
    })
    increment_local_request()
    return Response(
        artifact.data,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-VeilGraph-Synthetic-Source-SHA256": output["sha256"],
            "X-VeilGraph-Synthetic-Export-SHA256": artifact.report["export_sha256"],
        },
    )


@router.get("/jobs/{job_id}/outputs/{output_id}/synthetic-export-receipt")
def synthetic_format_export_receipt(job_id: str, output_id: str, format: str = Query(..., min_length=3, max_length=5)) -> dict[str, Any]:
    output, _manifest, artifact = _synthetic_export_or_423(job_id, output_id, format)
    receipt = _synthetic_export_receipt(output, artifact)
    append_event(job_id, "SYNTHETIC_FORMAT_RECEIPT_ISSUED", {
        "output_id": output_id,
        "target_format": artifact.report["target_format"],
        "export_sha256": artifact.report["export_sha256"],
        "signer_fingerprint": receipt["payload"]["signer"]["public_key_sha256"],
    })
    increment_local_request()
    return receipt


@router.delete("/jobs/{job_id}/destroy", response_model=DestructionResponse)
def destroy_job(job_id: str) -> DestructionResponse:
    job = db.fetchone("SELECT id FROM jobs WHERE id=?", (job_id,))
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        response = destroy_job_with_receipt(job_id, trigger="MANUAL")
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    increment_local_request()
    return DestructionResponse.model_validate(response)
