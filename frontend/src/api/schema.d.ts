// Generated from backend/openapi.json. Do not edit manually.
export interface components {
  schemas: {
    "AnalysisResponse": {
      "job_id": string
      "file_id": string
      "file_type": components['schemas']['FileType']
      "page_count": number
      "scanned_pages": number
      "canonical_entities": number
      "mentions": number
      "direct_identifier_mentions": number
      "quasi_identifier_mentions": number
      "visual_mentions": number
      "pending_reviews": number
      "privacy_ir_schema": string
      "privacy_ir_units": number
      "privacy_ir_commitment_sha256": string
      "structured_format"?: string | null
      "structured_records"?: number
      "structured_fields"?: number
      "structured_sheets"?: number
      "structured_cells"?: number
      "structured_schema_sha256"?: string | null
      "docx_text_parts"?: number
      "docx_media_images"?: number
      "docx_units"?: Array<components['schemas']['DocxEvidenceUnitResponse']>
      "video_duration_seconds"?: number
      "video_fps"?: number
      "video_width"?: number
      "video_height"?: number
      "video_total_frames"?: number
      "video_sampled_frames"?: number
      "video_security_frames_analyzed"?: number
      "video_security_detection_frames"?: number
      "video_novel_security_frames"?: number
      "video_security_coverage_percent"?: number
      "video_security_policy"?: string | null
      "video_has_audio"?: boolean
      "video_audio_policy"?: string | null
      "video_units"?: Array<components['schemas']['VideoEvidenceUnitResponse']>
      "status": components['schemas']['JobStatus']
    }
    "AudienceProfile": "PUBLIC_RELEASE" | "RESEARCH_PARTNER" | "INTERNAL_OPERATIONS"
    "AuditEventResponse": {
      "sequence": number
      "event_type": string
      "timestamp": string
      "details": Record<string, unknown>
      "prev_hash": string
      "event_hash": string
    }
    "AuditLedgerResponse": {
      "job_id": string
      "valid": boolean
      "event_count": number
      "chain_head": string
      "error"?: string | null
      "events": Array<components['schemas']['AuditEventResponse']>
    }
    "Body_upload_file_api_v1_jobs__job_id__files_post": {
      "file": string
    }
    "CanonicalEntityResponse": {
      "id": string
      "job_id": string
      "file_id": string
      "entity_type": components['schemas']['EntityType']
      "fingerprint": string
      "placeholder": string
      "sensitivity": components['schemas']['SensitivityLevel']
      "transformation": components['schemas']['TransformationType']
      "mention_count": number
    }
    "CertificatePayloadResponse": {
      "schema": string
      "certificate_id": string
      "product": string
      "product_version": string
      "issued_at": string
      "verified_at": string
      "job_commitment_sha256": string
      "output_sha256": string
      "input_sha256": string
      "manifest_sha256": string
      "graph_sha256": string
      "verification_sha256": string
      "privacy_level": number
      "audience_profile": string
      "proof_score": number
      "attack_coverage": number
      "critical_failures": number
      "release_decision": string
      "risk_before": number
      "residual_risk": number
      "utility_score": number
      "audit_head_at_certification": string
      "audit_events_at_certification": number
      "signer": components['schemas']['SignerResponse']
      "disclaimer": string
    }
    "CertificateResponse": {
      "payload": components['schemas']['CertificatePayloadResponse']
      "signature_algorithm": string
      "signature_b64": string
      "signature_valid": boolean
    }
    "DestructionReceiptPayloadResponse": {
      "schema": string
      "product": string
      "product_version": string
      "issued_at": string
      "job_commitment_sha256": string
      "trigger": string
      "audit_integrity_valid": boolean
      "retention_deadline": string
      "final_audit_head": string
      "final_audit_event_count": number
      "deleted_workspace_files": number
      "cleared_plaintext_entities": number
      "destroyed_outputs": number
      "deleted_database_rows": Record<string, number>
      "signer": components['schemas']['SignerResponse']
      "scope_note": string
    }
    "DestructionReceiptResponse": {
      "payload": components['schemas']['DestructionReceiptPayloadResponse']
      "signature_algorithm": string
      "signature_b64": string
      "signature_valid": boolean
    }
    "DestructionResponse": {
      "job_id": string
      "status": components['schemas']['JobStatus']
      "trigger": string
      "deleted_workspace_files": number
      "cleared_plaintext_entities": number
      "destroyed_outputs": number
      "deleted_database_rows": Record<string, number>
      "note": string
      "destruction_receipt": components['schemas']['DestructionReceiptResponse']
    }
    "DetectionSource": "TEXT_LAYER" | "OCR" | "VISUAL"
    "DocxEvidenceUnitResponse": {
      "page_index": number
      "kind": string
      "part_name": string
      "label": string
    }
    "EntityMentionResponse": {
      "id": string
      "canonical_entity_id": string
      "page_index": number
      "page_char_start": number
      "page_char_end": number
      "x0": number
      "y0": number
      "x1": number
      "y1": number
      "confidence": number
      "source": components['schemas']['DetectionSource']
      "review_status": components['schemas']['ReviewStatus']
      "context_label"?: string | null
    }
    "EntityType": "PHONE" | "EMAIL" | "AADHAAR_LIKE" | "PAN_LIKE" | "PERSON_NAME" | "PERSON_TITLE" | "DATE_OF_BIRTH" | "GENERIC_DATE" | "AGE" | "STREET_ADDRESS" | "BUILDING_NUMBER" | "LOCALITY" | "POSTCODE" | "EMPLOYER" | "JOB_TITLE" | "CASE_REFERENCE" | "NATIONAL_ID" | "PASSPORT_NUMBER" | "DRIVER_LICENSE_NUMBER" | "TAX_IDENTIFIER" | "SOCIAL_IDENTIFIER" | "PAYMENT_CARD_NUMBER" | "DEMOGRAPHIC_ATTRIBUTE" | "FACE" | "QR_CODE" | "SIGNATURE_CANDIDATE"
    "EntityWithMentions": {
      "entity": components['schemas']['CanonicalEntityResponse']
      "mentions": Array<components['schemas']['EntityMentionResponse']>
    }
    "ExposureGraphResponse": {
      "job_id": string
      "file_id": string
      "graph_version": string
      "graph_sha256": string
      "policy": components['schemas']['PolicyResponse']
      "nodes": Array<components['schemas']['GraphNodeResponse']>
      "edges": Array<components['schemas']['GraphEdgeResponse']>
      "high_risk_paths": Array<components['schemas']['RiskPathResponse']>
      "risk": components['schemas']['RiskSummaryResponse']
    }
    "FileResponse": {
      "id": string
      "job_id": string
      "original_filename": string
      "file_type": components['schemas']['FileType']
      "media_type": string
      "sha256": string
      "page_count": number
      "status": string
      "created_at": string
    }
    "FileType": "PDF" | "IMAGE" | "TEXT" | "DATASET" | "DOCX" | "VIDEO"
    "GraphEdgeResponse": {
      "id": string
      "source": string
      "target": string
      "edge_type": components['schemas']['GraphEdgeType']
      "weight": number
      "explanation": string
    }
    "GraphEdgeType": "CONTAINS" | "IDENTIFIES" | "DESCRIBES" | "RELATED_TO" | "CO_OCCURS_WITH"
    "GraphNodeKind": "DOCUMENT" | "SUBJECT" | "RELATED_PERSON" | "DIRECT_IDENTIFIER" | "QUASI_IDENTIFIER" | "VISUAL_IDENTIFIER"
    "GraphNodeResponse": {
      "id": string
      "kind": components['schemas']['GraphNodeKind']
      "label": string
      "entity_id"?: string | null
      "entity_type"?: components['schemas']['EntityType'] | null
      "sensitivity"?: components['schemas']['SensitivityLevel'] | null
      "mention_count"?: number
      "review_state"?: string
      "page_indexes"?: Array<number>
    }
    "HTTPValidationError": {
      "detail"?: Array<components['schemas']['ValidationError']>
    }
    "JobCreate": {
      "purpose": string
      "recipient": string
      "audience_profile"?: components['schemas']['AudienceProfile']
      "privacy_level"?: components['schemas']['PrivacyLevel']
      "retention_seconds"?: number
    }
    "JobResponse": {
      "id": string
      "purpose": string
      "recipient": string
      "audience_profile": components['schemas']['AudienceProfile']
      "privacy_level": components['schemas']['PrivacyLevel']
      "retention_seconds": number
      "expires_at": string
      "status": components['schemas']['JobStatus']
      "created_at": string
      "updated_at": string
    }
    "JobStatus": "CREATED" | "UPLOADED" | "ANALYSED" | "HUMAN_REVIEW_REQUIRED" | "TRANSFORMED" | "VERIFIED" | "BLOCKED" | "DESTROYED" | "FAILED"
    "OfflineStatusResponse": {
      "offline_mode": boolean
      "backend_address": string
      "processing_location": string
      "external_model_calls": string
      "automatic_retention": boolean
      "retention_sweep_seconds": number
      "restart_key_loss_policy": string
      "bundled_components": Array<string>
      "non_local_inbound_requests": number
      "local_api_requests": number
      "device_signer_fingerprint": string
      "certificate_algorithm": string
      "statement": string
    }
    "OutputStatus": "CREATED" | "VERIFIED_SAFE" | "RELEASE_BLOCKED" | "DESTROYED"
    "PolicyResponse": {
      "audience_profile": components['schemas']['AudienceProfile']
      "privacy_level": components['schemas']['PrivacyLevel']
      "name": string
      "objective": string
      "rules": Array<components['schemas']['PolicyRuleResponse']>
    }
    "PolicyRuleResponse": {
      "entity_type": components['schemas']['EntityType']
      "action": "MASK" | "PROTECT" | "REMOVE" | "GENERALIZE" | "PSEUDONYMIZE" | "SYNTHESIZE" | "RETAIN"
      "replacement_preview": string
      "rationale": string
    }
    "PrivacyLevel": 1 | 2 | 3 | 4 | 5
    "PrivacyLevelPreviewResponse": {
      "privacy_level": components['schemas']['PrivacyLevel']
      "supported": boolean
      "risk_before": number
      "residual_risk": number
      "utility_score": number
      "label": string
      "limitation"?: string | null
    }
    "PrivacyRecommendationResponse": {
      "recommended_level": components['schemas']['PrivacyLevel']
      "minimum_level": components['schemas']['PrivacyLevel']
      "policy_floor_enforced": boolean
      "override_allowed": boolean
      "reasons": Array<string>
      "previews": Array<components['schemas']['PrivacyLevelPreviewResponse']>
      "methodology": string
      "disclaimer": string
    }
    "ReviewRequest": {
      "action": components['schemas']['ReviewStatus']
    }
    "ReviewResponse": {
      "mention_id": string
      "review_status": components['schemas']['ReviewStatus']
      "pending_reviews": number
      "job_status": components['schemas']['JobStatus']
    }
    "ReviewStatus": "NOT_REQUIRED" | "PENDING" | "PROTECT" | "IGNORE"
    "RiskBreakdownResponse": {
      "direct": number
      "quasi_identifier": number
      "relationship": number
      "combination_bonus": number
    }
    "RiskPathResponse": {
      "node_ids": Array<string>
      "score": number
      "reason": string
    }
    "RiskSummaryResponse": {
      "before": number
      "after": number
      "reduction": number
      "utility_score": number
      "band_before": string
      "band_after": string
      "breakdown_before": components['schemas']['RiskBreakdownResponse']
      "breakdown_after": components['schemas']['RiskBreakdownResponse']
      "disclaimer": string
    }
    "SensitivityLevel": "high" | "medium" | "low"
    "SignerResponse": {
      "algorithm": string
      "public_key_b64": string
      "public_key_sha256": string
    }
    "TestStatus": "PASS" | "FAIL" | "INCONCLUSIVE"
    "TransformRequest": {
      "privacy_level"?: components['schemas']['PrivacyLevel']
    }
    "TransformResponse": {
      "output_id": string
      "job_id": string
      "file_id": string
      "privacy_level": components['schemas']['PrivacyLevel']
      "transformations_applied": number
      "output_media_type": string
      "download_name": string
      "risk_before": number
      "residual_risk": number
      "utility_score": number
      "status": components['schemas']['OutputStatus']
      "synthetic_twin"?: Record<string, unknown> | null
    }
    "TransformationType": "MASK" | "REMOVE_REGION" | "GENERALIZE" | "PSEUDONYMIZE" | "SYNTHESIZE"
    "ValidationError": {
      "loc": Array<string | number>
      "msg": string
      "type": string
      "input"?: unknown
      "ctx"?: Record<string, unknown>
    }
    "VerificationResponse": {
      "output_id": string
      "status": components['schemas']['OutputStatus']
      "tests": Array<components['schemas']['VerificationTestResult']>
      "passed": number
      "failed": number
      "inconclusive": number
      "proof_score": number
      "attack_coverage": number
      "critical_failures": number
      "risk_before": number
      "residual_risk": number
      "utility_score": number
      "release_decision": "ALLOW_RELEASE" | "BLOCK_RELEASE"
      "verified_at": string
      "synthetic_twin"?: Record<string, unknown> | null
    }
    "VerificationTestResult": {
      "name": string
      "status": components['schemas']['TestStatus']
      "detail": string
      "attack_class": string
      "severity": "critical" | "high" | "medium"
    }
    "VideoEvidenceUnitResponse": {
      "page_index": number
      "frame_index": number
      "timestamp_seconds": number
      "label": string
      "is_evidence"?: boolean
      "security_scanned"?: boolean
      "full_ocr_selected"?: boolean
      "security_promoted"?: boolean
    }
  }
}
