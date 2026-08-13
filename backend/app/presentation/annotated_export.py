from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections import defaultdict
from typing import Any

from app.core.enums import AudienceProfile, FileType, PrivacyLevel
from app.policy.compiler import action_for
from app.presentation.preview import annotated_protected_preview
from app.security.signing import canonical_json_bytes
from app.transformation.sanitizer import ProtectionInstruction

ANNOTATION_SCHEMA = "veilgraph.annotation-evidence.v1"
ANNOTATED_EXPORT_SCHEMA = "veilgraph.annotated-export.v1"
MAX_RENDERED_PREVIEWS = 50


def build_annotation_evidence(
    *,
    rows: list[dict[str, Any]],
    instructions: list[ProtectionInstruction],
    privacy_level: PrivacyLevel,
    audience: AudienceProfile,
    output_sha256: str,
) -> dict[str, Any]:
    row_by_mention = {str(row["id"]): row for row in rows}
    entries: list[dict[str, Any]] = []
    for instruction in instructions:
        row = row_by_mention.get(instruction.mention_id, {})
        entry = {
            "mention_id": instruction.mention_id,
            "entity_id": instruction.entity_id,
            "placeholder": str(row.get("placeholder", instruction.entity_type.value)),
            "entity_type": instruction.entity_type.value,
            "page_index": int(instruction.page_index),
            "rect": [float(value) for value in instruction.rect],
            "confidence": round(float(row.get("confidence", 1.0)), 6),
            "source": str(row.get("source", "UNKNOWN")),
            "review_status": str(row.get("review_status", "NOT_REQUIRED")),
            "context_label": row.get("context_label"),
            "action": action_for(instruction.entity_type, privacy_level, audience),
            # Replacement is protected output data, not source plaintext. It is
            # useful to analysts when reviewing why a release changed.
            "replacement_preview": instruction.replacement,
            "replacement_sha256": hashlib.sha256(instruction.replacement.encode("utf-8")).hexdigest(),
        }
        entries.append(entry)

    payload = {
        "schema": ANNOTATION_SCHEMA,
        "privacy_level": int(privacy_level),
        "audience_profile": audience.value,
        "protected_output_sha256": output_sha256,
        "entry_count": len(entries),
        "entries": sorted(entries, key=lambda item: (item["page_index"], item["placeholder"], item["mention_id"])),
        "source_plaintext_included": False,
        "note": (
            "Annotations describe the transformation applied to the protected artifact. "
            "The clean release artifact remains separate and unchanged."
        ),
    }
    payload["annotation_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def verify_annotation_evidence(annotation: dict[str, Any], output_sha256: str) -> tuple[bool, str]:
    if annotation.get("schema") != ANNOTATION_SCHEMA:
        return False, "Annotation evidence schema is missing or unsupported"
    if annotation.get("protected_output_sha256") != output_sha256:
        return False, "Annotation evidence is not bound to this protected output"
    claimed = annotation.get("annotation_sha256")
    if not isinstance(claimed, str) or len(claimed) != 64:
        return False, "Annotation evidence SHA-256 is missing"
    payload = dict(annotation)
    payload.pop("annotation_sha256", None)
    actual = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    if actual != claimed:
        return False, "Annotation evidence SHA-256 is invalid"
    if int(annotation.get("entry_count", -1)) != len(annotation.get("entries", [])):
        return False, "Annotation evidence entry count does not match"
    return True, "Annotation evidence is output-bound and internally consistent"


def build_annotated_export(
    *,
    protected: bytes,
    protected_name: str,
    file_type: FileType,
    page_count: int,
    annotation: dict[str, Any],
    certificate: dict[str, Any],
) -> bytes:
    ok, detail = verify_annotation_evidence(annotation, hashlib.sha256(protected).hexdigest())
    if not ok:
        raise ValueError(detail)

    by_page: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for entry in annotation.get("entries", []):
        by_page[int(entry["page_index"])].append(entry)

    # For ordinary document/data formats, page_index addresses the logical
    # preview unit and therefore must remain bounded by page_count.
    #
    # Video is intentionally different: annotation entries are committed
    # against *physical frame indexes*. The representative evidence page_count
    # can be smaller than the physical timeline (for example, 4 representative
    # units for an 8-frame QR fixture). Bounding video annotations by page_count
    # silently drops valid later-frame evidence such as physical frames 6 and 7.
    #
    # Keep every non-negative committed physical-frame index for VIDEO and let
    # annotated_protected_preview()/physical_frame() fail closed if a manifest
    # ever contains an actually invalid frame index.
    if file_type == FileType.VIDEO:
        preview_pages = sorted(page for page in by_page if page >= 0)
        preview_unit_label = "modified physical-frame units"
    else:
        preview_pages = sorted(page for page in by_page if 0 <= page < page_count)
        preview_unit_label = "modified page/record units"

    rendered_pages = preview_pages[:MAX_RENDERED_PREVIEWS]
    entries: dict[str, bytes] = {
        protected_name: protected,
        "veilgraph-annotation-manifest.json": json.dumps(annotation, indent=2, sort_keys=True).encode("utf-8"),
        "veilgraph-certificate.json": json.dumps(certificate, indent=2, sort_keys=True).encode("utf-8"),
        "README.txt": (
            "VeilGraph annotated protected-output export\n\n"
            "The protected artifact in this ZIP is the exact clean release artifact.\n"
            "PNG files under annotated-previews/ are derived analyst/judge views and are not replacements for the clean artifact.\n"
            "Labels show entity placeholder, transformation action and detector confidence; source plaintext is never written to the annotation manifest.\n"
            f"Rendered annotated previews: {len(rendered_pages)} of {len(preview_pages)} {preview_unit_label}.\n"
            f"Preview cap: {MAX_RENDERED_PREVIEWS}. The JSON manifest always contains every transformation.\n"
        ).encode("utf-8"),
    }
    for page in rendered_pages:
        entries[f"annotated-previews/unit-{page + 1:04d}.png"] = annotated_protected_preview(
            protected, file_type, page, by_page[page]
        )

    index_payload = {
        "schema": ANNOTATED_EXPORT_SCHEMA,
        "protected_output_sha256": hashlib.sha256(protected).hexdigest(),
        "annotation_sha256": annotation["annotation_sha256"],
        "certificate_id": certificate.get("payload", {}).get("certificate_id"),
        "entries": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(entries.items())},
    }
    entries["veilgraph-annotated-export-index.json"] = json.dumps(index_payload, indent=2, sort_keys=True).encode("utf-8")

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return out.getvalue()
