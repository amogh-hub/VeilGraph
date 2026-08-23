from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from app.core.enums import (
    AudienceProfile,
    EntityType,
    GraphEdgeType,
    GraphNodeKind,
    PrivacyLevel,
    ReviewStatus,
    SensitivityLevel,
)
from app.policy.compiler import (
    DIRECT_TYPES,
    QUASI_TYPES,
    VISUAL_TYPES,
    action_for,
    policy_descriptor,
    residual_factor,
    utility_loss,
)


_DIRECT_WEIGHTS = {
    EntityType.PERSON_NAME: 22,
    EntityType.PHONE: 18,
    EntityType.EMAIL: 18,
    EntityType.AADHAAR_LIKE: 26,
    EntityType.PAN_LIKE: 24,
    EntityType.CASE_REFERENCE: 17,
    EntityType.NATIONAL_ID: 26,
    EntityType.PASSPORT_NUMBER: 25,
    EntityType.DRIVER_LICENSE_NUMBER: 23,
    EntityType.TAX_IDENTIFIER: 24,
    EntityType.SOCIAL_IDENTIFIER: 25,
    EntityType.PAYMENT_CARD_NUMBER: 25,
}
_QUASI_WEIGHTS = {
    EntityType.DATE_OF_BIRTH: 17,
    EntityType.AGE: 8,
    EntityType.STREET_ADDRESS: 22,
    EntityType.LOCALITY: 11,
    EntityType.POSTCODE: 16,
    EntityType.EMPLOYER: 13,
    EntityType.JOB_TITLE: 10,
    EntityType.PERSON_TITLE: 4,
    EntityType.GENERIC_DATE: 8,
    EntityType.BUILDING_NUMBER: 9,
    EntityType.DEMOGRAPHIC_ATTRIBUTE: 7,
}
_VISUAL_WEIGHTS = {
    EntityType.FACE: 24,
    EntityType.QR_CODE: 20,
    EntityType.SIGNATURE_CANDIDATE: 18,
}
_RELATED_LABELS = ("mother", "father", "spouse", "guardian", "nominee", "witness", "emergency contact")


def _risk_band(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def _kind(entity_type: EntityType, related: bool = False) -> GraphNodeKind:
    if entity_type == EntityType.PERSON_NAME:
        return GraphNodeKind.RELATED_PERSON if related else GraphNodeKind.SUBJECT
    if entity_type in DIRECT_TYPES:
        return GraphNodeKind.DIRECT_IDENTIFIER
    if entity_type in QUASI_TYPES:
        return GraphNodeKind.QUASI_IDENTIFIER
    return GraphNodeKind.VISUAL_IDENTIFIER


def _review_state(mentions: list[dict[str, Any]]) -> str:
    statuses = {item["review_status"] for item in mentions}
    if ReviewStatus.PENDING.value in statuses:
        return "pending"
    if statuses == {ReviewStatus.IGNORE.value}:
        return "ignored"
    if ReviewStatus.PROTECT.value in statuses:
        return "reviewed-protect"
    return "automatic"


def _active_mentions(mentions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in mentions if item["review_status"] != ReviewStatus.IGNORE.value]


def _relationship_name(context: str) -> str:
    lowered = context.casefold()
    for name in ("mother", "father", "spouse", "guardian", "nominee", "witness", "emergency contact"):
        if name in lowered:
            return name.replace("emergency contact", "emergency contact person")
    return "related person"


def _component_scores(
    active_entities: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    level: PrivacyLevel,
    audience: AudienceProfile,
    after: bool,
) -> tuple[int, int, int, int]:
    direct_raw = 0.0
    quasi_raw = 0.0
    relationship_raw = 0.0
    types = {EntityType(row["entity_type"]) for row, _ in active_entities}
    related_people = 0

    for row, mentions in active_entities:
        entity_type = EntityType(row["entity_type"])
        factor = residual_factor(action_for(entity_type, level, audience)) if after else 1.0
        if entity_type in _DIRECT_WEIGHTS:
            direct_raw += _DIRECT_WEIGHTS[entity_type] * factor
        elif entity_type in _QUASI_WEIGHTS:
            quasi_raw += _QUASI_WEIGHTS[entity_type] * factor
        elif entity_type in _VISUAL_WEIGHTS:
            direct_raw += _VISUAL_WEIGHTS[entity_type] * factor
        if entity_type == EntityType.PERSON_NAME:
            contexts = " ".join(str(item.get("context_label") or "") for item in mentions)
            if any(label in contexts.casefold() for label in _RELATED_LABELS):
                related_people += 1

    relation_factor = 1.0
    if after:
        person_action = action_for(EntityType.PERSON_NAME, level, audience)
        relation_factor = 0.04 if person_action == "SYNTHESIZE" else 0.12 if person_action == "PSEUDONYMIZE" else 0.16 if person_action == "PROTECT" else 0.18 if person_action == "MASK" else 1.0
    relationship_raw = related_people * 14 * relation_factor

    combos: list[tuple[set[EntityType], int]] = [
        ({EntityType.DATE_OF_BIRTH, EntityType.POSTCODE, EntityType.EMPLOYER}, 26),
        ({EntityType.AGE, EntityType.LOCALITY, EntityType.JOB_TITLE}, 18),
        ({EntityType.PERSON_NAME, EntityType.CASE_REFERENCE}, 16),
        ({EntityType.STREET_ADDRESS, EntityType.EMPLOYER}, 16),
    ]
    combo_raw = 0.0
    for required, weight in combos:
        if required.issubset(types):
            if after:
                factors = [residual_factor(action_for(item, level, audience)) for item in required]
                combo_raw += weight * max(factors)
            else:
                combo_raw += weight

    direct = min(50, round(direct_raw * 0.60))
    quasi = min(34, round(quasi_raw * 0.55))
    relationship = min(14, round(relationship_raw))
    combination = min(28, round(combo_raw * 0.70))
    return direct, quasi, relationship, combination


def build_exposure_graph(
    job: dict[str, Any],
    file_row: dict[str, Any],
    entities: list[dict[str, Any]],
    mentions_by_entity: dict[str, list[dict[str, Any]]],
    level: PrivacyLevel,
) -> dict[str, Any]:
    audience = AudienceProfile(job["audience_profile"])
    is_dataset = str(file_row.get("file_type", "")) == "DATASET"
    active_entities = [
        (row, _active_mentions(mentions_by_entity.get(row["id"], [])))
        for row in entities
    ]
    active_entities = [(row, mentions) for row, mentions in active_entities if mentions]
    present_types = {EntityType(row["entity_type"]) for row, _ in active_entities}

    nodes: list[dict[str, Any]] = [{
        "id": f"document:{file_row['id']}",
        "kind": GraphNodeKind.DOCUMENT.value,
        "label": file_row["original_filename"],
        "entity_id": None,
        "entity_type": None,
        "sensitivity": None,
        "mention_count": sum(len(items) for _, items in active_entities),
        "review_state": "source",
        "page_indexes": list(range(int(file_row.get("page_count", 0)))),
    }]
    edges: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []

    person_rows = [(row, mentions) for row, mentions in active_entities if EntityType(row["entity_type"]) == EntityType.PERSON_NAME]
    primary: tuple[dict[str, Any], list[dict[str, Any]]] | None = None
    related: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    if not is_dataset:
        for item in person_rows:
            contexts = " ".join(str(mention.get("context_label") or "") for mention in item[1]).casefold()
            if any(label in contexts for label in _RELATED_LABELS):
                related.append(item)
            elif primary is None:
                primary = item
            else:
                related.append(item)

    subject_id = "subject:dataset-records" if is_dataset else (f"entity:{primary[0]['id']}" if primary else "subject:reconstructable")
    if is_dataset or primary is None:
        nodes.append({
            "id": subject_id,
            "kind": GraphNodeKind.SUBJECT.value,
            "label": "Dataset record population" if is_dataset else "Reconstructable subject",
            "entity_id": None,
            "entity_type": None,
            "sensitivity": SensitivityLevel.HIGH.value,
            "mention_count": 0,
            "review_state": "inferred",
            "page_indexes": [],
        })
    document_id = f"document:{file_row['id']}"
    edges.append({
        "id": "edge:document-subject",
        "source": document_id,
        "target": subject_id,
        "edge_type": GraphEdgeType.CONTAINS.value,
        "weight": 10,
        "explanation": "The dataset contains reconstructable records." if is_dataset else "The document describes one reconstructable subject.",
    })

    for row, mentions in active_entities:
        entity_type = EntityType(row["entity_type"])
        contexts = sorted({str(item.get("context_label") or "").strip() for item in mentions if item.get("context_label")})
        context_text = contexts[0] if contexts else ""
        is_related = (not is_dataset) and entity_type == EntityType.PERSON_NAME and (primary is None or row["id"] != primary[0]["id"])
        node_id = f"entity:{row['id']}"
        node_kind = GraphNodeKind.DIRECT_IDENTIFIER if is_dataset and entity_type == EntityType.PERSON_NAME else _kind(entity_type, related=is_related)
        nodes.append({
            "id": node_id,
            "kind": node_kind.value,
            "label": f"{row['placeholder']}{' · ' + context_text if context_text else ''}",
            "entity_id": row["id"],
            "entity_type": entity_type.value,
            "sensitivity": row["sensitivity"],
            "mention_count": len(mentions),
            "review_state": _review_state(mentions),
            "page_indexes": sorted({int(item["page_index"]) for item in mentions}),
        })
        if node_id != subject_id:
            edges.append({
                "id": f"edge:document:{row['id']}",
                "source": document_id,
                "target": node_id,
                "edge_type": GraphEdgeType.CONTAINS.value,
                "weight": 4,
                "explanation": "The entity is present in the source document.",
            })
            if entity_type == EntityType.PERSON_NAME and is_related:
                relation = _relationship_name(context_text)
                edges.append({
                    "id": f"edge:relationship:{row['id']}",
                    "source": subject_id,
                    "target": node_id,
                    "edge_type": GraphEdgeType.RELATED_TO.value,
                    "weight": 14,
                    "explanation": f"The document links the subject to a {relation}.",
                })
                paths.append({
                    "node_ids": [subject_id, node_id],
                    "score": 14,
                    "reason": f"A named {relation} can expose the subject through relationship lookup.",
                })
            else:
                edge_type = GraphEdgeType.IDENTIFIES if entity_type in DIRECT_TYPES or entity_type in VISUAL_TYPES else GraphEdgeType.DESCRIBES
                weight = _DIRECT_WEIGHTS.get(entity_type, _VISUAL_WEIGHTS.get(entity_type, _QUASI_WEIGHTS.get(entity_type, 8)))
                edges.append({
                    "id": f"edge:subject:{row['id']}",
                    "source": subject_id,
                    "target": node_id,
                    "edge_type": edge_type.value,
                    "weight": min(26, weight),
                    "explanation": (
                        "This clue directly identifies or contacts the subject."
                        if edge_type == GraphEdgeType.IDENTIFIES
                        else "This clue narrows the population in which the subject can be reconstructed."
                    ),
                })
                if weight >= 17:
                    paths.append({
                        "node_ids": [subject_id, node_id],
                        "score": min(26, weight),
                        "reason": f"{entity_type.value.replace('_', ' ').title()} is a high-impact identity clue.",
                    })

    type_to_node: dict[EntityType, str] = {}
    for node in nodes:
        if node.get("entity_type"):
            type_to_node.setdefault(EntityType(node["entity_type"]), node["id"])
    combination_specs = [
        ((EntityType.DATE_OF_BIRTH, EntityType.POSTCODE, EntityType.EMPLOYER), 26, "Birth date, postcode and employer form a high-uniqueness combination."),
        ((EntityType.AGE, EntityType.LOCALITY, EntityType.JOB_TITLE), 18, "Age, locality and job title can reconstruct a person without a direct identifier."),
        ((EntityType.STREET_ADDRESS, EntityType.EMPLOYER), 16, "Exact address plus employer sharply narrows identity."),
    ]
    page_types: dict[int, set[EntityType]] = defaultdict(set)
    if is_dataset:
        for entity_row, entity_mentions in active_entities:
            entity_type = EntityType(entity_row["entity_type"])
            for mention in entity_mentions:
                page_types[int(mention["page_index"])].add(entity_type)

    for required, score, reason in combination_specs:
        globally_present = all(item in type_to_node for item in required)
        record_level_present = (
            any(set(required).issubset(types) for types in page_types.values())
            if is_dataset else globally_present
        )
        if globally_present and record_level_present:
            dataset_reason = (
                "Same-record cross-column linkage: " + reason
                if is_dataset else reason
            )
            node_ids = [subject_id] + [type_to_node[item] for item in required]
            paths.append({"node_ids": node_ids, "score": score, "reason": dataset_reason})
            for left, right in zip(required, required[1:]):
                edges.append({
                    "id": f"edge:co:{left.value}:{right.value}",
                    "source": type_to_node[left],
                    "target": type_to_node[right],
                    "edge_type": GraphEdgeType.CO_OCCURS_WITH.value,
                    "weight": score,
                    "explanation": dataset_reason,
                })

    before_parts = _component_scores(active_entities, level, audience, after=False)
    after_parts = _component_scores(active_entities, level, audience, after=True)
    before = min(100, sum(before_parts))
    after = min(100, sum(after_parts))
    total_loss = sum(
        utility_loss(action_for(EntityType(row["entity_type"]), level, audience), EntityType(row["entity_type"]))
        for row, _ in active_entities
    )
    utility = max(45, 100 - min(55, total_loss))
    risk = {
        "before": before,
        "after": after,
        "reduction": max(0, before - after),
        "utility_score": utility,
        "band_before": _risk_band(before),
        "band_after": _risk_band(after),
        "breakdown_before": {
            "direct": before_parts[0], "quasi_identifier": before_parts[1],
            "relationship": before_parts[2], "combination_bonus": before_parts[3],
        },
        "breakdown_after": {
            "direct": after_parts[0], "quasi_identifier": after_parts[1],
            "relationship": after_parts[2], "combination_bonus": after_parts[3],
        },
        "disclaimer": "VeilGraph Residual Exposure Score is a calibrated product risk indicator, not a legal guarantee of anonymity.",
    }
    payload: dict[str, Any] = {
        "job_id": job["id"],
        "file_id": file_row["id"],
        "graph_version": "ieg-0.3",
        "policy": policy_descriptor(audience, level, present_types),
        "nodes": nodes,
        "edges": edges,
        "high_risk_paths": sorted(paths, key=lambda item: item["score"], reverse=True)[:8],
        "risk": risk,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["graph_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload
