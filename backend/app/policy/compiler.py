from __future__ import annotations

import re
from datetime import datetime
from string import ascii_uppercase

from app.core.enums import AudienceProfile, EntityType, PrivacyLevel
from app.detection.direct_identifiers import replacement_for


DIRECT_TYPES = {
    EntityType.PHONE,
    EntityType.EMAIL,
    EntityType.AADHAAR_LIKE,
    EntityType.PAN_LIKE,
    EntityType.PERSON_NAME,
    EntityType.CASE_REFERENCE,
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
}
QUASI_TYPES = {
    EntityType.DATE_OF_BIRTH,
    EntityType.AGE,
    EntityType.STREET_ADDRESS,
    EntityType.LOCALITY,
    EntityType.POSTCODE,
    EntityType.EMPLOYER,
    EntityType.JOB_TITLE,
    EntityType.PERSON_TITLE,
    EntityType.GENERIC_DATE,
    EntityType.BUILDING_NUMBER,
    EntityType.DEMOGRAPHIC_ATTRIBUTE,
}
VISUAL_TYPES = {EntityType.FACE, EntityType.QR_CODE, EntityType.SIGNATURE_CANDIDATE}

# Level 2 deliberately sits between direct masking and context generalisation.
# It replaces high-impact sensitive entities with opaque, stable tokens while
# leaving lower-risk contextual clues available for later gradational levels.
LEVEL2_PROTECT_TYPES = DIRECT_TYPES | {
    EntityType.DATE_OF_BIRTH,
    EntityType.STREET_ADDRESS,
    EntityType.POSTCODE,
    EntityType.BUILDING_NUMBER,
    EntityType.GENERIC_DATE,
    EntityType.DEMOGRAPHIC_ATTRIBUTE,
}


def _letter(index: int) -> str:
    if index < len(ascii_uppercase):
        return ascii_uppercase[index]
    return f"{ascii_uppercase[index % 26]}{index // 26 + 1}"


def _parse_year(value: str) -> int | None:
    cleaned = re.sub(r"\s+", " ", value.strip().replace(",", ""))
    for fmt in ("%d %B %Y", "%d %b %Y", "%B %d %Y", "%b %d %Y", "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(cleaned, fmt).year
        except ValueError:
            continue
    match = re.search(r"\b(19\d{2}|20\d{2})\b", cleaned)
    return int(match.group(1)) if match else None


def _generalize_date(value: str) -> str:
    year = _parse_year(value)
    if year is None:
        return "Birth year band protected"
    start = year - (year % 5)
    return f"Born {start}-{start + 4}"


def _generalize_age(value: str) -> str:
    match = re.search(r"\d{1,3}", value)
    if not match:
        return "Age band protected"
    age = int(match.group())
    bands = ((0, 12), (13, 17), (18, 24), (25, 34), (35, 44), (45, 54), (55, 64))
    for low, high in bands:
        if low <= age <= high:
            return f"Age {low}-{high}"
    return "Age 65+"


def _generalize_location(value: str) -> str:
    lowered = value.casefold()
    if "bengaluru" in lowered or "bangalore" in lowered:
        return "Bengaluru metropolitan area"
    if "mumbai" in lowered:
        return "Mumbai metropolitan area"
    if "delhi" in lowered:
        return "Delhi metropolitan area"
    # Never construct a generalized value by appending text to the exact source
    # clue (for example "Waldorf" -> "Waldorf area"), because the original
    # remains trivially recoverable. Preserve only coarse semantic utility.
    if re.search(r"\b(?:street|st\.?|avenue|ave\.?|road|rd\.?|lane|ln\.?|boulevard|blvd\.?|drive|dr\.?|way|court|ct\.?)\b", lowered):
        return "Urban street area"
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) >= 2:
        return "Regional urban area"
    return "City-level location"


def _generalize_employer(value: str) -> str:
    lowered = value.casefold()
    if any(word in lowered for word in ("analytics", "data", "software", "tech")):
        return "Private analytics organisation"
    if any(word in lowered for word in ("hospital", "clinic", "health")):
        return "Healthcare organisation"
    if any(word in lowered for word in ("college", "university", "school")):
        return "Education institution"
    if any(word in lowered for word in ("government", "ministry", "department")):
        return "Public-sector organisation"
    return "Private-sector organisation"


def _generalize_job(value: str) -> str:
    lowered = value.casefold()
    if any(word in lowered for word in ("junior", "trainee", "intern", "associate")):
        return "Early-career professional"
    if any(word in lowered for word in ("analyst", "data", "research")):
        return "Data and research professional"
    if any(word in lowered for word in ("engineer", "developer", "architect")):
        return "Technical professional"
    if any(word in lowered for word in ("manager", "lead", "director")):
        return "Management professional"
    return "Professional role"


def action_for(entity_type: EntityType, level: PrivacyLevel, audience: AudienceProfile) -> str:
    if level == PrivacyLevel.SYNTHETIC_TWIN:
        return "REMOVE" if entity_type in VISUAL_TYPES else "SYNTHESIZE"
    if entity_type in VISUAL_TYPES:
        return "REMOVE"
    if level == PrivacyLevel.DIRECT_MASKING:
        return "MASK" if entity_type in DIRECT_TYPES else "RETAIN"
    if level == PrivacyLevel.SENSITIVE_ENTITY_PROTECTION:
        return "PROTECT" if entity_type in LEVEL2_PROTECT_TYPES else "RETAIN"
    if level == PrivacyLevel.CONTEXT_GENERALIZATION:
        if entity_type in DIRECT_TYPES:
            return "MASK"
        if audience == AudienceProfile.INTERNAL_OPERATIONS and entity_type in {EntityType.EMPLOYER, EntityType.JOB_TITLE}:
            return "RETAIN"
        return "GENERALIZE" if entity_type in QUASI_TYPES else "RETAIN"
    if level == PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION:
        if entity_type in DIRECT_TYPES or entity_type == EntityType.EMPLOYER:
            return "PSEUDONYMIZE"
        return "GENERALIZE" if entity_type in QUASI_TYPES else "RETAIN"
    raise ValueError(f"Unsupported privacy level: {level}")


def replacement_for_policy(
    entity_type: EntityType,
    value: str,
    level: PrivacyLevel,
    audience: AudienceProfile,
    ordinal: int,
) -> str:
    action = action_for(entity_type, level, audience)
    token = _letter(ordinal)
    if action == "RETAIN":
        return value
    if action == "REMOVE":
        return {
            EntityType.FACE: "FACE PROTECTED",
            EntityType.QR_CODE: "QR REMOVED",
            EntityType.SIGNATURE_CANDIDATE: "SIGNATURE PROTECTED",
        }[entity_type]
    if action == "PROTECT":
        index = ordinal + 1
        prefix = {
            EntityType.PERSON_NAME: "PERSON",
            EntityType.PHONE: "PHONE",
            EntityType.EMAIL: "EMAIL",
            EntityType.AADHAAR_LIKE: "AADHAAR",
            EntityType.PAN_LIKE: "PAN",
            EntityType.CASE_REFERENCE: "CASE_REFERENCE",
            EntityType.DATE_OF_BIRTH: "DOB",
            EntityType.STREET_ADDRESS: "ADDRESS",
            EntityType.POSTCODE: "POSTCODE",
            EntityType.BUILDING_NUMBER: "BUILDING",
            EntityType.GENERIC_DATE: "DATE",
            EntityType.DEMOGRAPHIC_ATTRIBUTE: "DEMOGRAPHIC",
            EntityType.NATIONAL_ID: "NATIONAL_ID",
            EntityType.PASSPORT_NUMBER: "PASSPORT",
            EntityType.DRIVER_LICENSE_NUMBER: "DRIVER_LICENSE",
            EntityType.TAX_IDENTIFIER: "TAX_ID",
            EntityType.SOCIAL_IDENTIFIER: "SOCIAL_ID",
            EntityType.PAYMENT_CARD_NUMBER: "PAYMENT_CARD",
        }.get(entity_type, entity_type.value)
        return f"[{prefix}_{index:03d}]"
    if action == "MASK":
        if entity_type in QUASI_TYPES:
            return "[CONTEXT PROTECTED]"
        return replacement_for(entity_type, value)
    if action == "SYNTHESIZE":
        return "[SYNTHETIC TWIN VALUE]"
    if action == "PSEUDONYMIZE":
        return {
            EntityType.PERSON_NAME: f"Person {token}",
            EntityType.PHONE: f"Contact {token}",
            EntityType.EMAIL: f"Email alias {token}",
            EntityType.AADHAAR_LIKE: f"Credential {token}",
            EntityType.PAN_LIKE: f"Tax credential {token}",
            EntityType.CASE_REFERENCE: f"Case {token}",
            EntityType.EMPLOYER: f"Organisation {token}",
            EntityType.NATIONAL_ID: f"Identity credential {token}",
            EntityType.PASSPORT_NUMBER: f"Passport credential {token}",
            EntityType.DRIVER_LICENSE_NUMBER: f"Licence credential {token}",
            EntityType.TAX_IDENTIFIER: f"Tax credential {token}",
            EntityType.SOCIAL_IDENTIFIER: f"Social credential {token}",
            EntityType.PAYMENT_CARD_NUMBER: f"Payment credential {token}",
        }.get(entity_type, f"Pseudonym {token}")
    if entity_type == EntityType.DATE_OF_BIRTH:
        return _generalize_date(value)
    if entity_type == EntityType.AGE:
        return _generalize_age(value)
    if entity_type in {EntityType.STREET_ADDRESS, EntityType.LOCALITY}:
        return _generalize_location(value)
    if entity_type == EntityType.POSTCODE:
        digits = re.sub(r"\D", "", value)
        return f"{digits[:3]}XXX" if len(digits) >= 3 else "Regional postcode"
    if entity_type == EntityType.EMPLOYER:
        return _generalize_employer(value)
    if entity_type == EntityType.JOB_TITLE:
        return _generalize_job(value)
    if entity_type == EntityType.PERSON_TITLE:
        return "Personal title protected"
    if entity_type == EntityType.GENERIC_DATE:
        year = _parse_year(value)
        return f"Date in {year}" if year is not None else "Date generalized"
    if entity_type == EntityType.BUILDING_NUMBER:
        return "Building number generalized"
    if entity_type == EntityType.DEMOGRAPHIC_ATTRIBUTE:
        return "Demographic category protected"
    if entity_type == EntityType.CASE_REFERENCE:
        return "[REFERENCE PROTECTED]"
    return "[GENERALIZED]"


def policy_descriptor(audience: AudienceProfile, level: PrivacyLevel, present_types: set[EntityType]) -> dict[str, object]:
    name = {
        PrivacyLevel.DIRECT_MASKING: "Level 1 / Direct masking",
        PrivacyLevel.SENSITIVE_ENTITY_PROTECTION: "Level 2 / Sensitive-entity protection",
        PrivacyLevel.CONTEXT_GENERALIZATION: "Level 3 / Context generalization",
        PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION: "Level 4 / Relationship-safe pseudonymization",
        PrivacyLevel.SYNTHETIC_TWIN: "Level 5 / Synthetic Twin generation",
    }[level]
    objective = {
        AudienceProfile.PUBLIC_RELEASE: "Minimise identity reconstruction in publicly shared material while retaining coarse analytical meaning.",
        AudienceProfile.RESEARCH_PARTNER: "Preserve cohort-level research utility without releasing direct or high-uniqueness identity clues.",
        AudienceProfile.INTERNAL_OPERATIONS: "Protect direct identity while retaining operational context required by an authorised internal recipient.",
    }[audience]
    rules = []
    for entity_type in sorted(present_types, key=lambda item: item.value):
        action = action_for(entity_type, level, audience)
        preview = {
            "REMOVE": "Irreversible region replacement",
            "MASK": "Direct value masked",
            "PROTECT": "Opaque stable protection token",
            "GENERALIZE": "Exact clue converted to a broader category",
            "PSEUDONYMIZE": "Stable job-scoped alias",
            "SYNTHESIZE": "Realistic source-independent synthetic value",
            "RETAIN": "Retained for this audience",
        }[action]
        rationale = {
            "REMOVE": "Visual content can encode identity outside the text layer.",
            "MASK": "The value directly identifies or contacts a person.",
            "PROTECT": "The exact sensitive value is replaced by a non-semantic token while preserving document structure.",
            "GENERALIZE": "The exact value is a quasi-identifier; a broader category preserves utility with lower uniqueness.",
            "PSEUDONYMIZE": "A stable alias preserves cross-page and relationship consistency without releasing the source value.",
            "SYNTHESIZE": "The source value is not released; a synthetic equivalent is generated while structural/statistical utility is measured separately.",
            "RETAIN": "The selected audience policy permits this context; residual risk remains visible in the score.",
        }[action]
        rules.append({"entity_type": entity_type.value, "action": action, "replacement_preview": preview, "rationale": rationale})
    return {
        "audience_profile": audience.value,
        "privacy_level": int(level),
        "name": name,
        "objective": objective,
        "rules": rules,
    }


def residual_factor(action: str) -> float:
    return {"REMOVE": 0.03, "MASK": 0.14, "PROTECT": 0.10, "PSEUDONYMIZE": 0.08, "SYNTHESIZE": 0.02, "GENERALIZE": 0.30, "RETAIN": 1.0}[action]


def utility_loss(action: str, entity_type: EntityType) -> int:
    if action == "RETAIN":
        return 0
    if action == "PSEUDONYMIZE":
        return 1 if entity_type in {EntityType.PERSON_NAME, EntityType.EMPLOYER, EntityType.CASE_REFERENCE} else 2
    if action == "SYNTHESIZE":
        return 2
    if action == "PROTECT":
        return 4
    if action == "GENERALIZE":
        return 3 if entity_type in {EntityType.DATE_OF_BIRTH, EntityType.GENERIC_DATE, EntityType.AGE, EntityType.LOCALITY, EntityType.JOB_TITLE, EntityType.PERSON_TITLE, EntityType.DEMOGRAPHIC_ATTRIBUTE} else 4
    if action == "MASK":
        return 3
    return 5
