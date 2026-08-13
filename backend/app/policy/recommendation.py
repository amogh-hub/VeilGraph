from __future__ import annotations

"""Explainable L1-L5 privacy-level recommendation policy.

The recommender is intentionally deterministic.  It converts the user's stated
purpose/audience and the analysed file type/risk into a transparent default. It
never certifies safety: the existing transformation + Privacy Red Team release
gates remain authoritative.
"""

from dataclasses import dataclass

from app.core.enums import AudienceProfile, EntityType, FileType, PrivacyLevel


_SYNTHETIC_TERMS = (
    "synthetic", "new dataset", "shareable dataset", "ml training", "model training",
    "machine learning training", "test dataset", "testing dataset", "training dataset",
)
_PUBLIC_TERMS = ("public", "publish", "publication", "open portal", "external release", "press release")
_EXTERNAL_TERMS = ("external", "vendor", "third party", "third-party", "partner", "outside")
_ANALYTICS_TERMS = ("analytics", "analysis", "research", "statistics", "statistical", "cohort", "study")
_LINKAGE_TERMS = ("anonymous record", "pseudonym", "link records", "record linkage", "same person", "longitudinal")
_INTERNAL_TERMS = ("internal", "operations", "audit", "case handling", "service delivery", "same team")
_HIGH_RISK_TYPES = {
    EntityType.AADHAAR_LIKE,
    EntityType.PAN_LIKE,
    EntityType.NATIONAL_ID,
    EntityType.PASSPORT_NUMBER,
    EntityType.DRIVER_LICENSE_NUMBER,
    EntityType.TAX_IDENTIFIER,
    EntityType.SOCIAL_IDENTIFIER,
    EntityType.PAYMENT_CARD_NUMBER,
}


@dataclass(frozen=True)
class RecommendationDecision:
    recommended_level: PrivacyLevel
    minimum_level: PrivacyLevel
    reasons: tuple[str, ...]
    l5_supported: bool


def _has(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.casefold()
    return any(term in lowered for term in terms)


def recommend_privacy_level(
    *,
    purpose: str,
    recipient: str,
    audience: AudienceProfile,
    file_type: FileType,
    risk_before: int,
    entity_types: set[EntityType],
) -> RecommendationDecision:
    text = f"{purpose} {recipient}".strip()
    reasons: list[str] = []
    l5_supported = file_type == FileType.DATASET

    # Audience is the stable baseline. These are recommendation floors, not a
    # release certificate and not necessarily enforced unless governance mode
    # is enabled by the deployment.
    if audience == AudienceProfile.PUBLIC_RELEASE:
        recommended = PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION
        minimum = PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION
        reasons.append("The audience is unrestricted/public, so relationship-safe protection is the default safety floor.")
    elif audience == AudienceProfile.RESEARCH_PARTNER:
        recommended = PrivacyLevel.CONTEXT_GENERALIZATION
        minimum = PrivacyLevel.SENSITIVE_ENTITY_PROTECTION
        reasons.append("A research partner usually needs analytical context but not exact direct identity.")
    else:
        recommended = PrivacyLevel.DIRECT_MASKING
        minimum = PrivacyLevel.DIRECT_MASKING
        reasons.append("The audience is trusted internal operations, so direct masking is the least-destructive default.")

    if _has(text, _SYNTHETIC_TERMS):
        if l5_supported:
            recommended = PrivacyLevel.SYNTHETIC_TWIN
            minimum = PrivacyLevel.SYNTHETIC_TWIN
            reasons.append("The stated objective is a new shareable/training dataset; structured input supports a genuine Synthetic Twin.")
        else:
            recommended = max(recommended, PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION)
            reasons.append("A synthetic-data objective was detected, but L5 is only available for CSV/JSON/XLSX; this file stays on L1-L4.")
    elif _has(text, _PUBLIC_TERMS) or _has(text, _EXTERNAL_TERMS):
        recommended = max(recommended, PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION)
        reasons.append("The purpose/recipient crosses a public or external trust boundary.")
    elif _has(text, _ANALYTICS_TERMS):
        recommended = max(recommended, PrivacyLevel.CONTEXT_GENERALIZATION)
        reasons.append("Analytics/research benefits from retaining coarse context while reducing exact quasi-identifiers.")
    elif _has(text, _LINKAGE_TERMS):
        recommended = max(recommended, PrivacyLevel.SENSITIVE_ENTITY_PROTECTION)
        reasons.append("Anonymous record linkage requires stable non-identity record references rather than raw identifiers.")
    elif _has(text, _INTERNAL_TERMS):
        reasons.append("The stated use is internal/operational, so utility can be retained unless higher-risk evidence requires escalation.")

    if entity_types & _HIGH_RISK_TYPES:
        if audience == AudienceProfile.INTERNAL_OPERATIONS:
            recommended = max(recommended, PrivacyLevel.SENSITIVE_ENTITY_PROTECTION)
        else:
            recommended = max(recommended, PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION)
        reasons.append("High-risk credential/identity fields were detected, so the recommendation is escalated.")

    if risk_before >= 75 and recommended < PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION and audience != AudienceProfile.INTERNAL_OPERATIONS:
        recommended = PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION
        reasons.append(f"Identity Exposure is {risk_before}/100, so a stronger external/research protection level is recommended.")
    elif risk_before >= 75:
        reasons.append(f"Identity Exposure is high ({risk_before}/100); review the L1-L4 privacy/utility preview before release.")

    # L5 is never silently recommended for prose/multimedia.
    if recommended == PrivacyLevel.SYNTHETIC_TWIN and not l5_supported:
        recommended = PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION

    return RecommendationDecision(
        recommended_level=recommended,
        minimum_level=minimum,
        reasons=tuple(dict.fromkeys(reasons)),
        l5_supported=l5_supported,
    )
