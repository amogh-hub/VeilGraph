from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

from app.browser.models import BrowserGateResult, BrowserVerificationSummary
from app.browser.release_gate import release_payload_sha256
from app.core.enums import EntityType, FileType, TestStatus
from app.detection.visual_detector import detect_visual_entities
from app.extraction.document_processor import process_document
from app.security.signing import canonical_json_bytes


_DIRECT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)),
    ("pan_like", re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])", re.I)),
    ("aadhaar_like", re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)")),
    ("payment_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
    ("phone", re.compile(r"(?<!\d)(?:\+?\d[\s().-]*){10,15}(?!\d)")),
)
_FORBIDDEN_SERIALIZED_KEYS = {
    "raw_value", "href", "privacy_hints", "accessible_name", "screenshot_data_url", "screenshot", "captured_at",
}


def _gate(name: str, status: TestStatus, detail: str, *, severity: str = "critical") -> BrowserGateResult:
    return BrowserGateResult(
        name=name,
        status=status,
        detail=detail,
        attack_class="browser_network_release",
        severity=severity,
        mandatory=True,
    )


def _semantic_object(evidence) -> dict:
    obj = evidence.payload.model_dump(mode="json", by_alias=True)
    visual = obj.get("page", {}).get("visual_context")
    if isinstance(visual, dict):
        visual = dict(visual)
        visual.pop("image_base64", None)
        obj["page"] = dict(obj["page"])
        obj["page"]["visual_context"] = visual
    return obj


def _semantic_text(evidence) -> str:
    payload = evidence.payload
    parts = [payload.task, payload.page.title, payload.page.origin]
    for element in payload.page.elements:
        parts.extend((element.role, element.label, element.text, element.control_type or ""))
    return "\n".join(parts)


def _normalized(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def _known_leaks(text: str, values) -> list[str]:
    lowered = _normalized(text)
    leaks: list[str] = []
    for value in values:
        normalized = _normalized(value)
        if len(normalized) >= 3 and normalized in lowered:
            leaks.append(value)
    return leaks[:12]


def _independent_direct_hits(text: str) -> list[str]:
    hits: list[str] = []
    for name, pattern in _DIRECT_PATTERNS:
        if pattern.search(text):
            hits.append(name)
    return hits


def _direct_identifier_rescan(evidence) -> BrowserGateResult:
    text = _semantic_text(evidence)
    known = _known_leaks(text, evidence.direct_sensitive_values)
    independent = _independent_direct_hits(text)
    if known or independent:
        detail = f"Residual direct identifier evidence: known={known[:4]} independent={independent}"
        return _gate("direct_identifier_rescan", TestStatus.FAIL, detail)
    return _gate("direct_identifier_rescan", TestStatus.PASS, "No known or independently patterned direct identifier remains in the semantic release")


def _visual_sensitive_rescan(evidence) -> BrowserGateResult:
    if evidence.overall_visual_status != "READY":
        return _gate(
            "visual_sensitive_rescan",
            TestStatus.INCONCLUSIVE,
            f"Visual coverage is {evidence.overall_visual_status}; a network release cannot rely on incomplete raster verification",
        )
    try:
        document = process_document(evidence.sanitized_image_bytes, FileType.IMAGE, "browser-sanitized-release.webp")
        ocr_text = "\n".join(line.text for page in document.pages for line in page.lines)
        leaks = _known_leaks(ocr_text, evidence.sensitive_values)
        direct_hits = _independent_direct_hits(ocr_text)
        visual_hits = [
            finding.entity_type.value
            for finding in detect_visual_entities(document)
            if finding.entity_type in {EntityType.FACE, EntityType.QR_CODE}
        ]
        if leaks or direct_hits or visual_hits:
            return _gate(
                "visual_sensitive_rescan",
                TestStatus.FAIL,
                f"Independent sanitized-raster rescan recovered sensitive evidence: known={leaks[:4]} direct={direct_hits} visual={visual_hits[:6]}",
            )
        return _gate(
            "visual_sensitive_rescan",
            TestStatus.PASS,
            "Fresh local OCR + face/QR rescan recovered no protected source value or visual identifier from the flattened sanitized raster",
        )
    except Exception as exc:
        return _gate("visual_sensitive_rescan", TestStatus.INCONCLUSIVE, f"Independent sanitized-raster rescan could not complete: {exc}")


def _dom_attribute_leakage(evidence) -> BrowserGateResult:
    element_dicts = [element.model_dump(mode="json", exclude_none=False) for element in evidence.payload.page.elements]
    allowed = {"element_id", "role", "label", "text", "control_type", "disabled", "checked", "selected", "bbox"}
    bad = sorted({key for item in element_dicts for key in item if key not in allowed})
    if bad:
        return _gate("dom_attribute_leakage", TestStatus.FAIL, f"Non-allow-listed DOM fields entered release payload: {bad}")
    return _gate("dom_attribute_leakage", TestStatus.PASS, "Release elements contain only the explicit public DOM allow-list; raw attributes/datasets/values are structurally absent")


def _accessibility_leakage(evidence) -> BrowserGateResult:
    text = "\n".join([evidence.payload.page.title, *(e.label for e in evidence.payload.page.elements), *(e.text for e in evidence.payload.page.elements)])
    leaks = _known_leaks(text, evidence.sensitive_values)
    if leaks:
        return _gate("accessibility_leakage", TestStatus.FAIL, f"Sanitized labels/text still expose protected values: {leaks[:6]}")
    return _gate("accessibility_leakage", TestStatus.PASS, "Accessible labels and visible semantic text contain no known protected source values")


def _url_referrer_leakage(evidence) -> BrowserGateResult:
    parsed = urlparse(evidence.payload.page.origin)
    safe = (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and parsed.path in {"", "/"}
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )
    if not safe:
        return _gate("url_referrer_leakage", TestStatus.FAIL, "Released page location is not a clean origin-only URL")
    return _gate("url_referrer_leakage", TestStatus.PASS, "Only scheme + origin are released; path, query, fragment, referrer and credentials are absent")


def _serialized_state_leakage(evidence) -> BrowserGateResult:
    obj = _semantic_object(evidence)
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lowered = serialized.casefold()
    bad_keys = sorted(key for key in _FORBIDDEN_SERIALIZED_KEYS if f'"{key}"' in lowered)
    leaks = _known_leaks(serialized, evidence.sensitive_values)
    if bad_keys or leaks:
        return _gate("serialized_state_leakage", TestStatus.FAIL, f"Forbidden serialized state detected: keys={bad_keys} known_values={leaks[:4]}")
    return _gate("serialized_state_leakage", TestStatus.PASS, "Recursive release serialization contains no raw capture fields or known protected source values")


def _policy_coverage(evidence) -> BrowserGateResult:
    if evidence.sensitive_values and evidence.policy_action_count <= 0:
        return _gate("policy_coverage", TestStatus.FAIL, "Sensitive evidence exists but no privacy-compiler action was committed")
    semantic_leaks = _known_leaks(_semantic_text(evidence), evidence.sensitive_values)
    if semantic_leaks:
        return _gate("policy_coverage", TestStatus.FAIL, f"Compiled policy left protected semantic values uncovered: {semantic_leaks[:6]}")
    if evidence.sensitive_values and not evidence.redaction_rects:
        return _gate("policy_coverage", TestStatus.FAIL, "Sensitive evidence exists but no visual redaction region was committed")
    return _gate("policy_coverage", TestStatus.PASS, f"Privacy compiler committed {evidence.policy_action_count} protection action(s) and {len(evidence.redaction_rects)} raster redaction region(s)")


def _relationship_reconstruction(evidence) -> BrowserGateResult:
    residual = evidence.payload.residual_identity_exposure
    threshold = 25
    if residual > threshold:
        return _gate("relationship_reconstruction", TestStatus.FAIL, f"Residual Identity Exposure {residual}/100 exceeds the external-network threshold {threshold}/100")
    return _gate("relationship_reconstruction", TestStatus.PASS, f"Residual Identity Exposure {residual}/100 is within the external-network threshold {threshold}/100")


def _identifier_fragment_attack(evidence) -> BrowserGateResult:
    haystack = re.sub(r"[^a-z0-9]", "", _semantic_text(evidence).casefold())
    fragments: list[str] = []
    for value in evidence.direct_sensitive_values:
        normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
        if len(normalized) < 7:
            continue
        candidates = {normalized}
        if "@" in value:
            local = re.sub(r"[^a-z0-9]", "", value.split("@", 1)[0].casefold())
            if len(local) >= 7:
                candidates.add(local)
        for candidate in candidates:
            if len(candidate) >= 7 and candidate in haystack:
                fragments.append(candidate[:32])
    if fragments:
        return _gate("identifier_fragment_attack", TestStatus.FAIL, f"Identifier fragments survived semantic minimization: {fragments[:6]}")
    return _gate("identifier_fragment_attack", TestStatus.PASS, "No long normalized fragment of a protected direct identifier survives in released semantics")


def _task_minimization(evidence) -> BrowserGateResult:
    m = evidence.minimization
    problems: list[str] = []
    if m.contract != "TASK_MINIMIZATION_V1":
        problems.append(f"contract={m.contract}")
    if m.released_element_count != evidence.released_element_count:
        problems.append("released element accounting mismatch")
    if m.raw_element_count != evidence.raw_element_count:
        problems.append("raw element accounting mismatch")
    if m.released_element_count > 32:
        problems.append(f"released element cap exceeded ({m.released_element_count}/32)")
    if m.raw_element_count > 2 and m.dropped_irrelevant_count <= 0:
        problems.append("no irrelevant context was removed")
    if m.raw_element_count > 2 and m.overall_minimization_basis_points < 500:
        problems.append(f"overall minimization too small ({m.overall_minimization_basis_points}/10000)")
    if not m.required_anchor_ids:
        problems.append("no required task anchor was identified")
    if m.retained_visual_regions > max(1, m.released_element_count):
        problems.append("visual retention regions exceed released semantic anchors")

    if problems:
        return _gate(
            "task_minimization",
            TestStatus.FAIL,
            "TASK_MINIMIZATION_V1 invariant failure: " + "; ".join(problems),
        )
    return _gate(
        "task_minimization",
        TestStatus.PASS,
        (
            f"TASK_MINIMIZATION_V1 released {m.released_element_count}/{m.raw_element_count} element(s); "
            f"dropped={m.dropped_irrelevant_count}; semantic={m.semantic_minimization_basis_points}/10000; "
            f"visual={m.visual_minimization_basis_points}/10000; overall={m.overall_minimization_basis_points}/10000"
        ),
    )


def _payload_commitment_integrity(evidence) -> BrowserGateResult:
    visual = evidence.payload.page.visual_context
    if visual is None:
        return _gate("payload_commitment_integrity", TestStatus.FAIL, "Sanitized visual context is missing from the signed release payload")
    try:
        decoded = base64.b64decode(visual.image_base64, validate=True)
    except Exception as exc:
        return _gate("payload_commitment_integrity", TestStatus.FAIL, f"Sanitized visual base64 is invalid: {exc}")
    import hashlib

    image_hash = hashlib.sha256(decoded).hexdigest()
    payload_hash = release_payload_sha256(evidence.payload)
    canonical_hash = hashlib.sha256(canonical_json_bytes(evidence.payload.model_dump(mode="json", by_alias=True))).hexdigest()
    if decoded != evidence.sanitized_image_bytes or image_hash != visual.sanitized_sha256 or payload_hash != canonical_hash:
        return _gate("payload_commitment_integrity", TestStatus.FAIL, "Sanitized raster or canonical payload commitment mismatch")
    return _gate("payload_commitment_integrity", TestStatus.PASS, f"Exact sanitized raster and canonical release payload commitments verified ({payload_hash[:16]}…)")


def _task_utility_anchor_preservation(evidence) -> BrowserGateResult:
    score = evidence.payload.task_utility_score
    m = evidence.minimization
    if (
        score < 60
        or evidence.released_element_count == 0
        or evidence.relevant_anchor_count == 0
        or not (
            m.actionability_preserved
            or m.completion_evidence_preserved
        )
        or not m.utility_sufficient
        or m.task_token_coverage_basis_points < 4_000
    ):
        return _gate(
            "task_utility_anchor_preservation",
            TestStatus.FAIL,
            (
                f"Sanitization removed too much task context: utility={score}/100 "
                f"anchors={evidence.relevant_anchor_count} elements={evidence.released_element_count} "
                f"token_coverage={m.task_token_coverage_basis_points}/10000 "
                f"actionability={m.actionability_preserved} "
                f"completion={m.completion_evidence_preserved} "
                f"sufficient={m.utility_sufficient}"
            ),
            severity="high",
        )
    return _gate(
        "task_utility_anchor_preservation",
        TestStatus.PASS,
        (
            f"Task-critical anchors remain after minimization: utility={score}/100 "
            f"anchors={evidence.relevant_anchor_count} "
            f"token_coverage={m.task_token_coverage_basis_points}/10000 "
            f"completion={m.completion_evidence_preserved}"
        ),
        severity="high",
    )


def verify_browser_release(evidence) -> BrowserVerificationSummary:
    """Independently attack the exact candidate network payload.

    Protection code does not get to declare itself safe. This verifier rebuilds
    semantic and raster views from the candidate release and records twelve
    mandatory fail-closed gates. FAIL or INCONCLUSIVE therefore prevents the
    signed Network Release Gate from issuing ALLOW_NETWORK_RELEASE.
    """

    tests = [
        _direct_identifier_rescan(evidence),
        _visual_sensitive_rescan(evidence),
        _dom_attribute_leakage(evidence),
        _accessibility_leakage(evidence),
        _url_referrer_leakage(evidence),
        _serialized_state_leakage(evidence),
        _policy_coverage(evidence),
        _relationship_reconstruction(evidence),
        _identifier_fragment_attack(evidence),
        _task_minimization(evidence),
        _payload_commitment_integrity(evidence),
        _task_utility_anchor_preservation(evidence),
    ]
    passed = sum(test.status == TestStatus.PASS for test in tests)
    proof_score = 100 if passed == len(tests) else round(100 * passed / len(tests))
    critical_failures = sum(test.severity == "critical" and test.status != TestStatus.PASS for test in tests)
    by_name = {test.name: test for test in tests}
    forbidden = any(
        by_name[name].status != TestStatus.PASS
        for name in ("dom_attribute_leakage", "accessibility_leakage", "url_referrer_leakage", "serialized_state_leakage")
    )
    commitment_valid = by_name["payload_commitment_integrity"].status == TestStatus.PASS
    critical_exposure = (
        evidence.payload.residual_identity_exposure > 25
        or by_name["direct_identifier_rescan"].status != TestStatus.PASS
        or by_name["visual_sensitive_rescan"].status != TestStatus.PASS
        or by_name["relationship_reconstruction"].status != TestStatus.PASS
    )
    return BrowserVerificationSummary(
        tests=tests,
        proof_score=proof_score,
        critical_failures=critical_failures,
        policy_floor_satisfied=evidence.payload.privacy_level >= evidence.payload.network_privacy_floor,
        forbidden_raw_fields_present=forbidden,
        payload_commitment_valid=commitment_valid,
        critical_exposure_present=critical_exposure,
    )
