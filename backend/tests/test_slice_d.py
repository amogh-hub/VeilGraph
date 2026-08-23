from __future__ import annotations

import io

import fitz

from app.core.enums import EntityType, FileType, PrivacyLevel, TestStatus as GateStatus
from app.transformation.sanitizer import ProtectionInstruction
from app.verification.red_team import (
    TestResult as VerificationGateResult,
    direct_identifier_fragment_attack,
    proof_score,
    raw_object_stream_scan,
    replacement_presence_attack,
    utility_anchor_preservation,
)


def pdf_with_text(lines: list[str], *, metadata: dict[str, str] | None = None) -> bytes:
    document = fitz.open()
    page = document.new_page(width=595, height=842)
    y = 90
    for line in lines:
        page.insert_text((72, y), line, fontsize=12)
        y += 28
    if metadata:
        current = document.metadata
        current.update(metadata)
        document.set_metadata(current)
    output = io.BytesIO()
    document.save(output, garbage=4, deflate=True, clean=True)
    document.close()
    return output.getvalue()


def instruction(replacement: str = "Person A") -> ProtectionInstruction:
    return ProtectionInstruction(
        entity_id="entity-1",
        mention_id="mention-1",
        entity_type=EntityType.PERSON_NAME,
        page_index=0,
        rect=(70.0, 70.0, 260.0, 110.0),
        replacement=replacement,
    )


def test_raw_object_stream_attack_finds_original_hidden_in_metadata():
    original_name = "Aarav Testperson"
    protected = pdf_with_text(["Public release document"], metadata={"keywords": original_name})
    result = raw_object_stream_scan(protected, FileType.PDF, [(EntityType.PERSON_NAME, original_name)])
    assert result.status == GateStatus.FAIL
    assert "PERSON_NAME" in result.detail


def test_fragment_attack_blocks_substantial_phone_fragment_without_full_number():
    protected = pdf_with_text(["For audit correlation use trace 9198765 only."])
    result = direct_identifier_fragment_attack(
        protected,
        FileType.PDF,
        [(EntityType.PHONE, "+91 98765 43210")],
        PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION,
    )
    assert result.status == GateStatus.FAIL
    assert "PHONE" in result.detail


def test_fragment_attack_does_not_treat_generic_test_word_as_email_leak():
    protected = pdf_with_text(["This document is a test of privacy proof behavior."])
    result = direct_identifier_fragment_attack(
        protected,
        FileType.PDF,
        [(EntityType.EMAIL, "aarav.test@example.org")],
        PrivacyLevel.RELATIONSHIP_SAFE_PSEUDONYMIZATION,
    )
    assert result.status == GateStatus.PASS


def test_replacement_presence_attack_fails_when_manifest_alias_is_missing():
    protected = pdf_with_text(["Citizen identity was removed."])
    result = replacement_presence_attack(protected, FileType.PDF, [instruction("Person A")])
    assert result.status == GateStatus.FAIL
    assert "entity-1" in result.detail


def test_utility_anchor_attack_blocks_destroyed_non_sensitive_meaning():
    original = pdf_with_text([
        "Citizen service application for public research release",
        "This page contains ordinary explanatory context for reviewers",
        "The repeated employer and case reference connect records",
        "Analytical meaning should remain after privacy transformation",
    ])
    protected = pdf_with_text(["Person A"])
    result = utility_anchor_preservation(original, protected, FileType.PDF, [instruction("Person A")])
    assert result.status == GateStatus.FAIL
    assert "lexical anchors" in result.detail


def test_proof_score_is_severity_weighted_and_requires_all_passes_for_100():
    results = [
        VerificationGateResult("a", GateStatus.PASS, "ok", severity="critical"),
        VerificationGateResult("b", GateStatus.PASS, "ok", severity="high"),
        VerificationGateResult("c", GateStatus.PASS, "ok", severity="medium"),
    ]
    assert proof_score(results) == 100
    results[0] = VerificationGateResult("a", GateStatus.FAIL, "leak", severity="critical")
    assert proof_score(results) < 60
