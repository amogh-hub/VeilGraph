from __future__ import annotations

from app.security.workspace import create_workspace, destroy_workspace


def test_random_hkdf_fingerprints_are_job_scoped():
    first = create_workspace("slice-c-job-one")
    second = create_workspace("slice-c-job-two")
    try:
        assert first.fingerprint("aarav.test@example.org") == first.fingerprint(" aarav.test@example.org ")
        assert first.fingerprint("aarav.test@example.org") != second.fingerprint("aarav.test@example.org")
    finally:
        destroy_workspace("slice-c-job-one")
        destroy_workspace("slice-c-job-two")


def test_encrypted_workspace_round_trip_and_destruction():
    workspace = create_workspace("slice-c-job-crypto")
    workspace.write_encrypted("blob.vgenc", b"sensitive multimodal bytes")
    assert workspace.read_encrypted("blob.vgenc") == b"sensitive multimodal bytes"
    report = destroy_workspace("slice-c-job-crypto")
    assert report["destroyed"] is True
    assert report["deleted_workspace_files"] == 1
