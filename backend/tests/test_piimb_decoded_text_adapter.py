from __future__ import annotations

import json

import pytest

from app.benchmark.piimb import benchmark_piimb
from app.core.enums import FileType
from app.extraction.document_processor import DocumentProcessingError, process_document


def test_production_text_upload_guard_still_rejects_control_heavy_bytes():
    payload = ("\x01\x02\x03\x04" * 20 + " visible").encode("utf-8")
    with pytest.raises(DocumentProcessingError, match="binary/control"):
        process_document(payload, FileType.TEXT, "upload.txt")


def test_piimb_scores_already_decoded_unicode_without_mutating_offsets(tmp_path):
    # PIIMB is already parsed from UTF-8 JSON. Some public benchmark sentences
    # legitimately contain Unicode/control-format characters that a production
    # file-upload binary-safety heuristic rejects. The benchmark adapter must
    # preserve the exact Python string and its published character offsets.
    prefix = "\x01\x02\x03\x04"
    email = "alpha@example.org"
    text = prefix + "Email: " + email
    start = text.index(email)
    row = {
        "uid": "control-heavy",
        "task_name": "ai4privacy-en",
        "text": text,
        "entities": [{"start": start, "end": start + len(email), "label": "EMAIL"}],
        "language": "en",
    }
    path = tmp_path / "piimb.jsonl"
    path.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

    result = benchmark_piimb(path, task="ai4privacy-en", limit=1)

    assert result["rows_scored"] == 1
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 1.0
