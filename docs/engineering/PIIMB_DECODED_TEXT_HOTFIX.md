# VeilGraph — PIIMB decoded-text benchmark hotfix

## Problem

PIIMB rows are already decoded from UTF-8 JSON and their gold annotations are Python-string character offsets. The prior benchmark adapter re-encoded each row to bytes and routed it through VeilGraph's production text-upload decoder. The upload decoder intentionally rejects control-heavy/binary-looking payloads, so legitimate benchmark rows containing Unicode/control-format characters could terminate the benchmark before scoring.

## Fix

- Production text uploads keep the existing binary/control-character safety gate unchanged.
- A new `processed_document_from_decoded_text()` adapter builds VeilGraph's virtual text document directly from an already-decoded trusted string.
- PIIMB uses that adapter, preserving the original benchmark text and published character offsets without sanitising, deleting, or replacing characters.
- Two regression tests prove both sides of the boundary: production uploads still reject control-heavy bytes, while PIIMB can score already-decoded control-heavy Unicode text with correct offsets.

This changes benchmark ingestion only. It does not loosen the production upload validator or change detector/policy/proof behavior.
