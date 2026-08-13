# VeilGraph RE-DACT Annotated Output + DOCX Completion Block

## Scope

This block closes two explicit Stage-2 readiness gaps without changing the frozen Broad PII v3 detector or Level 5 Synthetic Twin privacy logic.

### 1. Annotated protected-output mode

VeilGraph now keeps two release views deliberately separate:

- **Clean protected artifact** — the exact releasable output verified by the Privacy Red Team and bound by the certificate.
- **Annotated evidence export** — a derived ZIP for analysts/judges containing the exact protected artifact, an output-bound annotation manifest, certificate JSON, and annotated PNG previews of transformed units.

The annotation manifest contains:

- placeholder / entity type;
- detector confidence and source;
- human-review state;
- applied policy action;
- privacy level / audience profile;
- protected replacement preview and hash;
- page/record/unit index and evidence rectangle;
- protected-output SHA-256 and an internal annotation SHA-256.

It does **not** serialize original plaintext values. The annotation manifest is embedded inside the signed release manifest and exported inside the complete proof bundle, so its identity and output binding are covered by the certificate's manifest hash.

The annotated export remains HTTP-423 locked until the clean artifact is `VERIFIED_SAFE`.

### 2. DOCX through Universal Privacy IR

`.docx` is now a first-class `FileType.DOCX`, not an ad-hoc text conversion path.

Supported privacy surfaces:

- body paragraphs;
- tables;
- headers;
- footers;
- footnotes/endnotes when present;
- displayed hyperlink text;
- text split across multiple WordprocessingML runs;
- embedded PNG/JPEG images through the same local OCR/visual detector pipeline.

The DOCX adapter creates deterministic virtual PAGE units for Privacy IR. Text character offsets remain anchored to their WordprocessingML part so transformations can replace exact spans even when an identifier crosses multiple runs.

### DOCX security posture

The validator/parser is fail-closed for unsafe OPC paths, ZIP-bomb budgets, macro/OLE/ActiveX/embedded-package content and unsupported alternate content.

Protected DOCX output:

- replaces exact visible XML text spans in place;
- regenerates modified embedded images irreversibly;
- re-encodes all supported embedded raster images without EXIF/ancillary metadata;
- removes document properties/custom XML/comments/people metadata from the release package;
- strips external relationships from the protected artifact;
- removes field instructions, deleted/hidden text and hidden run channels;
- removes active/alternate object content;
- preserves paragraph/table/header/footer/note/media structure;
- is reparsed before release so malformed output fails closed.

### DOCX 12-gate release profile

DOCX Levels 1–4 use twelve mandatory gates:

1. direct identifier rescan;
2. independent WordprocessingML/media extraction;
3. secondary DOCX parser rescan;
4. DOCX hidden-channel + embedded QR sub-gate;
5. committed text/image transformation integrity;
6. metadata and embedded-content inspection;
7. policy coverage;
8. relationship consistency;
9. raw OPC object/stream scan;
10. direct-identifier fragment attack;
11. replacement-presence attack;
12. DOCX structure preservation.

Any FAIL or INCONCLUSIVE result blocks release.

## Proof-package impact

New outputs include `veilgraph-annotation-manifest.json` inside the inner proof bundle. New proof packages therefore perform two additional checks:

- annotation manifest internal/output integrity;
- annotation manifest equality with the certificate-bound main manifest.

Legacy proof packages without annotation evidence remain valid and continue to execute the original 19 package checks. New packages execute 21.

## Regression target

This block adds six dedicated tests covering:

- DOCX validation and active-package rejection;
- Privacy IR entry for body/header/footer and split runs;
- Level-4 DOCX end-to-end 12-gate release;
- annotated evidence export and proof binding;
- pre-verification HTTP-423 lock;
- embedded-image regeneration / metadata stripping.

Run the dedicated matrix with `./scripts/run_annotated_docx_matrix.sh`.

Baseline before this block: **146 tests**. Expected full-suite target after application: **152 tests**, plus generated OpenAPI types, TypeScript typecheck and Vite production build.

## Bundled judge fixture

`backend/test_docx_privacy_demo.docx` is a fictional, one-page DOCX fixture containing body text, split-run identifiers, a table, header/footer content and an external hyperlink. It is intended for the final browser smoke test of the DOCX adapter and annotated-evidence export.
