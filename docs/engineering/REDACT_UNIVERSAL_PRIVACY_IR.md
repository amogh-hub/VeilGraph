# RE-DACT Completion — Universal Privacy IR v1

VeilGraph now normalizes extracted content through a format-neutral **Universal Privacy IR** before detection, graph construction, policy compilation, transformation and proof.

## Why this exists

Adding TXT, CSV, XLSX, JSON and video as separate privacy pipelines would create inconsistent security behavior. Privacy IR gives every format one downstream privacy engine.

Current adapters:

- PDF → PAGE units
- Scanned PDF → PAGE/OCR units
- PNG/JPG/JPEG → PAGE/OCR units

Reserved IR unit kinds for the next adapters:

- TEXT
- TABLE
- VIDEO_FRAME

## Security property

Source text exists only in memory inside the IR. Persistent audit metadata contains only counts, extraction-source metadata and a SHA-256 commitment over hashed spans/tokens and geometry. `plaintext_persisted` is explicitly false.

## Evidence

The patch adds tests proving:

1. IR round-tripping preserves detector semantics.
2. IR commitments are deterministic and content-bound.
3. IR summaries do not serialize source plaintext.
4. Analysis/audit events are cryptographically bound to the IR commitment.

The next RE-DACT completion step is to add common text and structured-data adapters into this same IR rather than creating parallel redaction implementations.
