# VeilGraph — RE-DACT Structured Data Engine

This completion step adds first-class `.csv`, `.json`, and `.xlsx` handling to the same privacy pipeline used by documents and images.

## Architecture

`CSV / JSON / XLSX -> schema-aware Universal Privacy IR -> direct + quasi detection -> record-level Identity Exposure Graph -> L1/L2/L3/L4 policy -> canonical structured transform -> 12-attack structured Privacy Red Team -> signed proof`

## Security properties

- CSV and JSON must be UTF-8 and are parsed with deterministic bounds.
- Duplicate JSON object keys are rejected to avoid ambiguous hidden values.
- XLSX is treated as an untrusted ZIP/XML container with path, member-count and uncompressed-size guards.
- XLSX macros, external links, embeddings, ActiveX, query tables and other active/external package channels are rejected fail-closed.
- Formula-bearing XLSX cells are rejected in secure structured mode; judges can be told to export values-only datasets before privacy compilation.
- Protected XLSX is regenerated as a clean canonical workbook rather than copying untrusted package metadata forward.
- CSV formula-injection prefixes are neutralised in exported data.
- Structured outputs preserve schema / record shape while transforming only committed scalar spans.

## Dataset reasoning

Each logical record becomes a TABLE unit inside `veilgraph.privacy-ir.v1`. The graph only claims a cross-column combination when the required clues actually co-occur in the same record. It does not infer a relationship merely because different records contain different people.

## New evidence

12 structured-data regression tests cover validation, Privacy IR, end-to-end CSV/JSON/XLSX release, cross-column graph reasoning, formula fail-closed handling, CSV injection neutralisation, previews, proof-package issuance and stable cross-record pseudonyms.

The project test count therefore moves from 72 to 84. The authoritative acceptance gate remains `./scripts/run_checks.sh` on the target VeilGraph environment.
