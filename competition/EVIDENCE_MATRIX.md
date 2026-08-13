# VeilGraph Competition Evidence Matrix

| Judge question | Evidence to show | Reproducible artifact |
|---|---|---|
| Is it more than redaction? | Identity Exposure Graph, quasi-identifiers, relationship paths, audience policy | UI graph + Level 3/4 comparison |
| Does it work offline? | Local-only backend, egress guard, bundled OCR/vision, Wi-Fi-off demo | `./scripts/start_local.sh` |
| Does transformation preserve utility? | Generalized/pseudonymized protected preview, utility score | Level 4 protected PDF |
| How do you know the output is safe? | 12 independent mandatory attack gates, fail-closed release | Privacy Red Team proof panel |
| Can hidden PDF data leak? | raw object/stream scan, independent extraction, metadata checks | verification JSON in proof bundle |
| Can repeated identities become inconsistent? | relationship consistency gate and stable aliases | Page 1 + Page 2 protected preview |
| Can proof be forged after the fact? | Ed25519 certificate bound to output/manifest/graph/verification hashes | `veilgraph-certificate.json` |
| Is the activity trail tamper evident? | SHA-256 chained audit ledger | `veilgraph-audit-ledger.json` |
| Can evidence be verified outside the app? | Complete signed proof package + exact-bundle receipt + offline verifier | `scripts/verify_proof_package.py` (`PACKAGE_VALID`) |
| Does sensitive workspace state disappear? | key destruction, encrypted blob deletion, signed destruction receipt | destruction screen / receipt JSON |
| Is there reproducible evaluation? | VeilBench bundled fictional fixtures | `./scripts/run_veilbench.sh` |
| What happens with sideways scans? | Tesseract OSD auto-orientation plus inverse coordinate mapping | `./scripts/run_stress_matrix.sh` → `rotated_90_degree_scan` |
| Can a huge page or image exhaust the machine? | bounded render/pixel budgets reject before analysis | stress matrix + upload validation tests |
| What about password-protected PDFs? | fail-closed rejection because encrypted content cannot be fully inspected | `encrypted_pdf` stress case |
| Can a malicious filename inject a response header/path? | basename + control-character/header-safe normalization | `filename_header_injection` stress case |
