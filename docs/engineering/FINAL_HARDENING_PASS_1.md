# VeilGraph — Final Hardening Pass 1

This pass hardens the already-complete Slice E codebase. It is **not a new slice**.

## What changed

1. **Recomputable proof bundle**
   - adds `veilgraph-manifest.json`;
   - adds `identity-exposure-graph.json`;
   - adds `veilgraph-bundle-index.json` with SHA-256 commitments for every inner artifact;
   - preserves the protected output, certificate JSON/PDF, verification JSON and certification-time audit ledger.

2. **Signed exact-bundle receipt**
   - VeilGraph now produces a complete proof package whose outer ZIP contains the exact inner proof bundle, an Ed25519-signed receipt for the inner ZIP bytes and the post-export audit ledger;
   - the receipt commits to the inner bundle SHA-256 and byte length, certificate hash, output hash, manifest hash, graph hash, verification hash and export audit checkpoint;
   - the outer package intentionally does not claim a hash of itself, avoiding a circular self-reference.

3. **Standalone package verifier**

```bash
python3 scripts/verify_proof_package.py <complete-proof-package.zip>
```

It independently checks:

- signed bundle receipt;
- exact inner bundle SHA-256 and size;
- export audit hash chain and export event;
- inner bundle index;
- Ed25519 certificate signature;
- protected artifact SHA-256;
- manifest SHA-256;
- Identity Exposure Graph internal SHA-256 and certificate binding;
- exact manifest ↔ graph binding;
- verification-result SHA-256;
- certification audit hash chain and the certificate's historical audit checkpoint.

4. **Certificate PDF improvement**
   - now prints the **complete** Ed25519 Base64 signature instead of an abbreviated signature;
   - includes explicit offline-verification guidance.

5. **Tamper regression matrix**
   - modified protected artifact → rejected;
   - modified certificate → rejected;
   - modified manifest → rejected;
   - modified Identity Exposure Graph → rejected;
   - modified export audit ledger → rejected;
   - modified signed bundle receipt → rejected.

## Acceptance gate

The final target Mac must run:

```bash
./scripts/run_checks.sh
```

Expected after this hardening patch:

```text
46 passed
TypeScript type-check passed
Vite production build passed
```

The exact number increases from 45 to 46 because the tamper/recomputability matrix is one additional end-to-end regression test.

## Proof-package semantics

A **proof bundle** is the inner evidence archive. A **complete signed proof package** is the outer transport archive containing:

```text
<certificate-id>-proof-bundle.zip
veilgraph-bundle-receipt.json
veilgraph-export-audit-ledger.json
VERIFY_PACKAGE.txt
```

The receipt signs the exact bytes of the inner proof bundle. The export ledger proves VeilGraph recorded that exact bundle hash. The inner bundle contains all material needed to recompute the hashes committed by the certificate.

## Boundary

This strengthens evidence integrity and reproducibility. It does not turn the residual-exposure score into a mathematical anonymity guarantee, nor does it establish a third-party certificate authority. The Ed25519 key represents the local VeilGraph installation.
