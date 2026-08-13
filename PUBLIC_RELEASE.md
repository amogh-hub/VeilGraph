# Public / Judge Release Provenance

This repository tree is a **sanitized public/judge copy** of the authoritative VeilGraph pre-Grand-Finale build. It is intentionally not the private archival directory that created the signed freezes.

## Intentionally omitted

The public copy excludes:

- `.veilgraph/device-ed25519.key` and any other private signing key material;
- runtime `.db` / workspace / upload state;
- `.env` or credential material;
- dependency environments (`backend/.venv`, `.cots-benchmark-venv`, `node_modules`);
- caches and local hotfix backups;
- the generated ~138 MB `competition/releases/veilgraph-sih-phase2-sanitized.zip` archive;
- raw `*.log` files that contain machine-local build paths.

The structured JSON/Markdown evidence and all three signed authoritative manifests are retained.

## Consequence for the archival verifier

The authoritative pre-Grand-Finale manifest binds one raw file that is intentionally omitted here:

```text
competition/final/FINAL_FULL_REGRESSION.log
expected SHA-256:
25c152eaa0e73348bd6da5186e133b17231051822293e0b6604def71ea858363
```

Therefore `scripts/verify_post_hardening_freeze.py` is the **private archival verifier** and is expected to report that one file as missing in this sanitized tree. This does not alter the signed manifests; it reflects a deliberate public-release redaction of machine-local raw logs.

## Public provenance verification

After `./scripts/setup_once.sh`, run:

```bash
backend/.venv/bin/python scripts/verify_public_release.py
```

The public verifier:

1. verifies all three Ed25519 manifest signatures;
2. verifies every signed file that is present in the public tree;
3. permits only the explicitly documented missing raw regression log;
4. fails on any other missing or hash-mismatched signed file.

Expected ending:

```text
PUBLIC_RELEASE_PROVENANCE_VALID
Allowed sanitized omission: competition/final/FINAL_FULL_REGRESSION.log
```

## Authoritative freeze hashes

```text
Phase 1
53701b65c668b181f1432783ea8bfe03b4b91821c1efe5a61aa2d431e3e55040

Phase 2
843ebc8f64fe5c906bc330a96a912d2c4c0d80b3b8a9a93e91f89aba05930042

Pre-Grand-Finale
864781e4eb48c23fe2cae8477427d146aa38814d47708676bd6cc7d7a71bdf6c
```

For full byte-for-byte archival verification, use the private frozen repository containing the omitted raw log—not this GitHub-oriented sanitized copy.
