# VeilGraph SIH Judge Demo — 2:15 Core Flow

## 0:00–0:12 — Promise
Show the landing page.

“Redaction hides obvious fields. VeilGraph asks a harder question: can this person still be reconstructed from the clues that remain? It maps that exposure, transforms it for the intended audience, attacks its own output, and cryptographically binds the evidence before release.”

Point once to: `L1–L5 privacy gradation · fail-closed adversarial gates · 19 package checks · 7/7 offline stress cases`.

## 0:12–0:32 — Discover
Upload `backend/test_identity_graph_document.pdf` and analyse.

Show the graph and outcome ribbon:
- `100 CRITICAL` original exposure
- `37 MODERATE` residual exposure at L4
- `66%` utility retained

Point to one direct identifier, one quasi-identifier and the related person. Do not narrate every node.

## 0:32–0:50 — Explain the differentiator
“Employer, locality, age, birth date and a related person are ordinary clues individually. Linked together, they become an identity reconstruction path. Ordinary redaction misses that relationship risk.”

Briefly show L1, L2, L3 and L4, then return to L4.

## 0:50–1:05 — Fail-closed review
The Human Review Gate is now above the document preview. Protect both genuine person-name candidates.

“Uncertain sensitive detections require explicit review. Until they are resolved, transformation is blocked.”

Do not open the technical inventory.

## 1:05–1:30 — Transform
The compact policy summary shows how many entity classes are pseudonymized/generalized/removed. Keep full policy details collapsed.

Apply Level 4. Show Page 1 before/after, then Page 2:
- `Person A / Person B`
- `Organisation A` stays stable across pages
- `Case A` stays stable across pages
- exact context becomes broader context

“Identity reconstruction is broken while coarse analytical meaning and relationships survive.”

## 1:30–1:55 — Attack
Run the 12-attack Privacy Red Team.

Stop on:
- `VERIFIED SAFE`
- `12/12`
- `100/100`
- `0 critical blockers`
- `ALLOW RELEASE`

“VeilGraph does not trust its own transformation. Any non-PASS mandatory gate keeps release locked.”

Keep all 12 technical attack cards collapsed unless asked.

## 1:55–2:10 — Prove
Show:
- `ED25519 VALID`
- artifact hash-bound
- graph hash-bound
- audit chained
- complete signed proof package

“The proof is bound to this exact artifact, graph, verification result and audit history.”

Keep raw hashes collapsed unless a technical judge asks.

## 2:10–2:15 — Close
“VeilGraph does not merely redact information. It breaks identity reconstruction and proves what is safe to release.”

### Optional follow-up: tamper proof
- genuine package → `PACKAGE_VALID`
- deliberately altered protected PDF → `PACKAGE_INVALID`

### Optional technical drill-down
Only if requested, expand:
- policy details
- full entity inventory
- all 12 adversarial checks
- cryptographic SHA-256 bindings


### Optional high-impact follow-up: Level 5 Synthetic Twin
Upload `backend/test_synthetic_twin_dataset.csv` and choose **Level 5 · Synthetic Twin**.

Show:
- a completely regenerated synthetic population rather than stable L4 aliases;
- zero exact source-row copies;
- zero exact source identity reuse;
- measured schema / distribution / numeric-correlation / time-order fidelity;
- production release randomization;
- the 15-gate Level 5 Red Team and signed proof.

Say:

“Level 4 keeps relationships useful through stable pseudonyms. Level 5 goes further: it learns the dataset's structure in memory and generates a new population that preserves analytical patterns without preserving the source identities or exact source records.”

Do not describe the product scores as differential privacy or a legal anonymity guarantee.
