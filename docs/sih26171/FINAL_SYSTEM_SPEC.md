# VeilGraph — SIH26171 Final System Specification

## Status

**Authoritative direction.** This document defines the system VeilGraph will present for Smart India Hackathon 2026 problem statement **SIH26171 — Indian Space Research Organisation (ISRO) — “On-device Visual Perception for Light-weight Browser Agents.”**

The previous RE-DACT judge-facing GitHub tree is preserved as the immutable historical baseline. Development from this point targets one final architecture; implementation checkpoints are not product versions and must not introduce throwaway architecture.

## Competition objective

Build the strongest defensible implementation of SIH26171, optimized for the official evaluation dimensions while retaining VeilGraph's relationship-aware privacy advantage.

**Core thesis:** **The screen does not leave the device until it is safe.**

**Positioning:** VeilGraph is the privacy-governance layer that controls whether a browser agent may communicate with a reasoning server. It is not a redaction add-on placed beside the agent.

## Official scoring dimensions

The final system must continuously benchmark and expose evidence for:

1. Visual-context accuracy — **25%**
2. Precision/recall of sensitive/PII detection — **20%**
3. Precision of redaction — **20%**
4. Client-side resource utilization — **20%**
5. End-to-end task latency — **15%**

## Non-negotiable architecture

```text
Browser page
  ├─ DOM semantics
  ├─ accessibility semantics
  └─ visual screen
        ↓
Browser-native local multimodal perception
        ↓
Hybrid sensitive-data engine
        ↓
Identity Exposure Graph
        ↓
Task-aware privacy compiler + mandatory network privacy floor
        ↓
Context-minimal sanitizer
        ↓
Independent Browser Privacy Red Team
        ↓
Network Release Gate
  ├─ FAIL / INCONCLUSIVE → DENY_NETWORK_RELEASE
  └─ PASS → signed, commitment-bound sanitized context only
        ↓
Reasoning server LLM/VLM
        ↓
Typed action plan
        ↓
Local action security validator
        ↓
Constrained browser executor
        ↓
Observe result and iterate through the same privacy boundary
```

## Security zones

### Zone A — Private device

Raw screenshot pixels, raw DOM text/attributes, form values, local browsing context, direct identifiers, quasi-identifiers and identity relationships exist only in the local trust boundary.

The extension and local VeilGraph companion may exchange raw context over loopback. **No raw context is permitted to cross an external network boundary.** Loopback is not treated as external disclosure.

### Zone B — Network release boundary

The only externally transmissible object is a schema-constrained `BrowserReleaseEnvelope`. It must be:

- generated from sanitized/minimized context;
- bound to a SHA-256 payload commitment;
- associated with a complete mandatory Browser Privacy Red Team result;
- associated with a satisfied network privacy floor;
- free of raw screenshot bytes, raw DOM dumps, hidden raw attributes and raw form values;
- authorized by a deterministic `ALLOW_NETWORK_RELEASE` decision;
- cryptographically signed by the local VeilGraph signer;
- short-lived and nonce-bound to reduce replay risk.

There is no “continue anyway” path for a mandatory privacy failure.

### Zone C — Reasoning server

The reasoning server receives only the release envelope. It must not request or recover the raw screen. It returns a typed action plan, never executable JavaScript.

### Zone D — Local execution

The extension validates every action against a strict allow-list and local policy before execution. High-impact actions require explicit user confirmation.

## Final browser perception model

Perception is deliberately multimodal:

### DOM semantics

Capture only relevant semantic features locally: tag/role, labels, visible text, field type, state, normalized geometry and privacy-relevant attribute classes. Raw DOM is never externally serialized.

### Accessibility semantics

Derive accessible name, role, state and relationships from DOM semantics; use browser accessibility APIs only where permission and platform support justify them. The system must not claim access to a native accessibility tree unless it actually obtains one.

### Visual screen

Capture the visible tab locally and perform browser-native inference using WebGPU when available, with a WASM fallback. The local vision runtime must be open-weight/offline deployable and packaged with the extension or local bundle; no model download is allowed during judged runtime.

DOM/a11y semantics and visual detections are fused by stable local element identifiers and geometry.

## Existing VeilGraph components retained

The following current capabilities are architectural assets and must be adapted rather than rewritten without evidence:

- deterministic + semantic sensitive-data detection;
- contextual/quasi-identifier detection;
- visual sensitive-region detection;
- Privacy IR concepts;
- canonical entity resolution;
- Identity Exposure Graph and reconstruction paths;
- L1–L5 privacy compiler concepts;
- residual exposure/utility indicators;
- independent fail-closed Privacy Red Team pattern;
- AES-256-GCM local workspace protection;
- HMAC-SHA256 local entity fingerprints;
- SHA-256 commitments/audit chain;
- Ed25519 proof signing;
- bounded resource admission and local/offline runtime controls.

Existing file-release code remains supported as a historical capability, but browser-network release is a new first-class release surface with its own policy and adversarial verification.

## Network privacy floor

Audience/purpose recommendations become mandatory at the external network boundary. The effective protection level is:

```text
effective_network_level = max(user_requested_level, compiler_required_network_floor)
```

Users may strengthen privacy but may not weaken protection below the network floor.

A recommendation is not equivalent to a mathematical anonymity guarantee. The floor is a product-governance decision and must be benchmarked/calibrated.

## Task-conditioned data minimization

Sanitization is not limited to hiding sensitive pixels. VeilGraph asks what information the reasoning server actually needs to complete the task.

The release envelope should contain the smallest useful semantic representation of task-relevant UI elements. Irrelevant page regions and identifiers remain local even if they could theoretically be safely generalized.

The system will report a **Data Minimization Ratio** as a descriptive engineering metric, not as proof of privacy.

## Browser Privacy Red Team — mandatory attack classes

Before any external request, the final browser release verifier must independently evaluate at least these mandatory classes:

1. direct identifier rescan;
2. visual sensitive-region recovery/rescan;
3. DOM attribute leakage;
4. accessibility-name/state leakage;
5. URL/query/referrer leakage;
6. hidden/raw serialized-state leakage;
7. policy coverage and required network floor;
8. relationship/reconstruction attack;
9. identifier-fragment recombination attack;
10. task-minimization / unnecessary disclosure check;
11. release-envelope schema + payload commitment integrity;
12. task-utility anchor preservation.

Any mandatory `FAIL` or `INCONCLUSIVE` blocks the external request.

## Network release decision invariant

External transmission is authorized only when all of the following hold:

```text
all mandatory browser privacy gates == PASS
proof_score == 100
critical_failures == 0
network privacy floor satisfied
no forbidden raw-field classes in release envelope
payload SHA-256 commitment matches canonical envelope payload
envelope is unexpired and nonce-bound
release proof signature validates
```

The residual exposure score remains evidence, not a standalone mathematical probability and not the only release criterion.

## Reasoning-server protocol

The server receives a typed semantic envelope, not raw page state. Returned actions are schema constrained. Initial allowed actions:

- `CLICK`
- `SCROLL`
- `TYPE`
- `SELECT`
- `NAVIGATE`
- `READ`
- `WAIT`

No arbitrary script/eval action exists.

Every action includes a stable local target identifier when applicable, a confidence score, and a reason. The local executor rejects stale/missing targets.

## Sensitive action policy

Automatic execution is allowed only for low-impact actions that match the user-requested task.

Explicit confirmation is required for actions that can materially affect the user or disclose protected information, including payments, purchases, account/security changes, destructive actions, sending messages/email, external uploads, final form submission containing sensitive fields, permission grants, or other policy-classified high-impact actions.

## Browser-extension privilege model

- Manifest V3.
- Minimum required permissions.
- Content scripts do not receive broad external host permissions.
- External reasoning-server access is centralized in the service worker.
- Loopback access is explicitly scoped to the local VeilGraph companion.
- Reasoning-server origins are optional/explicit rather than `<all_urls>` host permissions where technically feasible.
- Strict extension CSP; no `eval`, remote scripts or remote executable code.
- No secrets embedded in extension source.
- Session context is ephemeral and bounded.

## Benchmark requirements

Create `VeilBench-Browser`, containing labelled pages/tasks across at least:

- authentication/login;
- banking/financial;
- healthcare;
- government forms;
- e-commerce;
- email;
- social media;
- HR/employment;
- education;
- insurance;
- travel;
- browser PDF/content viewers;
- dashboards;
- spreadsheet-like interfaces;
- mixed DOM/canvas/image applications.

Ground truth includes direct PII, credentials, visual PII, quasi-identifiers, safe context, task-critical elements and expected action outcomes.

## Required measurements

### Official metrics

- visual/semantic context accuracy;
- PII precision, recall and F1 overall and by entity class;
- sensitive-region/redaction precision, recall, leakage and over-redaction;
- CPU, RAM, browser memory, GPU/WebGPU utilization where measurable, model load time;
- capture/perception/detection/graph/compiler/sanitizer/verification/network/reasoning/execution latency with median and p95;
- end-to-end task completion rate.

### VeilGraph differentiation metrics

- Identity Exposure before/after;
- dangerous reconstruction paths before/after;
- task utility retained;
- data minimization ratio;
- Browser Privacy Red Team coverage/pass rate;
- raw external disclosure count (target: zero for protected classes).

## Evidence discipline

Every capability must have one of four statuses:

- `IMPLEMENTED` — code exists and is integrated;
- `PARTIAL` — code exists but the final requirement is not met;
- `PLANNED` — design only, not claimable as implemented;
- `VALIDATED` — implemented and supported by reproducible evidence.

Judge-facing claims may not upgrade a status. Evidence upgrades status.

## Zero-defect release target

Literal absence of all possible software defects cannot be guaranteed. The competition release bar is therefore:

- no known critical/high-severity privacy, security or correctness defects;
- all mandatory release/security gates green;
- all regression/integration/adversarial tests green;
- reproducible clean build;
- no known raw external disclosure path;
- no unhandled happy-path errors;
- graceful fail-closed behavior for unsupported/ambiguous privacy cases;
- benchmark evidence generated from the exact build being demonstrated;
- architecture shown to judges matches the running architecture.

## Anti-shortcut rules

The final system must not contain:

- fake local inference while raw data goes to cloud;
- screenshot-only privacy if DOM semantics are available and useful;
- decorative Identity Exposure Graphs that do not affect policy;
- decorative Red Team results that do not control network release;
- user bypasses for mandatory privacy failures;
- arbitrary server-returned JavaScript;
- hard-coded demo-only metrics;
- fabricated benchmarks;
- future architecture presented as current architecture;
- silent security fallbacks.

## Delivery strategy

One final architecture is implemented progressively. Breadth follows a complete final-architecture vertical path:

```text
user task → local perception → exposure analysis → privacy compilation →
minimization → adversarial verification → actual external release gate →
sanitized reasoning → action validation → browser execution → evidence
```

Once this path is fully real and hardened, scenario breadth and model coverage expand without replacing its architectural spine.
