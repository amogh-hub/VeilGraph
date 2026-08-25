# VeilGraph — Privacy Firewall for Browser Agents

**SIH26171 · On-device Visual Perception for Light-weight Browser Agents**

> **The screen does not leave the device until it is safe.**

VeilGraph is a privacy-governed browser agent that separates **local perception
and privacy enforcement** from **central reasoning**. Raw screen state, DOM
values and visual context are processed locally. Only a task-minimal,
privacy-filtered, cryptographically authorized representation may cross the
reasoning boundary.

## Why this directly answers SIH26171

The problem requires a browser-local visual agent, dynamic PII sanitization
before network release, a centralized LLM/VLM that reasons over sanitized
context, and an end-to-end executable browser workflow.

VeilGraph implements:

- browser-local DOM + accessibility + screenshot perception;
- ONNX Runtime Web/WASM UltraFace inference with pinned model hash;
- local OCR / text-region / QR / sensitive-region fusion;
- direct and quasi-identifier detection;
- Identity Exposure Graph;
- task-aware context minimization;
- flattened visual redaction;
- 12 mandatory fail-closed privacy attacks;
- Ed25519-signed network release authorization;
- authenticated ECDH + HKDF + AES-256-GCM raw localhost transport;
- central open-weight Qwen reasoning over sanitized context only;
- schema-validated typed browser actions;
- deterministic local target/action validation;
- independent high-impact confirmation;
- mandatory fresh recapture after every executed action;
- terminal completion evidence constrained to DONE/WAIT;
- Chrome production package and Firefox validation package.

## Enforced execution path

```text
Browser DOM + Accessibility + Visible Screen
        ↓
Local Multimodal Perception
        ↓
Sensitive-Data Fusion
        ↓
Identity Exposure Graph
        ↓
Task/Audience Privacy Compiler
        ↓
Context-Minimal Semantic + Visual Sanitization
        ↓
12 Mandatory Privacy Red-Team Gates
 FAIL / INCONCLUSIVE ───────────────→ BLOCK
        ↓
Signed Network Release Authorization
        ↓
Central Qwen LLM/VLM
        ↓
Typed Action Plan
        ↓
Deterministic Local Security Validator
        ↓
low-impact + high-confidence → local execution
high-impact / uncertain      → local confirmation
        ↓
MANDATORY FRESH RECAPTURE
        ↺
```

## Authenticated raw local transport

The extension does not send plaintext raw captures to an unauthenticated process
merely because it occupies localhost port 8000.

Before raw capture delivery:

1. the extension generates an ephemeral P-256 ECDH key;
2. the companion returns its ephemeral key inside a short-lived attestation;
3. that attestation is signed by the already-pinned persistent Ed25519 identity;
4. the extension verifies the signer before raw material enters an HTTP body;
5. both sides derive an AES-256-GCM key via HKDF-SHA256;
6. DOM metadata + screenshot are sent as authenticated ciphertext;
7. the transport session is one-time and endpoint-bound.

## Controlled proof flow

The bundled PrismCare fixture contains synthetic identity/privacy canaries and a
two-action task:

1. `View Follow-Up Options` — low impact, uniquely supported, autonomous;
2. `Confirm Appointment` — consequential, mandatory local confirmation;
3. fresh capture of `Appointment confirmed`;
4. terminal constrained reasoning returns complete.

## Official metric evidence

Run the final closure workflow or:

```bash
python3 scripts/run_sih26171_scorecard.py
```

Evidence is generated under `artifacts/sih26171/` for:

- visual-context grounding — 25%;
- PII precision/recall — 20%;
- redaction precision/recall — 20%;
- client resource utilization — 20%;
- end-to-end p50/p90/p95 latency — 15%;
- external egress canary proof;
- adversarial closure;
- Chrome and Firefox controlled runs.

Open:

```text
artifacts/sih26171/judge-dashboard.html
```

for the judge-facing measured evidence view.

## Claim discipline

VeilGraph reports only scoped measured evidence.

It does **not** claim:
- universal anonymity;
- zero unknown bugs;
- WebGPU validation on a machine where the validated path was WASM;
- Firefox runtime validation unless a real Firefox loop is recorded;
- a fabricated organizer-issued SIH score.

See `EVALUATION.md`, `SECURITY.md`, `THREAT_MODEL.md`,
`SIH_TRACEABILITY.md`, and `competition/SIH26171_BENCHMARK_PROTOCOL.md`.
