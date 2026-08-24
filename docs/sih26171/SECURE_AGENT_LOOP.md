# SECURE_AGENT_LOOP_V1

Status: implementation checkpoint. It becomes VALIDATED only after `./scripts/verify_sih_checkpoint.sh` reports `RESULT: VALIDATED`.

## Purpose

This checkpoint composes the already validated VeilGraph boundaries into the actual browser-agent control loop:

`observe → local perception → privacy compiler → task minimization → Browser Privacy Red Team → signed release → sanitized LLM/VLM reasoning → typed action validation → local live-DOM security validation → execute one action → fresh observation`

The loop never bypasses any prior boundary.

## One action, then re-observe

Even if the reasoning server returns several typed actions, VeilGraph only makes the **first** action eligible. After one action executes, the prior plan is stale by definition.

The next action therefore requires:

1. a new screen/DOM/accessibility observation;
2. a new task-conditioned privacy compilation;
3. a new 12-gate Browser Privacy Red Team pass;
4. a new signed `ALLOW_NETWORK_RELEASE`;
5. a new server reasoning request;
6. a new local live-DOM action-security pass.

This is the core stale-plan defense.

## Autonomous vs locally confirmed actions

An action may auto-execute only when all existing local-action checks pass and:

- the server/local policy did **not** mark it high impact; and
- confidence is at least 7000 basis points.

High-impact actions and lower-confidence actions pause the loop and require a local confirmation from the VeilGraph side panel.

A denial cancels the loop without executing the pending action.

## Loop governor

`SECURE_AGENT_LOOP_V1` adds a deterministic local governor:

- maximum 8 executed actions, with the judge UI defaulting to 6; after the limit, a final fresh observation/reasoning pass may still mark the task complete, but no further action can execute;
- 120-second loop deadline;
- active-tab binding;
- top-frame origin binding: an unexpected cross-origin transition stops the loop before another network release;
- only one running/waiting loop per tab;
- repeated identical-action detection (third consecutive identical action is stopped);
- memory-only state — service-worker restart loses loop state and therefore fails closed;
- explicit local cancellation;
- bounded local trace with no raw capture content.

## Privacy invariants per iteration

Every iteration calls the existing local `prepare-release` path. If the signed release decision is not `ALLOW_NETWORK_RELEASE`, the loop stops and the reasoning server is not contacted.

The loop trace records only evidence summaries such as proof score, residual exposure, minimization basis points, action type and target ID. It does not persist the raw screenshot, raw DOM values, Identity Exposure Graph, or unsanitized task context.

## Page stabilization

After a successful action VeilGraph waits briefly, then performs a fresh observation. The observation path retries a bounded number of times if the browser page is still transitioning.

If a trustworthy fresh top-frame observation cannot be obtained, the loop fails closed.

## Claim boundary

After harness validation, it is valid to claim that the full secure browser-agent control-loop orchestration is implemented and contract/regression tested across the already validated privacy, reasoning and local-execution boundaries.

Do **not** yet claim:

- a measured real-model end-to-end task success rate;
- official SIH 25/20/20/20/15 benchmark scores;
- final Chrome/Firefox deployment validation;
- production latency/resource results.

Those require the dedicated browser E2E and benchmark checkpoints.
