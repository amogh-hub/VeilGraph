# LOCAL_ACTION_SECURITY_EXECUTION_V1

Status: implementation checkpoint. It becomes VALIDATED only after the repository harness reports `RESULT: VALIDATED`.

## Security boundary

The reasoning server cannot execute browser actions. It can only propose a typed `BrowserActionPlan`.

VeilGraph executes at most **one** proposed action before forcing a completely new:

`observe → local privacy analysis → task minimization → Red Team → signed release → server reasoning → local validation`

cycle.

This prevents a multi-step server plan from becoming stale after the first DOM mutation.

## Pending action binding

The service worker creates a short-lived `VGX-*` pending execution record bound to:

- active tab ID;
- sanitized release origin;
- session/task IDs;
- first typed server action only;
- exact local `vg_*` target ID;
- original frame ID and frame origin;
- released target role;
- 45-second expiry;
- locally recomputed confirmation requirement.

Pending actions are memory-only. Service-worker restart loses them and therefore fails closed.

## Fresh live-DOM validation

Immediately before execution VeilGraph:

1. verifies the same active tab and page origin;
2. re-captures the target frame;
3. requires the exact same `vg_*` node ID;
4. blocks replaced, hidden, offscreen or missing targets;
5. rejects role drift and newly disabled targets;
6. asks the content executor to independently check live visibility, occlusion, pointer events, disabled/ARIA-disabled state and action/role compatibility.

The `vg_*` ID is held in a WeakMap from DOM node to random local ID. Replacing the DOM node creates a different identity, so stale selectors are not reused.

## Confirmation

High-impact terms such as confirm, submit, send, payment, purchase, deletion, transfer, booking, signing and authorization are recomputed locally. Execution requires an explicit confirmation interaction in the VeilGraph side panel.

The service worker accepts execution requests only from the extension side-panel context. The pending record is consumed **before** browser mutation, so failed or duplicate executions require re-planning.

## Action execution

Supported locally in this checkpoint:

- `CLICK` — visible, unoccluded, compatible live target only.
- `TYPE` — input/textarea/contenteditable only; password, credential-like and file inputs blocked.
- `SELECT` — select/checkbox/radio only, and option/value must exist locally.
- `READ` — non-mutating; raw text is not returned to the server.
- `SCROLL` — top-frame local scroll only.
- `NAVIGATE` — service-worker controlled and same-origin only.
- `WAIT` — bounded service-worker delay.

No CSS selector, XPath, JavaScript, `eval`, shell command, arbitrary code or server-controlled DOM query is accepted.

## Observe-after-act rule

A successful execution returns:

`next_step = RECAPTURE_REQUIRED`

No second server action is automatically executed. The next milestone builds the continuous observe/reason/act loop around this invariant.

## Claim boundary

After harness validation, we may claim the local action-security/execution boundary is implemented and regression/contract-tested.

We must not yet claim full autonomous end-to-end task completion or official SIH task-success/latency benchmarks. Those require the subsequent agent-loop and benchmark checkpoints.
