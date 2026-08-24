import assert from 'node:assert/strict'
import {
  actionFingerprint,
  appendLoopTrace,
  beginSecureAgentLoop,
  evaluateLoopAction,
  markLoopCancelled,
  markLoopComplete,
  publicLoopResult,
  registerLoopExecution,
  validateLoopContinuation,
  validateLoopOrigin,
} from '../dist/security/agentLoop.js'

const click = {
  action: 'CLICK',
  target_id: 'vg_settings_button',
  confidence_basis_points: 9500,
  reason: 'Open settings',
  requires_confirmation: false,
}

const lowConfidence = {
  ...click,
  confidence_basis_points: 5000,
}

const highImpact = {
  ...click,
  reason: 'Confirm booking',
  requires_confirmation: true,
}

const machine = beginSecureAgentLoop(
  'VGL-0123456789ABCDEF01234567',
  7,
  'Open account settings',
  99,
  1_000,
)

assert.equal(machine.maxSteps, 8)
assert.equal(validateLoopContinuation(machine, 7, 2_000).allowed, true)
assert.equal(validateLoopOrigin(machine, 'https://example.test/account').allowed, true)
assert.equal(validateLoopOrigin(machine, 'https://example.test/settings').allowed, true)
assert.equal(validateLoopOrigin(machine, 'https://evil.test/').reason, 'ORIGIN_CHANGED_DURING_LOOP')
assert.equal(validateLoopContinuation(machine, 8, 2_000).reason, 'ACTIVE_TAB_CHANGED')
assert.equal(
  validateLoopContinuation(machine, 7, 1_000 + 120_001).reason,
  'LOOP_DEADLINE_EXCEEDED',
)

let evaluation = evaluateLoopAction(machine, click, 2_000)
assert.equal(evaluation.allowed, true)
assert.equal(evaluation.requiresConfirmation, false)

evaluation = evaluateLoopAction(machine, lowConfidence, 2_000)
assert.equal(evaluation.requiresConfirmation, true)
assert.match(evaluation.reason, /LOW_CONFIDENCE/)

evaluation = evaluateLoopAction(machine, highImpact, 2_000)
assert.equal(evaluation.requiresConfirmation, true)
assert.match(evaluation.reason, /HIGH_IMPACT/)

registerLoopExecution(machine, click, 4, 2_100)
registerLoopExecution(machine, click, 4, 2_200)
evaluation = evaluateLoopAction(machine, click, 2_300)
assert.equal(evaluation.allowed, false)
assert.equal(evaluation.status, 'LOOP_DETECTED')

assert.equal(actionFingerprint(click), actionFingerprint({...click}))
assert.notEqual(actionFingerprint(click), actionFingerprint({...click, target_id: 'vg_other_button'}))

const stepMachine = beginSecureAgentLoop(
  'VGL-1123456789ABCDEF01234567',
  9,
  'Task',
  2,
  1_000,
)
registerLoopExecution(stepMachine, click, 1, 1_100)
registerLoopExecution(stepMachine, {...click, target_id: 'vg_second_button'}, 1, 1_200)
assert.equal(validateLoopContinuation(stepMachine, 9, 1_300).allowed, true)
assert.equal(
  evaluateLoopAction(stepMachine, {...click, target_id: 'vg_third_button'}, 1_300).status,
  'STEP_LIMIT',
)

appendLoopTrace(stepMachine, {
  stage: 'OBSERVE',
  action: null,
  targetId: null,
  proofScore: null,
  residualExposure: null,
  minimizationBasisPoints: null,
  elapsedMs: 3,
  note: 'Fresh observation',
})
markLoopComplete(stepMachine, 1_400)
const complete = publicLoopResult(stepMachine, null)
assert.equal(complete.status, 'COMPLETE')
assert.equal(complete.ended_at, new Date(1_400).toISOString())

const cancelledMachine = beginSecureAgentLoop(
  'VGL-2123456789ABCDEF01234567',
  11,
  'Task',
  4,
  1_000,
)
markLoopCancelled(cancelledMachine, 'LOCAL_CANCEL_REQUEST', 1_500)
assert.equal(publicLoopResult(cancelledMachine, null).status, 'CANCELLED')

const bounded = beginSecureAgentLoop(
  'VGL-3123456789ABCDEF01234567',
  12,
  'Task',
  4,
  1_000,
)
for (let index = 0; index < 30; index += 1) {
  appendLoopTrace(bounded, {
    stage: 'OBSERVE',
    action: null,
    targetId: null,
    proofScore: null,
    residualExposure: null,
    minimizationBasisPoints: null,
    elapsedMs: index,
    note: `event-${index}`,
  })
}
assert.equal(bounded.trace.length, 24)
assert.equal(bounded.trace[0].sequence, 1)
assert.equal(bounded.trace.at(-1).sequence, 24)

console.log(JSON.stringify({
  status: 'READY',
  contract: 'SECURE_AGENT_LOOP_V1',
  cases: 14,
  guarantees: [
    'bounded-max-steps',
    'tab-binding',
    'same-origin-loop-continuity',
    'cross-origin-loop-stop',
    'global-loop-deadline',
    'high-confidence-low-impact-auto-execution',
    'low-confidence-confirmation',
    'high-impact-confirmation',
    'repeated-action-loop-detection',
    'stable-action-fingerprint',
    'step-limit-stop',
    'task-complete-terminal-state',
    'local-cancellation',
    'bounded-safe-trace',
  ],
}))
