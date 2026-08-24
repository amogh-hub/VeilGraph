import assert from 'node:assert/strict'
import { validateReasoningResponse } from '../dist/security/actionPlan.js'

const payload = {
  schema: 'veilgraph.browser-release-payload.v1',
  session_id: 'session_0123456789abcdef',
  task_id: 'task_0123456789abcdef',
  task: 'Open account settings',
  page: {
    origin: 'https://example.test',
    page_class: 'web',
    title: 'Account',
    elements: [{
      element_id: 'vg_settings_button',
      role: 'button',
      label: 'Account settings',
      text: 'Account settings',
      disabled: false,
      bbox: [1000, 1000, 3000, 1800],
    }],
    visual_context: null,
  },
  privacy_level: 4,
  network_privacy_floor: 4,
  identity_exposure_before: 80,
  residual_identity_exposure: 8,
  task_utility_score: 92,
  minimization_basis_points: 8600,
}

const baseResponse = {
  schema: 'veilgraph.browser-reasoning-response.v1',
  plan: {
    schema: 'veilgraph.browser-action-plan.v1',
    session_id: payload.session_id,
    task_id: payload.task_id,
    actions: [{
      action: 'CLICK',
      target_id: 'vg_settings_button',
      confidence_basis_points: 9400,
      reason: 'Open the requested settings control',
      requires_confirmation: false,
    }],
    complete: false,
    summary: 'Open account settings',
  },
  evidence: {
    provider: 'ollama',
    model: 'contract-test',
    elapsed_ms: 4,
    payload_sha256: 'a'.repeat(64),
    visual_context_used: false,
    structured_output_validated: true,
    target_ids_validated: true,
    authorization_verified: true,
    signer_trusted: true,
    replay_protected: true,
  },
}

assert.equal(validateReasoningResponse(baseResponse, payload, 'a'.repeat(64)).plan.actions.length, 1)

assert.throws(
  () => validateReasoningResponse({
    ...baseResponse,
    plan: {...baseResponse.plan, actions: [{...baseResponse.plan.actions[0], target_id: 'vg_invented_target'}]},
  }, payload, 'a'.repeat(64)),
  /invented target/,
)

const highImpactPayload = {
  ...payload,
  task: 'Confirm booking',
  page: {...payload.page, elements: [{...payload.page.elements[0], label: 'Confirm booking', text: 'Confirm booking'}]},
}
assert.throws(
  () => validateReasoningResponse({
    ...baseResponse,
    plan: {...baseResponse.plan, actions: [{...baseResponse.plan.actions[0], reason: 'Confirm booking', requires_confirmation: false}]},
  }, highImpactPayload, 'a'.repeat(64)),
  /required local confirmation/,
)

const textboxPayload = {
  ...payload,
  page: {...payload.page, elements: [{...payload.page.elements[0], role: 'textbox', label: 'Search', text: ''}]},
}
assert.throws(
  () => validateReasoningResponse({
    ...baseResponse,
    plan: {
      ...baseResponse.plan,
      actions: [{
        action: 'TYPE',
        target_id: 'vg_settings_button',
        value: 'person@example.test',
        confidence_basis_points: 9000,
        reason: 'Unsafe generated value',
        requires_confirmation: false,
      }],
    },
  }, textboxPayload, 'a'.repeat(64)),
  /direct-identifier/,
)

console.log(JSON.stringify({
  status: 'READY',
  contract: 'SANITIZED_REASONING_ACTION_V1',
  cases: 4,
  guarantees: [
    'payload-bound-plan',
    'released-target-only',
    'direct-identifier-value-block',
    'high-impact-confirmation',
  ],
}))
