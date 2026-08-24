import assert from 'node:assert/strict'
import { assertLiveElementSecurity } from '../dist/content/actionSecurity.js'
import {
  createPendingExecution,
  validatePendingExecution,
} from '../dist/security/localAction.js'

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

const frame = {
  frameId: 0,
  isTopFrame: true,
  origin: 'https://example.test',
  href: 'https://example.test/account',
  title: 'Account',
  viewportWidth: 1000,
  viewportHeight: 800,
  devicePixelRatioBasisPoints: 10000,
  scrollX: 0,
  scrollY: 0,
  documentWidth: 1000,
  documentHeight: 1600,
  elements: [{
    localId: 'vg_settings_button',
    tag: 'button',
    role: 'button',
    accessibleName: 'Account settings',
    visibleText: 'Account settings',
    disabled: false,
    bbox: [1000, 1000, 3000, 1800],
    privacyHints: [],
  }],
  eligibleElementCount: 1,
  capturedElementCount: 1,
  captureTruncated: false,
  shadowRootCount: 0,
  captureElapsedMs: 2,
  inaccessibleDescendantFrames: 0,
}

function reasoning(action, task = payload.task) {
  return {
    schema: 'veilgraph.browser-reasoning-response.v1',
    plan: {
      schema: 'veilgraph.browser-action-plan.v1',
      session_id: payload.session_id,
      task_id: payload.task_id,
      actions: [action],
      complete: false,
      summary: task,
    },
    evidence: {
      provider: 'ollama',
      model: 'contract-test',
      elapsed_ms: 1,
      payload_sha256: 'a'.repeat(64),
      visual_context_used: false,
      structured_output_validated: true,
      target_ids_validated: true,
      authorization_verified: true,
      signer_trusted: true,
      replay_protected: true,
    },
  }
}

const click = {
  action: 'CLICK',
  target_id: 'vg_settings_button',
  confidence_basis_points: 9500,
  reason: 'Open settings',
  requires_confirmation: false,
}

const pending = createPendingExecution(
  'VGX-0123456789ABCDEF01234567',
  7,
  [frame],
  payload,
  reasoning(click),
  1_000,
)
assert.ok(pending)
assert.equal(pending.public.frame_id, 0)
assert.equal(pending.public.target_id, 'vg_settings_button')
assert.equal(
  validatePendingExecution(pending, 7, 'https://example.test', frame, false, 2_000).frameId,
  0,
)

assert.throws(
  () => validatePendingExecution(
    pending,
    7,
    'https://example.test',
    {...frame, elements: []},
    false,
    2_000,
  ),
  /stale|missing/,
)

assert.throws(
  () => validatePendingExecution(
    pending,
    7,
    'https://example.test',
    {...frame, elements: [{...frame.elements[0], role: 'textbox'}]},
    false,
    2_000,
  ),
  /role changed/,
)

assert.throws(
  () => validatePendingExecution(pending, 7, 'https://evil.test', frame, false, 2_000),
  /origin changed/,
)

assert.throws(
  () => validatePendingExecution(pending, 7, 'https://example.test', frame, false, 60_000),
  /expired/,
)

const bookingPayload = {
  ...payload,
  task: 'Confirm booking',
  page: {
    ...payload.page,
    elements: [{...payload.page.elements[0], label: 'Confirm booking', text: 'Confirm booking'}],
  },
}
const confirmPending = createPendingExecution(
  'VGX-1123456789ABCDEF01234567',
  7,
  [frame],
  bookingPayload,
  reasoning({...click, reason: 'Confirm booking'}, 'Confirm booking'),
  1_000,
)
assert.ok(confirmPending)
assert.equal(confirmPending.public.requires_confirmation, true)
assert.throws(
  () => validatePendingExecution(confirmPending, 7, 'https://example.test', frame, false, 2_000),
  /explicit local confirmation/,
)

assert.throws(
  () => createPendingExecution(
    'VGX-2123456789ABCDEF01234567',
    7,
    [frame],
    payload,
    reasoning({
      action: 'NAVIGATE',
      url: 'https://evil.test/',
      confidence_basis_points: 9000,
      reason: 'Leave origin',
      requires_confirmation: false,
    }),
    1_000,
  ),
  /cross-origin/,
)

const liveBase = {
  connected: true,
  visible: true,
  occluded: false,
  disabled: false,
  ariaDisabled: false,
  pointerEventsNone: false,
  role: 'button',
  tag: 'button',
  inputType: null,
  credentialLike: false,
}
assert.doesNotThrow(() => assertLiveElementSecurity(click, liveBase))
assert.throws(() => assertLiveElementSecurity(click, {...liveBase, occluded: true}), /occluded/)
assert.throws(() => assertLiveElementSecurity(click, {...liveBase, disabled: true}), /disabled/)

const typeAction = {
  action: 'TYPE',
  target_id: 'vg_search_field',
  value: 'safe query',
  confidence_basis_points: 9000,
  reason: 'Type query',
  requires_confirmation: false,
}
assert.throws(
  () => assertLiveElementSecurity(typeAction, {
    ...liveBase,
    role: 'textbox',
    tag: 'input',
    inputType: 'password',
    credentialLike: true,
  }),
  /credential\/file/,
)

console.log(JSON.stringify({
  status: 'READY',
  contract: 'LOCAL_ACTION_SECURITY_EXECUTION_V1',
  cases: 10,
  guarantees: [
    'single-action-before-reobserve',
    'stable-local-node-id',
    'fresh-frame-preflight',
    'origin-binding',
    'expiry',
    'explicit-high-impact-confirmation',
    'same-origin-navigation',
    'occlusion-block',
    'disabled-block',
    'credential-type-block',
  ],
}))
