import type {
  BrowserReasoningResponse,
  BrowserReleasePreparation,
  LocalActionExecutionResult,
  PendingActionExecution,
  RuntimeResponse,
  SecureAgentLoopResult,
} from '../common/protocol.js'

const status = document.querySelector<HTMLDivElement>('#status')
const analyseButton = document.querySelector<HTMLButtonElement>('#analyse')
const pairButton = document.querySelector<HTMLButtonElement>('#pair')
const prepareButton = document.querySelector<HTMLButtonElement>('#prepare')
const reasonButton = document.querySelector<HTMLButtonElement>('#reason')
const executeButton = document.querySelector<HTMLButtonElement>('#execute')
const loopButton = document.querySelector<HTMLButtonElement>('#agent-loop')
const stopLoopButton = document.querySelector<HTMLButtonElement>('#stop-loop')
const taskInput = document.querySelector<HTMLInputElement>('#task')
const serverInput = document.querySelector<HTMLInputElement>('#server-url')
const detail = document.querySelector<HTMLPreElement>('#detail')
let pendingExecution: PendingActionExecution | null = null
let activeLoopId: `VGL-${string}` | null = null
let loopRunning = false

function setBusy(busy: boolean): void {
  if (analyseButton) analyseButton.disabled = busy
  if (prepareButton) prepareButton.disabled = busy
  if (reasonButton) reasonButton.disabled = busy
  if (executeButton) executeButton.disabled = busy || pendingExecution === null || loopRunning
  if (loopButton) loopButton.disabled = busy || loopRunning
  if (stopLoopButton) stopLoopButton.disabled = !loopRunning || activeLoopId === null
  if (pairButton) pairButton.disabled = busy
}

function taskOrWarn(): string | null {
  if (!taskInput || !status) return null
  const task = taskInput.value.trim()
  if (!task) {
    status.textContent = 'Describe the browser task first.'
    return null
  }
  return task
}

async function analyse(): Promise<void> {
  if (!status || !detail) return
  const task = taskOrWarn()
  if (!task) return
  setBusy(true)
  status.textContent = 'Analysing locally…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_ANALYSE_ACTIVE_PAGE',
      task,
      audienceProfile: 'PUBLIC_RELEASE',
      privacyLevel: 4,
    })
    if (!response.ok) throw new Error(response.error)
    const result = response.data as Record<string, unknown>
    status.textContent = String(result.readiness ?? 'Local analysis complete')
    detail.textContent = JSON.stringify({
      riskBefore: result.risk_before,
      residualPreview: result.residual_risk_preview,
      utilityPreview: result.utility_preview,
      semanticElements: result.semantic_elements,
      credentialFields: result.credential_fields,
      browserVision: result.browser_visual_perception_status,
      localCompanionVision: result.local_companion_visual_status,
      overallVisualCoverage: result.visual_perception_status,
      ocrLines: result.ocr_lines,
      visualFindings: result.visual_findings_count,
      readiness: result.readiness,
    }, null, 2)
  } catch (error) {
    status.textContent = 'Local analysis failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
  }
}

async function prepareRelease(): Promise<void> {
  if (!status || !detail) return
  const task = taskOrWarn()
  if (!task) return
  setBusy(true)
  status.textContent = 'Protecting, attacking and verifying locally…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_PREPARE_ACTIVE_PAGE',
      task,
      audienceProfile: 'PUBLIC_RELEASE',
      privacyLevel: 4,
    })
    if (!response.ok) throw new Error(response.error)
    const result = response.data as BrowserReleasePreparation
    const authorization = result.authorization.payload
    const failed = result.verification.tests
      .filter((test) => test.status !== 'PASS')
      .map((test) => `${test.name}:${test.status}`)

    status.textContent = authorization.decision === 'ALLOW_NETWORK_RELEASE'
      ? 'SAFE PAYLOAD AUTHORIZED — external send still requires the release gate.'
      : 'NETWORK RELEASE DENIED'
    detail.textContent = JSON.stringify({
      decision: authorization.decision,
      proofScore: result.verification.proof_score,
      mandatoryGates: `${authorization.mandatory_passed}/${authorization.mandatory_gates}`,
      criticalFailures: result.verification.critical_failures,
      riskBefore: result.payload.identity_exposure_before,
      residualExposure: result.payload.residual_identity_exposure,
      taskUtility: result.payload.task_utility_score,
      semanticMinimizationBasisPoints: result.minimization.semantic_minimization_basis_points,
      visualMinimizationBasisPoints: result.minimization.visual_minimization_basis_points,
      overallMinimizationBasisPoints: result.minimization.overall_minimization_basis_points,
      taskIntent: result.minimization.task_intent,
      releasedElements: result.minimization.released_element_count,
      droppedIrrelevantElements: result.minimization.dropped_irrelevant_count,
      effectivePrivacyLevel: result.payload.privacy_level,
      networkPrivacyFloor: result.payload.network_privacy_floor,
      redactedVisualRegions: result.payload.page.visual_context?.redacted_regions ?? 0,
      sanitizedVisualSha256: result.payload.page.visual_context?.sanitized_sha256 ?? null,
      payloadSha256: authorization.payload_sha256,
      authorizationId: authorization.authorization_id,
      expiresAt: authorization.expires_at,
      failedOrInconclusiveGates: failed,
    }, null, 2)
  } catch (error) {
    status.textContent = 'Privacy release preparation failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
  }
}


async function reasonSafely(): Promise<void> {
  if (!status || !detail || !serverInput) return
  const task = taskOrWarn()
  if (!task) return
  const serverUrl = serverInput.value.trim()
  if (!serverUrl) {
    status.textContent = 'Configure the sanitized reasoning server first.'
    return
  }

  pendingExecution = null
  setBusy(true)
  status.textContent = 'Minimizing locally, verifying release, then reasoning on sanitized context…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_REASON_ACTIVE_PAGE',
      task,
      serverUrl,
      audienceProfile: 'PUBLIC_RELEASE',
      privacyLevel: 4,
    })
    if (!response.ok) throw new Error(response.error)

    const data = response.data as {
      preparation: BrowserReleasePreparation
      reasoning: BrowserReasoningResponse
      pendingExecution: PendingActionExecution | null
    }
    const auth = data.preparation.authorization.payload
    const plan = data.reasoning.plan
    pendingExecution = data.pendingExecution

    status.textContent = plan.complete
      ? 'TASK COMPLETE — server returned no further action.'
      : pendingExecution
        ? 'SERVER PLAN VERIFIED — next action is awaiting local security execution.'
        : 'SERVER PLAN VERIFIED — no executable local action was issued.'
    detail.textContent = JSON.stringify({
      releaseDecision: auth.decision,
      proofScore: data.preparation.verification.proof_score,
      residualExposure: data.preparation.payload.residual_identity_exposure,
      overallMinimizationBasisPoints: data.preparation.minimization.overall_minimization_basis_points,
      provider: data.reasoning.evidence.provider,
      model: data.reasoning.evidence.model,
      serverReasoningMs: data.reasoning.evidence.elapsed_ms,
      authorizationVerified: data.reasoning.evidence.authorization_verified,
      signerTrusted: data.reasoning.evidence.signer_trusted,
      replayProtected: data.reasoning.evidence.replay_protected,
      structuredOutputValidated: data.reasoning.evidence.structured_output_validated,
      targetIdsValidated: data.reasoning.evidence.target_ids_validated,
      actionPlan: plan.actions,
      planComplete: plan.complete,
      planSummary: plan.summary,
      executionState: pendingExecution ? 'PENDING_LOCAL_SECURITY_VALIDATION' : (plan.complete ? 'COMPLETE' : 'NO_PENDING_ACTION'),
      pendingExecution: pendingExecution ? {
        executionId: pendingExecution.execution_id,
        action: pendingExecution.action.action,
        targetId: pendingExecution.target_id,
        frameId: pendingExecution.frame_id,
        requiresConfirmation: pendingExecution.requires_confirmation,
        expiresAt: pendingExecution.expires_at,
      } : null,
    }, null, 2)
  } catch (error) {
    status.textContent = 'Sanitized server reasoning blocked or failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
  }
}


async function executePending(): Promise<void> {
  if (!status || !detail || !pendingExecution) return
  const execution = pendingExecution
  const action = execution.action

  let confirmed = false
  if (execution.requires_confirmation) {
    confirmed = window.confirm(
      `VeilGraph local confirmation required before ${action.action}.\n\n${action.reason}\n\nProceed?`,
    )
    if (!confirmed) {
      status.textContent = 'High-impact action was not confirmed. Nothing executed.'
      return
    }
  }

  setBusy(true)
  status.textContent = 'Re-validating live DOM state before local execution…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_EXECUTE_PENDING_ACTION',
      executionId: execution.execution_id,
      confirmed,
    })
    if (!response.ok) throw new Error(response.error)

    const result = response.data as LocalActionExecutionResult
    pendingExecution = null
    status.textContent = 'LOCAL ACTION EXECUTED — fresh observation is required before any next action.'
    detail.textContent = JSON.stringify({
      contract: result.contract,
      executionId: result.execution_id,
      status: result.status,
      action: result.action,
      tabId: result.tab_id,
      frameId: result.frame_id,
      targetId: result.target_id,
      confirmed: result.confirmed,
      freshness: result.freshness,
      elapsedMs: result.elapsed_ms,
      nextStep: result.next_step,
      rule: 'Every later action requires a new observe → sanitize → reason → validate cycle.',
    }, null, 2)
  } catch (error) {
    pendingExecution = null
    status.textContent = 'LOCAL ACTION BLOCKED — re-plan from a fresh page observation.'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
  }
}


function localLoopId(): `VGL-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(12))
  return `VGL-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()}`
}

function renderLoop(result: SecureAgentLoopResult): void {
  if (!status || !detail) return
  activeLoopId = result.loop_id
  const terminal = ['COMPLETE', 'BLOCKED', 'CANCELLED', 'STEP_LIMIT', 'LOOP_DETECTED'].includes(result.status)
  if (terminal) loopRunning = false

  status.textContent = result.status === 'COMPLETE'
    ? `TASK COMPLETE — secure agent loop finished in ${result.step_count} action(s).`
    : result.status === 'WAITING_CONFIRMATION'
      ? 'AGENT PAUSED — local confirmation is required.'
      : result.status === 'STEP_LIMIT'
        ? 'AGENT STOPPED — configured action-step limit reached.'
        : result.status === 'LOOP_DETECTED'
          ? 'AGENT STOPPED — repeated-action loop detected.'
          : result.status === 'CANCELLED'
            ? 'AGENT LOOP CANCELLED LOCALLY.'
            : result.status === 'BLOCKED'
              ? 'AGENT LOOP BLOCKED BY A SECURITY/PRIVACY INVARIANT.'
              : 'SECURE AGENT LOOP RUNNING…'

  detail.textContent = JSON.stringify({
    contract: result.contract,
    loopId: result.loop_id,
    status: result.status,
    stepCount: result.step_count,
    maxSteps: result.max_steps,
    startedAt: result.started_at,
    endedAt: result.ended_at,
    stopReason: result.stop_reason,
    pendingExecution: result.pending_execution ? {
      action: result.pending_execution.action.action,
      targetId: result.pending_execution.target_id,
      reason: result.pending_execution.action.reason,
      confidenceBasisPoints: result.pending_execution.action.confidence_basis_points,
      requiresConfirmation: result.pending_execution.requires_confirmation,
      expiresAt: result.pending_execution.expires_at,
    } : null,
    trace: result.trace,
    invariant: 'Every executed action is followed by a completely fresh local observation and privacy release decision.',
  }, null, 2)
  setBusy(false)
}

async function continueLoopFromResult(result: SecureAgentLoopResult): Promise<void> {
  renderLoop(result)
  if (result.status !== 'WAITING_CONFIRMATION' || !result.pending_execution || !activeLoopId) return

  const pending = result.pending_execution
  const loopId = activeLoopId
  const confirmed = window.confirm(
    `VeilGraph secure agent loop requires local confirmation before ${pending.action.action}.\n\n`
    + `${pending.action.reason}\n\nProceed with this one action?`,
  )

  setBusy(true)
  const response = await chrome.runtime.sendMessage<RuntimeResponse>({
    type: 'VG_RESUME_SECURE_AGENT_LOOP',
    loopId,
    confirmed,
  })
  if (!response.ok) throw new Error(response.error)
  await continueLoopFromResult(response.data as SecureAgentLoopResult)
}

async function runSecureAgentLoop(): Promise<void> {
  if (!status || !detail || !serverInput) return
  const task = taskOrWarn()
  if (!task) return
  const serverUrl = serverInput.value.trim()
  if (!serverUrl) {
    status.textContent = 'Configure the sanitized reasoning server first.'
    return
  }

  pendingExecution = null
  const loopId = localLoopId()
  activeLoopId = loopId
  loopRunning = true
  setBusy(true)
  status.textContent = 'Starting secure observe → sanitize → reason → validate → act loop…'

  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_RUN_SECURE_AGENT_LOOP',
      loopId,
      task,
      serverUrl,
      audienceProfile: 'PUBLIC_RELEASE',
      privacyLevel: 4,
      maxSteps: 6,
    })
    if (!response.ok) throw new Error(response.error)
    await continueLoopFromResult(response.data as SecureAgentLoopResult)
  } catch (error) {
    loopRunning = false
    status.textContent = 'SECURE AGENT LOOP FAILED OR WAS BLOCKED.'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
    setBusy(false)
  }
}

async function stopSecureAgentLoop(): Promise<void> {
  if (!activeLoopId || !status) return
  const loopId = activeLoopId
  status.textContent = 'Requesting local loop cancellation…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_CANCEL_SECURE_AGENT_LOOP',
      loopId,
    })
    if (!response.ok) throw new Error(response.error)
    renderLoop(response.data as SecureAgentLoopResult)
  } catch (error) {
    status.textContent = 'Unable to cancel loop cleanly; it will still fail closed on its next boundary.'
    if (detail) detail.textContent = error instanceof Error ? error.message : 'unknown error'
  }
}


async function pairCompanion(): Promise<void> {
  if (!status || !detail) return
  setBusy(true)
  status.textContent = 'Pairing local VeilGraph companion…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({ type: 'VG_PAIR_LOCAL_COMPANION' })
    if (!response.ok) throw new Error(response.error)
    const trusted = response.data as { publicKeySha256?: string; pairedAt?: string }
    status.textContent = 'Local companion identity pinned.'
    detail.textContent = JSON.stringify({
      trustMode: 'explicit TOFU pin',
      signerFingerprint: trusted.publicKeySha256 ?? null,
      pairedAt: trusted.pairedAt ?? null,
      rule: 'A later signer-key change is blocked until trust is explicitly reset.',
    }, null, 2)
  } catch (error) {
    status.textContent = 'Local companion pairing failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
  }
}

pairButton?.addEventListener('click', () => void pairCompanion())
analyseButton?.addEventListener('click', () => void analyse())
prepareButton?.addEventListener('click', () => void prepareRelease())
reasonButton?.addEventListener('click', () => void reasonSafely())
executeButton?.addEventListener('click', () => void executePending())
loopButton?.addEventListener('click', () => void runSecureAgentLoop())
stopLoopButton?.addEventListener('click', () => void stopSecureAgentLoop())
setBusy(false)
