import type { BrowserReasoningResponse, BrowserReleasePreparation, RuntimeResponse } from '../common/protocol.js'

const status = document.querySelector<HTMLDivElement>('#status')
const analyseButton = document.querySelector<HTMLButtonElement>('#analyse')
const pairButton = document.querySelector<HTMLButtonElement>('#pair')
const prepareButton = document.querySelector<HTMLButtonElement>('#prepare')
const reasonButton = document.querySelector<HTMLButtonElement>('#reason')
const taskInput = document.querySelector<HTMLInputElement>('#task')
const serverInput = document.querySelector<HTMLInputElement>('#server-url')
const detail = document.querySelector<HTMLPreElement>('#detail')

function setBusy(busy: boolean): void {
  if (analyseButton) analyseButton.disabled = busy
  if (prepareButton) prepareButton.disabled = busy
  if (reasonButton) reasonButton.disabled = busy
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
    }
    const auth = data.preparation.authorization.payload
    const plan = data.reasoning.plan

    status.textContent = 'SANITIZED SERVER PLAN VERIFIED — execution remains local and disabled in this checkpoint.'
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
      executionState: 'NOT_EXECUTED — local action validator/executor is the next security boundary',
    }, null, 2)
  } catch (error) {
    status.textContent = 'Sanitized server reasoning blocked or failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    setBusy(false)
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
