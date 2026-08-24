import type {
  BrowserNetworkAuthorization,
  BrowserReasoningResponse,
  BrowserReleasePayload,
  BrowserReleasePreparation,
  FrameCapture,
  LocalActionExecutionResult,
  PendingActionExecution,
  SecureAgentLoopResult,
  CaptureCoverageItem,
  LocalPerceptionStatus,
  PageCaptureBundle,
  RuntimeRequest,
  RuntimeResponse,
  VisualCapability,
} from '../common/protocol.js'
import { runLocalVision } from '../perception/localVision.js'
import { createOnnxLearnedFaceDetector } from '../perception/learnedFaceModel.js'
import type { OnnxRuntimeLike } from '../perception/learnedFaceModel.js'
// The build copies this pinned ONNX Runtime Web module into dist/vendor.
// @ts-ignore -- generated vendor asset intentionally lives outside src/.
import * as ortRuntime from '../vendor/onnxruntime/ort.wasm.bundle.min.mjs'
import { verifyTrustedNetworkAuthorization } from '../security/releaseGate.js'
import { pairLocalCompanion } from '../security/pairing.js'
import { validateReasoningResponse } from '../security/actionPlan.js'
import {
  createPendingExecution,
  validatePendingExecution,
} from '../security/localAction.js'
import type { PendingExecutionRecord } from '../security/localAction.js'
import {
  appendLoopTrace,
  beginSecureAgentLoop,
  evaluateLoopAction,
  markLoopCancelled,
  markLoopComplete,
  markLoopStopped,
  publicLoopResult,
  registerLoopExecution,
  validateLoopContinuation,
  validateLoopOrigin,
} from '../security/agentLoop.js'
import type { SecureAgentLoopMachine } from '../security/agentLoop.js'


const learnedFaceDetector = createOnnxLearnedFaceDetector(
  ortRuntime as unknown as OnnxRuntimeLike,
  (path) => chrome.runtime.getURL(path),
)

function nowMs(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

function captureId(): `VGC-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(12))
  return `VGC-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()}`
}

function executionId(): `VGX-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(12))
  return `VGX-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()}`
}

const pendingExecutions = new Map<`VGX-${string}`, PendingExecutionRecord>()

function rememberPendingExecution(record: PendingExecutionRecord): void {
  const now = Date.now()
  for (const [key, candidate] of pendingExecutions) {
    if (Date.parse(candidate.public.expires_at) < now) pendingExecutions.delete(key)
  }
  pendingExecutions.set(record.public.execution_id, record)
}

function pageOrigin(url: string | undefined): string {
  if (!url) throw new Error('active tab URL is unavailable')
  const parsed = new URL(url)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('active tab is not an HTTP(S) page')
  return parsed.origin
}

function trustedSidepanelSender(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id
    && !sender.tab
    && typeof sender.url === 'string'
    && sender.url.startsWith(chrome.runtime.getURL('sidepanel/'))
  )
}

interface SecureAgentLoopRuntime {
  machine: SecureAgentLoopMachine
  task: string
  serverUrl: string
  audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS'
  privacyLevel: 1 | 2 | 3 | 4 | 5
  pendingRecord: PendingExecutionRecord | null
  cancelled: boolean
}

const secureAgentLoops = new Map<`VGL-${string}`, SecureAgentLoopRuntime>()
const ACTION_SETTLE_MS = 350

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function pruneAgentLoops(): void {
  const now = Date.now()
  for (const [key, runtime] of secureAgentLoops) {
    const terminal = ['COMPLETE', 'BLOCKED', 'CANCELLED', 'STEP_LIMIT', 'LOOP_DETECTED'].includes(runtime.machine.status)
    const ended = runtime.machine.endedAtMs ?? runtime.machine.startedAtMs
    if ((terminal && now - ended > 60_000) || now - runtime.machine.startedAtMs > 5 * 60_000) {
      secureAgentLoops.delete(key)
    }
  }
}

function assertNoCompetingLoop(tabId: number): void {
  pruneAgentLoops()
  for (const runtime of secureAgentLoops.values()) {
    if (
      runtime.machine.tabId === tabId
      && (runtime.machine.status === 'RUNNING' || runtime.machine.status === 'WAITING_CONFIRMATION')
    ) {
      throw new Error('another secure agent loop is already active on this tab')
    }
  }
}

async function observeForLoop(tabId: number): Promise<PageCaptureBundle> {
  let lastError: unknown = null
  for (let attempt = 0; attempt < 5; attempt += 1) {
    if (attempt > 0) await sleep(250 * attempt)
    try {
      const bundle = await captureActivePage()
      if (bundle.tabId !== tabId) throw new Error('active tab changed during secure agent loop')
      if (!bundle.frames.some((frame) => frame.isTopFrame)) {
        throw new Error('top-frame observation is not ready')
      }
      return bundle
    } catch (error) {
      lastError = error
    }
  }
  throw new Error(
    `fresh loop observation failed${lastError instanceof Error ? `: ${lastError.message}` : ''}`,
  )
}

function loopResult(runtime: SecureAgentLoopRuntime): SecureAgentLoopResult {
  return publicLoopResult(runtime.machine, runtime.pendingRecord?.public ?? null)
}

async function continueSecureAgentLoop(
  runtime: SecureAgentLoopRuntime,
  confirmation: boolean | null,
): Promise<SecureAgentLoopResult> {
  const machine = runtime.machine
  machine.status = 'RUNNING'

  if (runtime.pendingRecord) {
    if (confirmation !== true) {
      if (confirmation === false) {
        runtime.pendingRecord = null
        runtime.cancelled = true
        markLoopCancelled(machine, 'LOCAL_CONFIRMATION_DENIED', Date.now())
        return loopResult(runtime)
      }
      machine.status = 'WAITING_CONFIRMATION'
      return loopResult(runtime)
    }

    const pending = runtime.pendingRecord
    runtime.pendingRecord = null
    const executed = await executePendingAction(pending, true)
    registerLoopExecution(machine, pending.public.action, executed.elapsed_ms, Date.now())
    appendLoopTrace(machine, {
      stage: 'EXECUTE',
      action: pending.public.action.action,
      targetId: pending.public.target_id,
      proofScore: null,
      residualExposure: null,
      minimizationBasisPoints: null,
      elapsedMs: executed.elapsed_ms,
      note: 'Locally confirmed action executed; a fresh observation is mandatory.',
    })
    await sleep(ACTION_SETTLE_MS)
  }

  while (true) {
    if (runtime.cancelled) {
      markLoopCancelled(machine, 'LOCAL_CANCEL_REQUEST', Date.now())
      return loopResult(runtime)
    }

    const active = await activeTab()
    if (!active.id) throw new Error('active tab is unavailable')
    const continuation = validateLoopContinuation(machine, active.id, Date.now())
    if (!continuation.allowed) {
      markLoopStopped(machine, continuation.status, continuation.reason, Date.now())
      return loopResult(runtime)
    }

    const observeStarted = nowMs()
    const bundle = await observeForLoop(machine.tabId)
    const topFrame = bundle.frames.find((frame) => frame.isTopFrame)
    if (!topFrame) {
      markLoopStopped(machine, 'BLOCKED', 'TOP_FRAME_MISSING_AFTER_OBSERVATION', Date.now())
      return loopResult(runtime)
    }
    const originCheck = validateLoopOrigin(machine, topFrame.origin)
    if (!originCheck.allowed) {
      markLoopStopped(machine, 'BLOCKED', originCheck.reason, Date.now())
      return loopResult(runtime)
    }
    appendLoopTrace(machine, {
      stage: 'OBSERVE',
      action: null,
      targetId: null,
      proofScore: null,
      residualExposure: null,
      minimizationBasisPoints: null,
      elapsedMs: Math.max(0, Math.round(nowMs() - observeStarted)),
      note: `Fresh viewport observation ${bundle.captureId}; raw capture remained local.`,
    })

    if (runtime.cancelled) {
      markLoopCancelled(machine, 'LOCAL_CANCEL_REQUEST', Date.now())
      return loopResult(runtime)
    }

    const privacyStarted = nowMs()
    const preparation = await prepareWithLocalCompanion(
      bundle,
      runtime.task,
      runtime.audienceProfile,
      runtime.privacyLevel,
    )
    appendLoopTrace(machine, {
      stage: 'PRIVACY',
      action: null,
      targetId: null,
      proofScore: preparation.verification.proof_score,
      residualExposure: preparation.payload.residual_identity_exposure,
      minimizationBasisPoints: preparation.minimization.overall_minimization_basis_points,
      elapsedMs: Math.max(0, Math.round(nowMs() - privacyStarted)),
      note: `Network release decision: ${preparation.authorization.payload.decision}.`,
    })

    if (preparation.authorization.payload.decision !== 'ALLOW_NETWORK_RELEASE') {
      markLoopStopped(machine, 'BLOCKED', 'PRIVACY_RELEASE_DENIED', Date.now())
      return loopResult(runtime)
    }

    if (runtime.cancelled) {
      markLoopCancelled(machine, 'LOCAL_CANCEL_REQUEST', Date.now())
      return loopResult(runtime)
    }

    const reasonStarted = nowMs()
    const reasoning = await sendExternally(
      runtime.serverUrl,
      preparation.payload,
      preparation.authorization,
    )
    const proposed = reasoning.plan.actions[0] ?? null
    appendLoopTrace(machine, {
      stage: 'REASON',
      action: proposed?.action ?? null,
      targetId: proposed?.target_id ?? null,
      proofScore: preparation.verification.proof_score,
      residualExposure: preparation.payload.residual_identity_exposure,
      minimizationBasisPoints: preparation.minimization.overall_minimization_basis_points,
      elapsedMs: Math.max(0, Math.round(nowMs() - reasonStarted)),
      note: reasoning.plan.complete
        ? 'Reasoning server marked the task complete.'
        : 'Typed server plan independently validated; only its first action is eligible.',
    })

    if (reasoning.plan.complete) {
      markLoopComplete(machine, Date.now())
      return loopResult(runtime)
    }

    const pending = createPendingExecution(
      executionId(),
      bundle.tabId,
      bundle.frames,
      preparation.payload,
      reasoning,
      Date.now(),
    )
    if (!pending) {
      markLoopStopped(machine, 'BLOCKED', 'NO_EXECUTABLE_FIRST_ACTION', Date.now())
      return loopResult(runtime)
    }

    const evaluation = evaluateLoopAction(machine, pending.public.action, Date.now())
    if (!evaluation.allowed) {
      markLoopStopped(machine, evaluation.status, evaluation.reason, Date.now())
      return loopResult(runtime)
    }

    let eligible = pending
    if (evaluation.requiresConfirmation && !pending.public.requires_confirmation) {
      eligible = {
        ...pending,
        public: {
          ...pending.public,
          requires_confirmation: true,
          action: {
            ...pending.public.action,
            requires_confirmation: true,
          },
        },
      }
    }

    if (evaluation.requiresConfirmation) {
      runtime.pendingRecord = eligible
      machine.status = 'WAITING_CONFIRMATION'
      appendLoopTrace(machine, {
        stage: 'STOP',
        action: eligible.public.action.action,
        targetId: eligible.public.target_id,
        proofScore: null,
        residualExposure: null,
        minimizationBasisPoints: null,
        elapsedMs: 0,
        note: evaluation.reason,
      })
      return loopResult(runtime)
    }

    if (runtime.cancelled) {
      markLoopCancelled(machine, 'LOCAL_CANCEL_REQUEST', Date.now())
      return loopResult(runtime)
    }

    const executed = await executePendingAction(eligible, false)
    registerLoopExecution(machine, eligible.public.action, executed.elapsed_ms, Date.now())
    appendLoopTrace(machine, {
      stage: 'EXECUTE',
      action: eligible.public.action.action,
      targetId: eligible.public.target_id,
      proofScore: null,
      residualExposure: null,
      minimizationBasisPoints: null,
      elapsedMs: executed.elapsed_ms,
      note: 'Low-impact high-confidence action executed locally after fresh live-DOM validation.',
    })

    await sleep(ACTION_SETTLE_MS)
  }
}

async function activeTab(): Promise<chrome.tabs.Tab> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  const tab = tabs[0]
  if (!tab?.id) throw new Error('no active browser tab')
  return tab
}

function statusFromCapability(capability: VisualCapability | undefined): LocalPerceptionStatus {
  if (!capability) return 'UNAVAILABLE'
  if (capability.status === 'READY') return 'READY'
  if (capability.status === 'ERROR') return 'ERROR'
  return 'UNAVAILABLE'
}

function buildCoverage(
  frames: FrameCapture[],
  expectedFrameCount: number,
  failedFrameIds: number[],
  visualStatus: LocalPerceptionStatus,
  capabilities: VisualCapability[],
): CaptureCoverageItem[] {
  const topFrame = frames.find((frame) => frame.isTopFrame)
  const anyTruncated = frames.some((frame) => frame.captureTruncated)
  const domComplete = Boolean(topFrame) && failedFrameIds.length === 0 && !anyTruncated && frames.length === expectedFrameCount
  const domStatus: LocalPerceptionStatus = !topFrame ? 'UNAVAILABLE' : domComplete ? 'READY' : 'PARTIAL'
  const accessibleCount = frames.reduce(
    (total, frame) => total + frame.elements.filter((element) => Boolean(element.accessibleName || element.role)).length,
    0,
  )
  const totalElements = frames.reduce((total, frame) => total + frame.elements.length, 0)
  const accessibilityStatus: LocalPerceptionStatus = !topFrame
    ? 'UNAVAILABLE'
    : totalElements === 0
      ? 'PARTIAL'
      : accessibleCount === totalElements && !anyTruncated
        ? 'READY'
        : 'PARTIAL'
  const byName = new Map(capabilities.map((capability) => [capability.name, capability]))
  return [
    {
      name: 'DOM',
      status: domStatus,
      required: true,
      detail: `${frames.length}/${expectedFrameCount} frame DOM capture(s); failed=${failedFrameIds.length}; truncated=${anyTruncated}`,
    },
    {
      name: 'ACCESSIBILITY',
      status: accessibilityStatus,
      required: true,
      detail: `${accessibleCount}/${totalElements} captured viewport element(s) have role/name semantics`,
    },
    {
      name: 'VISUAL',
      status: visualStatus,
      required: true,
      detail: 'Visible-tab raster was analysed locally before any external release path',
    },
    {
      name: 'TEXT_REGIONS',
      status: statusFromCapability(byName.get('TEXT_REGION_DETECTION')),
      required: true,
      detail: byName.get('TEXT_REGION_DETECTION')?.detail ?? 'visual text-region capability not reported',
    },
    {
      name: 'FACE',
      status: statusFromCapability(byName.get('LEARNED_FACE_DETECTION') ?? byName.get('FACE_DETECTION')),
      required: true,
      detail: (byName.get('LEARNED_FACE_DETECTION') ?? byName.get('FACE_DETECTION'))?.detail ?? 'face capability not reported',
    },
    {
      name: 'QR',
      status: statusFromCapability(byName.get('QR_DETECTION')),
      required: true,
      detail: byName.get('QR_DETECTION')?.detail ?? 'QR capability not reported',
    },
  ]
}

async function captureActivePage(): Promise<PageCaptureBundle> {
  const totalStarted = nowMs()
  const tab = await activeTab()
  const tabId = tab.id as number
  const frameDetails = (await chrome.webNavigation.getAllFrames({ tabId })) ?? []
  const frames: FrameCapture[] = []
  const failedFrameIds: number[] = []
  const domStarted = nowMs()

  for (const frame of frameDetails) {
    try {
      const response = await chrome.tabs.sendMessage<RuntimeResponse>(tabId, { type: 'VG_CAPTURE_FRAME' } satisfies RuntimeRequest, { frameId: frame.frameId })
      if (response.ok) {
        const captured = response.data as FrameCapture
        frames.push({ ...captured, frameId: frame.frameId })
      } else {
        failedFrameIds.push(frame.frameId)
      }
    } catch {
      // Cross-origin/inaccessible frames remain visible to the screenshot model.
      // Absence from DOM capture is represented rather than silently assumed safe.
      failedFrameIds.push(frame.frameId)
    }
  }
  frames.sort((left, right) => left.frameId - right.frameId)
  const frameDomMs = Math.max(0, Math.round(nowMs() - domStarted))

  const screenshotStarted = nowMs()
  const screenshotDataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' })
  const screenshotCaptureMs = Math.max(0, Math.round(nowMs() - screenshotStarted))
  const vision = await runLocalVision(screenshotDataUrl, frames, learnedFaceDetector)
  const expectedFrameCount = frameDetails.length
  const coverage = buildCoverage(frames, expectedFrameCount, failedFrameIds, vision.status, vision.report.capabilities)

  return {
    schema: 'veilgraph.browser-local-capture.v1',
    captureId: captureId(),
    capturedAt: new Date().toISOString(),
    tabId,
    screenshotDataUrl,
    frames,
    expectedFrameCount,
    capturedFrameCount: frames.length,
    failedFrameIds,
    captureTimings: {
      frameDomMs,
      screenshotCaptureMs,
      visualPerceptionMs: vision.report.elapsedMs,
      totalLocalMs: Math.max(0, Math.round(nowMs() - totalStarted)),
    },
    coverage,
    visualPerceptionStatus: vision.status,
    visualPerceptionReport: vision.report,
    visualFindings: vision.findings,
  }
}

function dataUrlToBlob(dataUrl: string): Blob {
  const [header, encoded] = dataUrl.split(',', 2)
  if (!header || encoded === undefined || !header.startsWith('data:image/')) throw new Error('invalid screenshot data URL')
  const mime = header.slice(5).split(';', 1)[0] || 'image/png'
  const raw = atob(encoded)
  const bytes = new Uint8Array(raw.length)
  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index)
  return new Blob([bytes], { type: mime })
}

function snakeCaseCapture(bundle: PageCaptureBundle, task: string, audienceProfile: string, privacyLevel: number): Record<string, unknown> {
  return {
    schema: bundle.schema,
    capture_id: bundle.captureId,
    captured_at: bundle.capturedAt,
    tab_id: bundle.tabId,
    task,
    audience_profile: audienceProfile,
    requested_privacy_level: privacyLevel,
    expected_frame_count: bundle.expectedFrameCount,
    captured_frame_count: bundle.capturedFrameCount,
    failed_frame_ids: bundle.failedFrameIds,
    capture_timings: {
      frame_dom_ms: bundle.captureTimings.frameDomMs,
      screenshot_capture_ms: bundle.captureTimings.screenshotCaptureMs,
      visual_perception_ms: bundle.captureTimings.visualPerceptionMs,
      total_local_ms: bundle.captureTimings.totalLocalMs,
    },
    coverage: bundle.coverage.map((item) => ({
      name: item.name,
      status: item.status,
      required: item.required,
      detail: item.detail,
    })),
    visual_perception_status: bundle.visualPerceptionStatus,
    visual_perception_report: {
      status: bundle.visualPerceptionReport.status,
      model_id: bundle.visualPerceptionReport.modelId,
      backend: bundle.visualPerceptionReport.backend,
      elapsed_ms: bundle.visualPerceptionReport.elapsedMs,
      image_width: bundle.visualPerceptionReport.imageWidth,
      image_height: bundle.visualPerceptionReport.imageHeight,
      finding_count: bundle.visualPerceptionReport.findingCount,
      stage_timings_ms: {
        screenshot_decode_ms: bundle.visualPerceptionReport.stageTimingsMs.screenshotDecodeMs,
        dom_projection_ms: bundle.visualPerceptionReport.stageTimingsMs.domProjectionMs,
        learned_face_ms: bundle.visualPerceptionReport.stageTimingsMs.learnedFaceMs,
        face_detection_ms: bundle.visualPerceptionReport.stageTimingsMs.faceDetectionMs,
        qr_detection_ms: bundle.visualPerceptionReport.stageTimingsMs.qrDetectionMs,
        text_region_ms: bundle.visualPerceptionReport.stageTimingsMs.textRegionMs,
        fusion_ms: bundle.visualPerceptionReport.stageTimingsMs.fusionMs,
      },
      fusion_summary: {
        total_findings: bundle.visualPerceptionReport.fusionSummary.totalFindings,
        corroborated_findings: bundle.visualPerceptionReport.fusionSummary.corroboratedFindings,
        single_source_findings: bundle.visualPerceptionReport.fusionSummary.singleSourceFindings,
        learned_native_face_agreements: bundle.visualPerceptionReport.fusionSummary.learnedNativeFaceAgreements,
      },
      ...(bundle.visualPerceptionReport.learnedModel ? {
        learned_model: {
          model_id: bundle.visualPerceptionReport.learnedModel.modelId,
          model_sha256: bundle.visualPerceptionReport.learnedModel.modelSha256,
          runtime: bundle.visualPerceptionReport.learnedModel.runtime,
          execution_provider: bundle.visualPerceptionReport.learnedModel.executionProvider,
          model_load_ms: bundle.visualPerceptionReport.learnedModel.modelLoadMs,
          inference_ms: bundle.visualPerceptionReport.learnedModel.inferenceMs,
          input_width: bundle.visualPerceptionReport.learnedModel.inputWidth,
          input_height: bundle.visualPerceptionReport.learnedModel.inputHeight,
          detection_count: bundle.visualPerceptionReport.learnedModel.detectionCount,
          fallback_used: bundle.visualPerceptionReport.learnedModel.fallbackUsed,
          ...(bundle.visualPerceptionReport.learnedModel.fallbackReason ? { fallback_reason: bundle.visualPerceptionReport.learnedModel.fallbackReason } : {}),
        },
      } : {}),
      capabilities: bundle.visualPerceptionReport.capabilities.map((capability) => ({
        name: capability.name,
        status: capability.status,
        backend: capability.backend,
        required: capability.required,
        detail: capability.detail,
      })),
    },
    visual_findings: bundle.visualFindings.map((finding) => ({
      finding_id: finding.findingId,
      type: finding.type,
      confidence_basis_points: finding.confidenceBasisPoints,
      bbox: finding.bbox,
      ...(finding.label ? { label: finding.label } : {}),
      ...(finding.provider ? { provider: finding.provider } : {}),
      ...(finding.modalities ? { modalities: finding.modalities } : {}),
      ...(finding.relatedElementIds ? { related_element_ids: finding.relatedElementIds } : {}),
      ...(finding.supportingProviders ? { supporting_providers: finding.supportingProviders } : {}),
      ...(finding.supportCount !== undefined ? { support_count: finding.supportCount } : {}),
      ...(finding.consensus ? { consensus: finding.consensus } : {}),
    })),
    frames: bundle.frames.map((frame) => ({
      frame_id: frame.frameId,
      is_top_frame: frame.isTopFrame,
      origin: frame.origin,
      href: frame.href,
      title: frame.title,
      viewport_width: frame.viewportWidth,
      viewport_height: frame.viewportHeight,
      device_pixel_ratio_basis_points: frame.devicePixelRatioBasisPoints,
      scroll_x: frame.scrollX,
      scroll_y: frame.scrollY,
      document_width: frame.documentWidth,
      document_height: frame.documentHeight,
      eligible_element_count: frame.eligibleElementCount,
      captured_element_count: frame.capturedElementCount,
      capture_truncated: frame.captureTruncated,
      shadow_root_count: frame.shadowRootCount,
      capture_elapsed_ms: frame.captureElapsedMs,
      inaccessible_descendant_frames: frame.inaccessibleDescendantFrames,
      elements: frame.elements.map((element) => ({
        local_id: element.localId,
        tag: element.tag,
        role: element.role,
        accessible_name: element.accessibleName,
        visible_text: element.visibleText,
        ...(element.inputType ? { input_type: element.inputType } : {}),
        ...(element.rawValue !== undefined ? { raw_value: element.rawValue } : {}),
        disabled: element.disabled,
        ...(element.checked !== undefined ? { checked: element.checked } : {}),
        ...(element.selected !== undefined ? { selected: element.selected } : {}),
        bbox: element.bbox,
        privacy_hints: element.privacyHints,
      })),
    })),
  }
}

async function postToLocalCompanion(
  endpoint: 'analyse-capture' | 'prepare-release',
  bundle: PageCaptureBundle,
  task: string,
  audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS',
  privacyLevel: 1 | 2 | 3 | 4 | 5,
): Promise<unknown> {
  const form = new FormData()
  form.append('metadata', JSON.stringify(snakeCaseCapture(bundle, task, audienceProfile, privacyLevel)))
  const screenshot = dataUrlToBlob(bundle.screenshotDataUrl)
  form.append('screenshot', screenshot, screenshot.type === 'image/jpeg' ? 'capture.jpg' : 'capture.png')
  const response = await fetch(`http://127.0.0.1:8000/api/v1/browser/${endpoint}`, {
    method: 'POST',
    body: form,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(`local VeilGraph companion returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 240)}` : ''}`)
  }
  return response.json()
}

async function analyseWithLocalCompanion(
  bundle: PageCaptureBundle,
  task: string,
  audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS',
  privacyLevel: 1 | 2 | 3 | 4 | 5,
): Promise<unknown> {
  return postToLocalCompanion('analyse-capture', bundle, task, audienceProfile, privacyLevel)
}

async function prepareWithLocalCompanion(
  bundle: PageCaptureBundle,
  task: string,
  audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS',
  privacyLevel: 1 | 2 | 3 | 4 | 5,
): Promise<BrowserReleasePreparation> {
  const raw = await postToLocalCompanion('prepare-release', bundle, task, audienceProfile, privacyLevel)
  if (!raw || typeof raw !== 'object') throw new Error('local VeilGraph companion returned an invalid release preparation')
  const prepared = raw as BrowserReleasePreparation
  if (prepared.schema !== 'veilgraph.browser-release-preparation.v1' || !prepared.payload || !prepared.authorization || !prepared.verification) {
    throw new Error('local VeilGraph companion returned an unsupported release preparation schema')
  }

  // An ALLOW decision is never trusted merely because the localhost service
  // returned it. The extension independently verifies the exact payload hash,
  // expiry, mandatory gate summary and Ed25519 signature before exposing it as
  // eligible for the later egress path.
  if (prepared.authorization.payload.decision === 'ALLOW_NETWORK_RELEASE') {
    const verified = await verifyTrustedNetworkAuthorization(prepared.authorization, prepared.payload)
    if (!verified.allowed) throw new Error(`invalid local network authorization: ${verified.reason}`)
  }
  return prepared
}

function normalizeReasoningServerUrl(serverUrl: string): string {
  const parsed = new URL(serverUrl)
  const local = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1'
  if (parsed.username || parsed.password) throw new Error('reasoning-server URL must not contain credentials')
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) {
    throw new Error('reasoning server must use HTTPS, except explicit localhost development')
  }
  if (parsed.hash) throw new Error('reasoning-server URL must not contain a fragment')
  return parsed.toString()
}

async function sendExternally(
  serverUrl: string,
  payload: BrowserReleasePayload,
  authorization: BrowserNetworkAuthorization,
): Promise<BrowserReasoningResponse> {
  const result = await verifyTrustedNetworkAuthorization(authorization, payload)
  if (!result.allowed) throw new Error(`VeilGraph blocked external release: ${result.reason}`)

  const normalizedServerUrl = normalizeReasoningServerUrl(serverUrl)
  const origin = new URL(normalizedServerUrl).origin + '/*'
  if (!(await chrome.permissions.contains({ origins: [origin] }))) {
    const granted = await chrome.permissions.request({ origins: [origin] })
    if (!granted) throw new Error('reasoning-server origin permission was not granted')
  }

  const response = await fetch(normalizedServerUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify({
      schema: 'veilgraph.browser-reasoning-request.v1',
      payload,
      authorization,
    }),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(`reasoning server returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 240)}` : ''}`)
  }
  const raw = await response.json()
  return validateReasoningResponse(raw, payload, authorization.payload.payload_sha256)
}

async function captureFreshFrame(tabId: number, frameId: number): Promise<FrameCapture> {
  const response = await chrome.tabs.sendMessage<RuntimeResponse>(
    tabId,
    { type: 'VG_CAPTURE_FRAME' } satisfies RuntimeRequest,
    { frameId },
  )
  if (!response.ok) throw new Error(`fresh action preflight capture failed: ${response.error}`)

  const captured = response.data as FrameCapture

  // chrome.tabs.sendMessage(..., { frameId }) already addressed this exact
  // browser frame. The content script cannot know Chrome's frame identifier
  // and therefore reports -1. Bind the fresh evidence to the trusted
  // browser-assigned frame identity before security validation.
  return {
    ...captured,
    frameId,
    isTopFrame: frameId === 0,
  }
}

async function executePendingAction(
  record: PendingExecutionRecord,
  confirmed: boolean,
): Promise<LocalActionExecutionResult> {
  const started = nowMs()
  const tab = await activeTab()
  if (!tab.id) throw new Error('active tab is unavailable')
  if (tab.id !== record.tabId) throw new Error('active tab changed after reasoning')

  const currentOrigin = pageOrigin(tab.url)
  let freshFrame: FrameCapture | null = null
  if (record.public.frame_id !== null) {
    freshFrame = await captureFreshFrame(tab.id, record.public.frame_id)
  }

  const preflight = validatePendingExecution(
    record,
    tab.id,
    currentOrigin,
    freshFrame,
    confirmed,
    Date.now(),
  )

  const action = record.public.action
  if (action.action === 'WAIT') {
    await new Promise<void>((resolve) => setTimeout(resolve, action.wait_ms ?? 0))
  } else if (action.action === 'NAVIGATE') {
    if (!action.url) throw new Error('validated NAVIGATE action is missing url')
    await chrome.tabs.update(tab.id, { url: action.url })
  } else {
    const frameId = preflight.frameId
    if (frameId === null) throw new Error('validated local frame action has no frame')
    const response = await chrome.tabs.sendMessage<RuntimeResponse>(
      tab.id,
      {
        type: 'VG_EXECUTE_FRAME_ACTION',
        executionId: record.public.execution_id,
        action,
      } satisfies RuntimeRequest,
      { frameId },
    )
    if (!response.ok) throw new Error(`local content executor blocked action: ${response.error}`)
  }

  return {
    contract: 'LOCAL_ACTION_SECURITY_EXECUTION_V1',
    execution_id: record.public.execution_id,
    status: 'EXECUTED',
    action: action.action,
    tab_id: tab.id,
    frame_id: record.public.frame_id,
    target_id: record.public.target_id,
    confirmed,
    freshness: record.public.target_id ? 'LIVE_NODE_MATCH' : 'NONTARGET_ACTION',
    elapsed_ms: Math.max(0, Math.round(nowMs() - started)),
    next_step: 'RECAPTURE_REQUIRED',
  }
}

chrome.action.onClicked.addListener((tab) => {
  if (tab.id) void chrome.sidePanel.open({ tabId: tab.id })
})

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  const request = message as Partial<RuntimeRequest>
  if (request.type === 'VG_PAIR_LOCAL_COMPANION') {
    void pairLocalCompanion()
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'local companion pairing failed' } satisfies RuntimeResponse))
    return true
  }
  if (request.type === 'VG_CAPTURE_ACTIVE_PAGE') {
    void captureActivePage()
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'page capture failed' } satisfies RuntimeResponse))
    return true
  }
  if (request.type === 'VG_ANALYSE_ACTIVE_PAGE' && typeof request.task === 'string' && request.task.trim()) {
    const audienceProfile = request.audienceProfile
    const privacyLevel = request.privacyLevel
    if (!audienceProfile || !privacyLevel) {
      sendResponse({ ok: false, error: 'missing audience/privacy policy' } satisfies RuntimeResponse)
      return false
    }
    void captureActivePage()
      .then((bundle) => analyseWithLocalCompanion(bundle, request.task as string, audienceProfile, privacyLevel))
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'local analysis failed' } satisfies RuntimeResponse))
    return true
  }
  if (request.type === 'VG_PREPARE_ACTIVE_PAGE' && typeof request.task === 'string' && request.task.trim()) {
    const audienceProfile = request.audienceProfile
    const privacyLevel = request.privacyLevel
    if (!audienceProfile || !privacyLevel) {
      sendResponse({ ok: false, error: 'missing audience/privacy policy' } satisfies RuntimeResponse)
      return false
    }
    void captureActivePage()
      .then((bundle) => prepareWithLocalCompanion(bundle, request.task as string, audienceProfile, privacyLevel))
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'privacy release preparation failed' } satisfies RuntimeResponse))
    return true
  }
  if (
    request.type === 'VG_REASON_ACTIVE_PAGE'
    && typeof request.task === 'string'
    && request.task.trim()
    && typeof request.serverUrl === 'string'
    && request.serverUrl.trim()
  ) {
    const audienceProfile = request.audienceProfile
    const privacyLevel = request.privacyLevel
    if (!audienceProfile || !privacyLevel) {
      sendResponse({ ok: false, error: 'missing audience/privacy policy' } satisfies RuntimeResponse)
      return false
    }
    void captureActivePage()
      .then(async (bundle) => {
        const preparation = await prepareWithLocalCompanion(bundle, request.task as string, audienceProfile, privacyLevel)
        if (preparation.authorization.payload.decision !== 'ALLOW_NETWORK_RELEASE') {
          throw new Error('VeilGraph denied network release; reasoning server was not contacted')
        }
        const reasoning = await sendExternally(
          request.serverUrl as string,
          preparation.payload,
          preparation.authorization,
        )
        const pendingRecord = createPendingExecution(
          executionId(),
          bundle.tabId,
          bundle.frames,
          preparation.payload,
          reasoning,
          Date.now(),
        )
        if (pendingRecord) rememberPendingExecution(pendingRecord)
        return {
          preparation,
          reasoning,
          pendingExecution: pendingRecord?.public ?? null,
        }
      })
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : 'sanitized server reasoning failed',
      } satisfies RuntimeResponse))
    return true
  }
  if (
    request.type === 'VG_EXECUTE_PENDING_ACTION'
    && typeof request.executionId === 'string'
    && request.executionId.startsWith('VGX-')
    && typeof request.confirmed === 'boolean'
  ) {
    if (!trustedSidepanelSender(_sender)) {
      sendResponse({ ok: false, error: 'local execution requires the trusted VeilGraph side panel' } satisfies RuntimeResponse)
      return false
    }

    const executionKey = request.executionId as `VGX-${string}`
    const record = pendingExecutions.get(executionKey)
    if (!record) {
      sendResponse({ ok: false, error: 'pending action is missing, expired, consumed, or lost after service-worker restart' } satisfies RuntimeResponse)
      return false
    }

    // Consume before mutation. A failed execution must be re-planned, never
    // blindly retried, which prevents duplicate clicks/submissions.
    pendingExecutions.delete(executionKey)
    void executePendingAction(record, request.confirmed)
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : 'local action security validator blocked execution',
      } satisfies RuntimeResponse))
    return true
  }
  if (
    request.type === 'VG_RUN_SECURE_AGENT_LOOP'
    && typeof request.loopId === 'string'
    && request.loopId.startsWith('VGL-')
    && typeof request.task === 'string'
    && request.task.trim()
    && typeof request.serverUrl === 'string'
    && request.serverUrl.trim()
  ) {
    if (!trustedSidepanelSender(_sender)) {
      sendResponse({ ok: false, error: 'secure agent loop requires the trusted VeilGraph side panel' } satisfies RuntimeResponse)
      return false
    }
    const audienceProfile = request.audienceProfile
    const privacyLevel = request.privacyLevel
    if (!audienceProfile || !privacyLevel) {
      sendResponse({ ok: false, error: 'missing audience/privacy policy' } satisfies RuntimeResponse)
      return false
    }

    void activeTab()
      .then(async (tab) => {
        if (!tab.id) throw new Error('active tab is unavailable')
        assertNoCompetingLoop(tab.id)
        const machine = beginSecureAgentLoop(
          request.loopId as `VGL-${string}`,
          tab.id,
          request.task as string,
          typeof request.maxSteps === 'number' ? request.maxSteps : 6,
          Date.now(),
        )
        const runtime: SecureAgentLoopRuntime = {
          machine,
          task: request.task as string,
          serverUrl: request.serverUrl as string,
          audienceProfile,
          privacyLevel,
          pendingRecord: null,
          cancelled: false,
        }
        secureAgentLoops.set(machine.loopId, runtime)
        try {
          return await continueSecureAgentLoop(runtime, null)
        } catch (error) {
          markLoopStopped(
            runtime.machine,
            'BLOCKED',
            error instanceof Error ? error.message : 'secure agent loop failed',
            Date.now(),
          )
          throw error
        }
      })
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : 'secure agent loop failed',
      } satisfies RuntimeResponse))
    return true
  }
  if (
    request.type === 'VG_RESUME_SECURE_AGENT_LOOP'
    && typeof request.loopId === 'string'
    && request.loopId.startsWith('VGL-')
    && typeof request.confirmed === 'boolean'
  ) {
    if (!trustedSidepanelSender(_sender)) {
      sendResponse({ ok: false, error: 'secure agent loop resume requires the trusted VeilGraph side panel' } satisfies RuntimeResponse)
      return false
    }
    const key = request.loopId as `VGL-${string}`
    const runtime = secureAgentLoops.get(key)
    if (!runtime) {
      sendResponse({ ok: false, error: 'secure agent loop is missing, expired, or lost after service-worker restart' } satisfies RuntimeResponse)
      return false
    }
    if (runtime.machine.status !== 'WAITING_CONFIRMATION' || !runtime.pendingRecord) {
      sendResponse({ ok: false, error: 'secure agent loop is not waiting for confirmation' } satisfies RuntimeResponse)
      return false
    }

    void continueSecureAgentLoop(runtime, request.confirmed)
      .then((data) => sendResponse({ ok: true, data } satisfies RuntimeResponse))
      .catch((error: unknown) => {
        markLoopStopped(runtime.machine, 'BLOCKED', error instanceof Error ? error.message : 'resume failed', Date.now())
        sendResponse({ ok: false, error: error instanceof Error ? error.message : 'secure agent loop resume failed' } satisfies RuntimeResponse)
      })
    return true
  }
  if (
    request.type === 'VG_CANCEL_SECURE_AGENT_LOOP'
    && typeof request.loopId === 'string'
    && request.loopId.startsWith('VGL-')
  ) {
    if (!trustedSidepanelSender(_sender)) {
      sendResponse({ ok: false, error: 'secure agent loop cancellation requires the trusted VeilGraph side panel' } satisfies RuntimeResponse)
      return false
    }
    const key = request.loopId as `VGL-${string}`
    const runtime = secureAgentLoops.get(key)
    if (!runtime) {
      sendResponse({ ok: false, error: 'secure agent loop is missing, expired, or already finished' } satisfies RuntimeResponse)
      return false
    }
    runtime.cancelled = true
    if (runtime.machine.status === 'WAITING_CONFIRMATION') {
      runtime.pendingRecord = null
      markLoopCancelled(runtime.machine, 'LOCAL_CANCEL_REQUEST', Date.now())
    }
    sendResponse({ ok: true, data: loopResult(runtime) } satisfies RuntimeResponse)
    return false
  }
  if (request.type === 'VG_GET_STATUS') {
    sendResponse({
      ok: true,
      data: {
        product: 'VeilGraph',
        networkReleaseGate: 'FAIL_CLOSED',
        perceptionContract: 'VIEWPORT_BOUND_V2',
        minimizationContract: 'TASK_MINIMIZATION_V1',
        reasoningContract: 'SANITIZED_REASONING_ACTION_V1',
        localActionContract: 'LOCAL_ACTION_SECURITY_EXECUTION_V1',
        agentLoopContract: 'SECURE_AGENT_LOOP_V1',
      },
    } satisfies RuntimeResponse)
  }
  return false
})

// SECURE_AGENT_LOOP_V1 preserves the same fail-closed release boundary for
// every iteration. Only one locally revalidated action may execute before a
// completely fresh observe → sanitize → reason cycle.
