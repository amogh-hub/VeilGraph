import type {
  BrowserNetworkAuthorization,
  BrowserReleasePayload,
  FrameCapture,
  PageCaptureBundle,
  RuntimeRequest,
  RuntimeResponse,
} from '../common/protocol.js'
import { runLocalVision } from '../perception/localVision.js'
import { verifyNetworkAuthorization } from '../security/releaseGate.js'

async function activeTab(): Promise<chrome.tabs.Tab> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  const tab = tabs[0]
  if (!tab?.id) throw new Error('no active browser tab')
  return tab
}

async function captureActivePage(): Promise<PageCaptureBundle> {
  const tab = await activeTab()
  const tabId = tab.id as number
  const frameDetails = (await chrome.webNavigation.getAllFrames({ tabId })) ?? []
  const frames: FrameCapture[] = []

  for (const frame of frameDetails) {
    try {
      const response = await chrome.tabs.sendMessage<RuntimeResponse>(tabId, { type: 'VG_CAPTURE_FRAME' } satisfies RuntimeRequest, { frameId: frame.frameId })
      if (response.ok) {
        const captured = response.data as FrameCapture
        frames.push({ ...captured, frameId: frame.frameId })
      }
    } catch {
      // Cross-origin/inaccessible frames remain visible to the screenshot model.
      // Absence from DOM capture is represented rather than silently assumed safe.
    }
  }

  const screenshotDataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' })
  const vision = await runLocalVision(screenshotDataUrl)

  return {
    schema: 'veilgraph.browser-local-capture.v1',
    capturedAt: new Date().toISOString(),
    tabId,
    screenshotDataUrl,
    frames,
    visualPerceptionStatus: vision.status,
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
    captured_at: bundle.capturedAt,
    tab_id: bundle.tabId,
    task,
    audience_profile: audienceProfile,
    requested_privacy_level: privacyLevel,
    visual_perception_status: bundle.visualPerceptionStatus,
    visual_findings: bundle.visualFindings.map((finding) => ({
      finding_id: finding.findingId,
      type: finding.type,
      confidence_basis_points: finding.confidenceBasisPoints,
      bbox: finding.bbox,
      ...(finding.label ? { label: finding.label } : {}),
    })),
    frames: bundle.frames.map((frame) => ({
      frame_id: frame.frameId,
      is_top_frame: frame.isTopFrame,
      origin: frame.origin,
      href: frame.href,
      title: frame.title,
      viewport_width: frame.viewportWidth,
      viewport_height: frame.viewportHeight,
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

async function analyseWithLocalCompanion(
  bundle: PageCaptureBundle,
  task: string,
  audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS',
  privacyLevel: 1 | 2 | 3 | 4 | 5,
): Promise<unknown> {
  const form = new FormData()
  form.append('metadata', JSON.stringify(snakeCaseCapture(bundle, task, audienceProfile, privacyLevel)))
  const screenshot = dataUrlToBlob(bundle.screenshotDataUrl)
  form.append('screenshot', screenshot, screenshot.type === 'image/jpeg' ? 'capture.jpg' : 'capture.png')
  const response = await fetch('http://127.0.0.1:8000/api/v1/browser/analyse-capture', {
    method: 'POST',
    body: form,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) throw new Error(`local VeilGraph companion returned HTTP ${response.status}`)
  return response.json()
}

async function sendExternally(
  serverUrl: string,
  payload: BrowserReleasePayload,
  authorization: BrowserNetworkAuthorization,
): Promise<unknown> {
  const result = await verifyNetworkAuthorization(authorization, payload)
  if (!result.allowed) throw new Error(`VeilGraph blocked external release: ${result.reason}`)

  const origin = new URL(serverUrl).origin + '/*'
  if (!(await chrome.permissions.contains({ origins: [origin] }))) {
    const granted = await chrome.permissions.request({ origins: [origin] })
    if (!granted) throw new Error('reasoning-server origin permission was not granted')
  }

  const response = await fetch(serverUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify({ payload, authorization }),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) throw new Error(`reasoning server returned HTTP ${response.status}`)
  return response.json()
}

chrome.action.onClicked.addListener((tab) => {
  if (tab.id) void chrome.sidePanel.open({ tabId: tab.id })
})

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  const request = message as Partial<RuntimeRequest>
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
  if (request.type === 'VG_GET_STATUS') {
    sendResponse({ ok: true, data: { product: 'VeilGraph', networkReleaseGate: 'FAIL_CLOSED' } } satisfies RuntimeResponse)
  }
  return false
})

// Intentionally not exported through the runtime message surface yet. External
// egress will be wired only after the local privacy compiler + Browser Red Team
// produce a trusted signed authorization object.
void sendExternally
