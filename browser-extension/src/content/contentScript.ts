import type { RuntimeRequest, RuntimeResponse } from '../common/protocol.js'
import { captureFrame } from './domCapture.js'

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  const request = message as Partial<RuntimeRequest>
  if (request.type !== 'VG_CAPTURE_FRAME') return
  try {
    sendResponse({ ok: true, data: captureFrame() } satisfies RuntimeResponse)
  } catch (error) {
    sendResponse({ ok: false, error: error instanceof Error ? error.message : 'frame capture failed' } satisfies RuntimeResponse)
  }
})
