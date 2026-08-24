import type { RuntimeRequest, RuntimeResponse } from '../common/protocol.js'
import { executeFrameAction } from './actionExecutor.js'
import { captureFrame } from './domCapture.js'

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = message as Partial<RuntimeRequest>

  if (request.type === 'VG_CAPTURE_FRAME') {
    try {
      sendResponse({ ok: true, data: captureFrame() } satisfies RuntimeResponse)
    } catch (error) {
      sendResponse({ ok: false, error: error instanceof Error ? error.message : 'frame capture failed' } satisfies RuntimeResponse)
    }
    return
  }

  if (
    request.type === 'VG_EXECUTE_FRAME_ACTION'
    && typeof request.executionId === 'string'
    && request.executionId.startsWith('VGX-')
    && request.action
  ) {
    if (sender.id !== chrome.runtime.id || sender.tab) {
      sendResponse({ ok: false, error: 'untrusted action-execution sender' } satisfies RuntimeResponse)
      return
    }
    try {
      const result = executeFrameAction(request.executionId, request.action)
      sendResponse({ ok: true, data: result } satisfies RuntimeResponse)
    } catch (error) {
      sendResponse({ ok: false, error: error instanceof Error ? error.message : 'local frame action blocked' } satisfies RuntimeResponse)
    }
  }
})
