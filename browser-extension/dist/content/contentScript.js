import { captureFrame } from './domCapture.js';
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    const request = message;
    if (request.type !== 'VG_CAPTURE_FRAME')
        return;
    try {
        sendResponse({ ok: true, data: captureFrame() });
    }
    catch (error) {
        sendResponse({ ok: false, error: error instanceof Error ? error.message : 'frame capture failed' });
    }
});
