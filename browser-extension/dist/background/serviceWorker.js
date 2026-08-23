import { runLocalVision } from '../perception/localVision.js';
import { verifyTrustedNetworkAuthorization } from '../security/releaseGate.js';
import { pairLocalCompanion } from '../security/pairing.js';
async function activeTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    if (!tab?.id)
        throw new Error('no active browser tab');
    return tab;
}
async function captureActivePage() {
    const tab = await activeTab();
    const tabId = tab.id;
    const frameDetails = (await chrome.webNavigation.getAllFrames({ tabId })) ?? [];
    const frames = [];
    for (const frame of frameDetails) {
        try {
            const response = await chrome.tabs.sendMessage(tabId, { type: 'VG_CAPTURE_FRAME' }, { frameId: frame.frameId });
            if (response.ok) {
                const captured = response.data;
                frames.push({ ...captured, frameId: frame.frameId });
            }
        }
        catch {
            // Cross-origin/inaccessible frames remain visible to the screenshot model.
            // Absence from DOM capture is represented rather than silently assumed safe.
        }
    }
    const screenshotDataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
    const vision = await runLocalVision(screenshotDataUrl, frames);
    return {
        schema: 'veilgraph.browser-local-capture.v1',
        capturedAt: new Date().toISOString(),
        tabId,
        screenshotDataUrl,
        frames,
        visualPerceptionStatus: vision.status,
        visualPerceptionReport: vision.report,
        visualFindings: vision.findings,
    };
}
function dataUrlToBlob(dataUrl) {
    const [header, encoded] = dataUrl.split(',', 2);
    if (!header || encoded === undefined || !header.startsWith('data:image/'))
        throw new Error('invalid screenshot data URL');
    const mime = header.slice(5).split(';', 1)[0] || 'image/png';
    const raw = atob(encoded);
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1)
        bytes[index] = raw.charCodeAt(index);
    return new Blob([bytes], { type: mime });
}
function snakeCaseCapture(bundle, task, audienceProfile, privacyLevel) {
    return {
        schema: bundle.schema,
        captured_at: bundle.capturedAt,
        tab_id: bundle.tabId,
        task,
        audience_profile: audienceProfile,
        requested_privacy_level: privacyLevel,
        visual_perception_status: bundle.visualPerceptionStatus,
        visual_perception_report: {
            status: bundle.visualPerceptionReport.status,
            model_id: bundle.visualPerceptionReport.modelId,
            backend: bundle.visualPerceptionReport.backend,
            elapsed_ms: bundle.visualPerceptionReport.elapsedMs,
            image_width: bundle.visualPerceptionReport.imageWidth,
            image_height: bundle.visualPerceptionReport.imageHeight,
            finding_count: bundle.visualPerceptionReport.findingCount,
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
    };
}
async function postToLocalCompanion(endpoint, bundle, task, audienceProfile, privacyLevel) {
    const form = new FormData();
    form.append('metadata', JSON.stringify(snakeCaseCapture(bundle, task, audienceProfile, privacyLevel)));
    const screenshot = dataUrlToBlob(bundle.screenshotDataUrl);
    form.append('screenshot', screenshot, screenshot.type === 'image/jpeg' ? 'capture.jpg' : 'capture.png');
    const response = await fetch(`http://127.0.0.1:8000/api/v1/browser/${endpoint}`, {
        method: 'POST',
        body: form,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
    });
    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        throw new Error(`local VeilGraph companion returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 240)}` : ''}`);
    }
    return response.json();
}
async function analyseWithLocalCompanion(bundle, task, audienceProfile, privacyLevel) {
    return postToLocalCompanion('analyse-capture', bundle, task, audienceProfile, privacyLevel);
}
async function prepareWithLocalCompanion(bundle, task, audienceProfile, privacyLevel) {
    const raw = await postToLocalCompanion('prepare-release', bundle, task, audienceProfile, privacyLevel);
    if (!raw || typeof raw !== 'object')
        throw new Error('local VeilGraph companion returned an invalid release preparation');
    const prepared = raw;
    if (prepared.schema !== 'veilgraph.browser-release-preparation.v1' || !prepared.payload || !prepared.authorization || !prepared.verification) {
        throw new Error('local VeilGraph companion returned an unsupported release preparation schema');
    }
    // An ALLOW decision is never trusted merely because the localhost service
    // returned it. The extension independently verifies the exact payload hash,
    // expiry, mandatory gate summary and Ed25519 signature before exposing it as
    // eligible for the later egress path.
    if (prepared.authorization.payload.decision === 'ALLOW_NETWORK_RELEASE') {
        const verified = await verifyTrustedNetworkAuthorization(prepared.authorization, prepared.payload);
        if (!verified.allowed)
            throw new Error(`invalid local network authorization: ${verified.reason}`);
    }
    return prepared;
}
async function sendExternally(serverUrl, payload, authorization) {
    const result = await verifyTrustedNetworkAuthorization(authorization, payload);
    if (!result.allowed)
        throw new Error(`VeilGraph blocked external release: ${result.reason}`);
    const origin = new URL(serverUrl).origin + '/*';
    if (!(await chrome.permissions.contains({ origins: [origin] }))) {
        const granted = await chrome.permissions.request({ origins: [origin] });
        if (!granted)
            throw new Error('reasoning-server origin permission was not granted');
    }
    const response = await fetch(serverUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({ payload, authorization }),
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
    });
    if (!response.ok)
        throw new Error(`reasoning server returned HTTP ${response.status}`);
    return response.json();
}
chrome.action.onClicked.addListener((tab) => {
    if (tab.id)
        void chrome.sidePanel.open({ tabId: tab.id });
});
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    const request = message;
    if (request.type === 'VG_PAIR_LOCAL_COMPANION') {
        void pairLocalCompanion()
            .then((data) => sendResponse({ ok: true, data }))
            .catch((error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'local companion pairing failed' }));
        return true;
    }
    if (request.type === 'VG_CAPTURE_ACTIVE_PAGE') {
        void captureActivePage()
            .then((data) => sendResponse({ ok: true, data }))
            .catch((error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'page capture failed' }));
        return true;
    }
    if (request.type === 'VG_ANALYSE_ACTIVE_PAGE' && typeof request.task === 'string' && request.task.trim()) {
        const audienceProfile = request.audienceProfile;
        const privacyLevel = request.privacyLevel;
        if (!audienceProfile || !privacyLevel) {
            sendResponse({ ok: false, error: 'missing audience/privacy policy' });
            return false;
        }
        void captureActivePage()
            .then((bundle) => analyseWithLocalCompanion(bundle, request.task, audienceProfile, privacyLevel))
            .then((data) => sendResponse({ ok: true, data }))
            .catch((error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'local analysis failed' }));
        return true;
    }
    if (request.type === 'VG_PREPARE_ACTIVE_PAGE' && typeof request.task === 'string' && request.task.trim()) {
        const audienceProfile = request.audienceProfile;
        const privacyLevel = request.privacyLevel;
        if (!audienceProfile || !privacyLevel) {
            sendResponse({ ok: false, error: 'missing audience/privacy policy' });
            return false;
        }
        void captureActivePage()
            .then((bundle) => prepareWithLocalCompanion(bundle, request.task, audienceProfile, privacyLevel))
            .then((data) => sendResponse({ ok: true, data }))
            .catch((error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : 'privacy release preparation failed' }));
        return true;
    }
    if (request.type === 'VG_GET_STATUS') {
        sendResponse({ ok: true, data: { product: 'VeilGraph', networkReleaseGate: 'FAIL_CLOSED' } });
    }
    return false;
});
// Intentionally not exported through the runtime message surface yet. External
// egress will be wired only after the local privacy compiler + Browser Red Team
// produce a trusted signed authorization object.
void sendExternally;
