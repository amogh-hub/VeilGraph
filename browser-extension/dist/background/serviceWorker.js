import { runLocalVision } from '../perception/localVision.js';
import { createOnnxLearnedFaceDetector } from '../perception/learnedFaceModel.js';
// The build copies this pinned ONNX Runtime Web module into dist/vendor.
// @ts-ignore -- generated vendor asset intentionally lives outside src/.
import * as ortRuntime from '../vendor/onnxruntime/ort.webgpu.bundle.min.mjs';
import { verifyTrustedNetworkAuthorization } from '../security/releaseGate.js';
import { pairLocalCompanion } from '../security/pairing.js';
import { validateReasoningResponse } from '../security/actionPlan.js';
const learnedFaceDetector = createOnnxLearnedFaceDetector(ortRuntime, (path) => chrome.runtime.getURL(path));
function nowMs() {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
}
function captureId() {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    return `VGC-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()}`;
}
async function activeTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    if (!tab?.id)
        throw new Error('no active browser tab');
    return tab;
}
function statusFromCapability(capability) {
    if (!capability)
        return 'UNAVAILABLE';
    if (capability.status === 'READY')
        return 'READY';
    if (capability.status === 'ERROR')
        return 'ERROR';
    return 'UNAVAILABLE';
}
function buildCoverage(frames, expectedFrameCount, failedFrameIds, visualStatus, capabilities) {
    const topFrame = frames.find((frame) => frame.isTopFrame);
    const anyTruncated = frames.some((frame) => frame.captureTruncated);
    const domComplete = Boolean(topFrame) && failedFrameIds.length === 0 && !anyTruncated && frames.length === expectedFrameCount;
    const domStatus = !topFrame ? 'UNAVAILABLE' : domComplete ? 'READY' : 'PARTIAL';
    const accessibleCount = frames.reduce((total, frame) => total + frame.elements.filter((element) => Boolean(element.accessibleName || element.role)).length, 0);
    const totalElements = frames.reduce((total, frame) => total + frame.elements.length, 0);
    const accessibilityStatus = !topFrame
        ? 'UNAVAILABLE'
        : totalElements === 0
            ? 'PARTIAL'
            : accessibleCount === totalElements && !anyTruncated
                ? 'READY'
                : 'PARTIAL';
    const byName = new Map(capabilities.map((capability) => [capability.name, capability]));
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
    ];
}
async function captureActivePage() {
    const totalStarted = nowMs();
    const tab = await activeTab();
    const tabId = tab.id;
    const frameDetails = (await chrome.webNavigation.getAllFrames({ tabId })) ?? [];
    const frames = [];
    const failedFrameIds = [];
    const domStarted = nowMs();
    for (const frame of frameDetails) {
        try {
            const response = await chrome.tabs.sendMessage(tabId, { type: 'VG_CAPTURE_FRAME' }, { frameId: frame.frameId });
            if (response.ok) {
                const captured = response.data;
                frames.push({ ...captured, frameId: frame.frameId });
            }
            else {
                failedFrameIds.push(frame.frameId);
            }
        }
        catch {
            // Cross-origin/inaccessible frames remain visible to the screenshot model.
            // Absence from DOM capture is represented rather than silently assumed safe.
            failedFrameIds.push(frame.frameId);
        }
    }
    frames.sort((left, right) => left.frameId - right.frameId);
    const frameDomMs = Math.max(0, Math.round(nowMs() - domStarted));
    const screenshotStarted = nowMs();
    const screenshotDataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
    const screenshotCaptureMs = Math.max(0, Math.round(nowMs() - screenshotStarted));
    const vision = await runLocalVision(screenshotDataUrl, frames, learnedFaceDetector);
    const expectedFrameCount = frameDetails.length;
    const coverage = buildCoverage(frames, expectedFrameCount, failedFrameIds, vision.status, vision.report.capabilities);
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
function normalizeReasoningServerUrl(serverUrl) {
    const parsed = new URL(serverUrl);
    const local = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1';
    if (parsed.username || parsed.password)
        throw new Error('reasoning-server URL must not contain credentials');
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && local)) {
        throw new Error('reasoning server must use HTTPS, except explicit localhost development');
    }
    if (parsed.hash)
        throw new Error('reasoning-server URL must not contain a fragment');
    return parsed.toString();
}
async function sendExternally(serverUrl, payload, authorization) {
    const result = await verifyTrustedNetworkAuthorization(authorization, payload);
    if (!result.allowed)
        throw new Error(`VeilGraph blocked external release: ${result.reason}`);
    const normalizedServerUrl = normalizeReasoningServerUrl(serverUrl);
    const origin = new URL(normalizedServerUrl).origin + '/*';
    if (!(await chrome.permissions.contains({ origins: [origin] }))) {
        const granted = await chrome.permissions.request({ origins: [origin] });
        if (!granted)
            throw new Error('reasoning-server origin permission was not granted');
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
    });
    if (!response.ok) {
        const detail = await response.text().catch(() => '');
        throw new Error(`reasoning server returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 240)}` : ''}`);
    }
    const raw = await response.json();
    return validateReasoningResponse(raw, payload, authorization.payload.payload_sha256);
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
    if (request.type === 'VG_REASON_ACTIVE_PAGE'
        && typeof request.task === 'string'
        && request.task.trim()
        && typeof request.serverUrl === 'string'
        && request.serverUrl.trim()) {
        const audienceProfile = request.audienceProfile;
        const privacyLevel = request.privacyLevel;
        if (!audienceProfile || !privacyLevel) {
            sendResponse({ ok: false, error: 'missing audience/privacy policy' });
            return false;
        }
        void captureActivePage()
            .then(async (bundle) => {
            const preparation = await prepareWithLocalCompanion(bundle, request.task, audienceProfile, privacyLevel);
            if (preparation.authorization.payload.decision !== 'ALLOW_NETWORK_RELEASE') {
                throw new Error('VeilGraph denied network release; reasoning server was not contacted');
            }
            const reasoning = await sendExternally(request.serverUrl, preparation.payload, preparation.authorization);
            return { preparation, reasoning };
        })
            .then((data) => sendResponse({ ok: true, data }))
            .catch((error) => sendResponse({
            ok: false,
            error: error instanceof Error ? error.message : 'sanitized server reasoning failed',
        }));
        return true;
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
            },
        });
    }
    return false;
});
// External egress is reachable only through VG_REASON_ACTIVE_PAGE, after the
// extension independently verifies a signed ALLOW_NETWORK_RELEASE authorization.
// Returned server plans remain plans; local action execution is a later boundary.
