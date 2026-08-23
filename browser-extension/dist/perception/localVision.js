const MAX_TEXT_REGIONS = 220;
const FACE_SCORE_BP = 9000;
const QR_SCORE_BP = 9800;
function nowMs() {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
}
function clampBp(value) {
    return Math.max(0, Math.min(10_000, Math.round(value)));
}
function rectToBasisPoints(rect, width, height) {
    return [
        clampBp((rect.x / Math.max(width, 1)) * 10_000),
        clampBp((rect.y / Math.max(height, 1)) * 10_000),
        clampBp(((rect.x + rect.width) / Math.max(width, 1)) * 10_000),
        clampBp(((rect.y + rect.height) / Math.max(height, 1)) * 10_000),
    ];
}
function iou(a, b) {
    const x0 = Math.max(a[0], b[0]);
    const y0 = Math.max(a[1], b[1]);
    const x1 = Math.min(a[2], b[2]);
    const y1 = Math.min(a[3], b[3]);
    const intersection = Math.max(0, x1 - x0) * Math.max(0, y1 - y0);
    if (intersection <= 0)
        return 0;
    const areaA = Math.max(0, a[2] - a[0]) * Math.max(0, a[3] - a[1]);
    const areaB = Math.max(0, b[2] - b[0]) * Math.max(0, b[3] - b[1]);
    return intersection / Math.max(1, areaA + areaB - intersection);
}
function deduplicate(findings) {
    const sorted = [...findings].sort((left, right) => right.confidenceBasisPoints - left.confidenceBasisPoints);
    const kept = [];
    for (const finding of sorted) {
        if (kept.some((existing) => existing.type === finding.type && iou(existing.bbox, finding.bbox) >= 0.72))
            continue;
        kept.push(finding);
    }
    return kept;
}
async function decodeScreenshot(dataUrl) {
    if (!dataUrl.startsWith('data:image/'))
        throw new Error('visual perception received a non-image data URL');
    const response = await fetch(dataUrl);
    if (!response.ok)
        throw new Error(`failed to decode screenshot (${response.status})`);
    return createImageBitmap(await response.blob());
}
function projectDomSensitiveRegions(frames) {
    const topFrame = frames.find((frame) => frame.isTopFrame);
    if (!topFrame)
        return [];
    const sensitiveHints = new Set([
        'credential',
        'email',
        'phone',
        'person_name',
        'government_identifier',
        'location',
        'financial',
        'quasi_identifier',
        'health',
    ]);
    const findings = [];
    for (const element of topFrame.elements) {
        const matchedHints = element.privacyHints.filter((hint) => sensitiveHints.has(hint));
        const isPassword = (element.inputType ?? '').toLowerCase() === 'password' || matchedHints.includes('credential');
        if (!isPassword && matchedHints.length === 0)
            continue;
        findings.push({
            findingId: `dom-${element.localId}`,
            type: isPassword ? 'PASSWORD_FIELD' : 'SENSITIVE_REGION',
            confidenceBasisPoints: isPassword ? 10_000 : 9600,
            bbox: element.bbox,
            label: matchedHints.join(',') || 'password',
            provider: 'dom-visual-fusion',
        });
    }
    return findings;
}
async function nativeBarcodeFindings(bitmap) {
    const scope = globalThis;
    if (!scope.BarcodeDetector) {
        return {
            findings: [],
            capability: { name: 'QR_DETECTION', status: 'UNAVAILABLE', backend: 'shape-detection-api', required: true, detail: 'BarcodeDetector API is unavailable' },
        };
    }
    try {
        const detector = new scope.BarcodeDetector({ formats: ['qr_code'] });
        const results = await detector.detect(bitmap);
        return {
            findings: results.map((result, index) => ({
                findingId: `qr-${index}`,
                type: 'QR_CODE',
                confidenceBasisPoints: QR_SCORE_BP,
                bbox: rectToBasisPoints(result.boundingBox, bitmap.width, bitmap.height),
                ...(result.rawValue ? { label: result.rawValue.slice(0, 96) } : {}),
                provider: 'shape-detection-api',
            })),
            capability: { name: 'QR_DETECTION', status: 'READY', backend: 'shape-detection-api', required: true, detail: 'Local BarcodeDetector QR inference available' },
        };
    }
    catch (error) {
        return {
            findings: [],
            capability: { name: 'QR_DETECTION', status: 'ERROR', backend: 'shape-detection-api', required: true, detail: error instanceof Error ? error.message : 'QR detection failed' },
        };
    }
}
async function nativeFaceFindings(bitmap) {
    const scope = globalThis;
    if (!scope.FaceDetector) {
        return {
            findings: [],
            capability: { name: 'FACE_DETECTION', status: 'UNAVAILABLE', backend: 'shape-detection-api', required: true, detail: 'FaceDetector API is unavailable; local companion fallback remains mandatory' },
        };
    }
    try {
        const detector = new scope.FaceDetector({ fastMode: true, maxDetectedFaces: 64 });
        const results = await detector.detect(bitmap);
        return {
            findings: results.map((result, index) => ({
                findingId: `face-${index}`,
                type: 'FACE',
                confidenceBasisPoints: FACE_SCORE_BP,
                bbox: rectToBasisPoints(result.boundingBox, bitmap.width, bitmap.height),
                provider: 'shape-detection-api',
            })),
            capability: { name: 'FACE_DETECTION', status: 'READY', backend: 'shape-detection-api', required: true, detail: 'Local FaceDetector inference available' },
        };
    }
    catch (error) {
        return {
            findings: [],
            capability: { name: 'FACE_DETECTION', status: 'ERROR', backend: 'shape-detection-api', required: true, detail: error instanceof Error ? error.message : 'face detection failed' },
        };
    }
}
async function nativeTextFindings(bitmap) {
    const scope = globalThis;
    if (!scope.TextDetector)
        return canvasTextRegionFindings(bitmap);
    try {
        const detector = new scope.TextDetector();
        const results = await detector.detect(bitmap);
        return {
            findings: results.slice(0, MAX_TEXT_REGIONS).map((result, index) => ({
                findingId: `text-${index}`,
                type: 'TEXT_REGION',
                confidenceBasisPoints: 9000,
                bbox: rectToBasisPoints(result.boundingBox, bitmap.width, bitmap.height),
                provider: 'shape-detection-api',
            })),
            capability: { name: 'TEXT_REGION_DETECTION', status: 'READY', backend: 'shape-detection-api', required: true, detail: 'Local TextDetector visual text-region inference available' },
        };
    }
    catch {
        return canvasTextRegionFindings(bitmap);
    }
}
async function canvasTextRegionFindings(bitmap) {
    try {
        const maxWidth = 960;
        const scale = Math.min(1, maxWidth / Math.max(bitmap.width, 1));
        const width = Math.max(1, Math.round(bitmap.width * scale));
        const height = Math.max(1, Math.round(bitmap.height * scale));
        const canvas = new OffscreenCanvas(width, height);
        const context = canvas.getContext('2d', { willReadFrequently: true });
        if (!context)
            throw new Error('2D canvas context unavailable');
        context.drawImage(bitmap, 0, 0, width, height);
        const { data } = context.getImageData(0, 0, width, height);
        const rowEdgeCounts = new Uint32Array(height);
        const rowMinX = new Int32Array(height);
        const rowMaxX = new Int32Array(height);
        rowMinX.fill(width);
        rowMaxX.fill(-1);
        const luminance = (offset) => Math.round(0.2126 * data[offset] + 0.7152 * data[offset + 1] + 0.0722 * data[offset + 2]);
        for (let y = 1; y < height; y += 1) {
            let previous = luminance((y * width) * 4);
            for (let x = 1; x < width; x += 1) {
                const offset = (y * width + x) * 4;
                const current = luminance(offset);
                const above = luminance(((y - 1) * width + x) * 4);
                const edge = Math.max(Math.abs(current - previous), Math.abs(current - above));
                previous = current;
                if (edge < 52)
                    continue;
                rowEdgeCounts[y] = rowEdgeCounts[y] + 1;
                rowMinX[y] = Math.min(rowMinX[y], x);
                rowMaxX[y] = Math.max(rowMaxX[y], x);
            }
        }
        const threshold = Math.max(8, Math.round(width * 0.012));
        const regions = [];
        let start = -1;
        let minX = width;
        let maxX = -1;
        let quietRows = 0;
        const close = (end) => {
            if (start < 0 || maxX < minX)
                return;
            const regionHeight = end - start + 1;
            const regionWidth = maxX - minX + 1;
            if (regionHeight >= 5 && regionHeight <= Math.max(120, Math.round(height * 0.18)) && regionWidth >= 18) {
                regions.push([Math.max(0, minX - 3), Math.max(0, start - 2), Math.min(width, maxX + 4), Math.min(height, end + 3)]);
            }
            start = -1;
            minX = width;
            maxX = -1;
            quietRows = 0;
        };
        for (let y = 0; y < height; y += 1) {
            const active = rowEdgeCounts[y] >= threshold;
            if (active) {
                if (start < 0)
                    start = y;
                minX = Math.min(minX, rowMinX[y]);
                maxX = Math.max(maxX, rowMaxX[y]);
                quietRows = 0;
            }
            else if (start >= 0) {
                quietRows += 1;
                if (quietRows > 2)
                    close(y - quietRows);
            }
            if (regions.length >= MAX_TEXT_REGIONS)
                break;
        }
        if (start >= 0 && regions.length < MAX_TEXT_REGIONS)
            close(height - 1);
        return {
            findings: regions.map((region, index) => ({
                findingId: `canvas-text-${index}`,
                type: 'TEXT_REGION',
                confidenceBasisPoints: 6200,
                bbox: [
                    clampBp((region[0] / width) * 10_000),
                    clampBp((region[1] / height) * 10_000),
                    clampBp((region[2] / width) * 10_000),
                    clampBp((region[3] / height) * 10_000),
                ],
                provider: 'canvas-cv',
            })),
            capability: { name: 'TEXT_REGION_DETECTION', status: 'READY', backend: 'canvas-cv', required: true, detail: 'Deterministic local edge-density text-region proposal fallback available' },
        };
    }
    catch (error) {
        return {
            findings: [],
            capability: { name: 'TEXT_REGION_DETECTION', status: 'ERROR', backend: 'canvas-cv', required: true, detail: error instanceof Error ? error.message : 'canvas text-region detection failed' },
        };
    }
}
function deriveStatus(capabilities) {
    const required = capabilities.filter((item) => item.required);
    if (required.every((item) => item.status === 'READY'))
        return 'READY';
    if (required.some((item) => item.status === 'ERROR'))
        return 'PARTIAL';
    if (required.some((item) => item.status === 'READY'))
        return 'PARTIAL';
    return 'UNAVAILABLE';
}
/**
 * Browser-native visual perception pass.
 *
 * This layer never calls a remote endpoint. It uses browser-local Shape
 * Detection APIs when available, deterministic Canvas CV for text-region
 * proposals, and DOM/visual projection for sensitive controls. Missing native
 * face/QR capabilities are explicitly surfaced as PARTIAL so the hardened
 * localhost companion must complete coverage before any network release.
 */
export async function runLocalVision(screenshotDataUrl, frames) {
    const started = nowMs();
    const capabilities = [];
    const findings = [];
    let bitmap = null;
    try {
        bitmap = await decodeScreenshot(screenshotDataUrl);
        capabilities.push({ name: 'SCREENSHOT_DECODE', status: 'READY', backend: 'browser-imagebitmap', required: true, detail: `${bitmap.width}x${bitmap.height} screenshot decoded locally` });
    }
    catch (error) {
        capabilities.push({ name: 'SCREENSHOT_DECODE', status: 'ERROR', backend: 'browser-imagebitmap', required: true, detail: error instanceof Error ? error.message : 'screenshot decode failed' });
        const report = {
            status: 'ERROR',
            modelId: 'veilgraph-browser-native-cv-v1',
            backend: 'browser-native',
            elapsedMs: Math.max(0, Math.round(nowMs() - started)),
            imageWidth: 0,
            imageHeight: 0,
            capabilities,
            findingCount: 0,
        };
        return { status: 'ERROR', findings: [], report };
    }
    const domFindings = projectDomSensitiveRegions(frames);
    findings.push(...domFindings);
    capabilities.push({
        name: 'DOM_SENSITIVE_PROJECTION',
        status: frames.some((frame) => frame.isTopFrame) ? 'READY' : 'UNAVAILABLE',
        backend: 'dom-visual-fusion',
        required: true,
        detail: `${domFindings.length} sensitive DOM region(s) projected into viewport geometry`,
    });
    const [faces, barcodes, text] = await Promise.all([
        nativeFaceFindings(bitmap),
        nativeBarcodeFindings(bitmap),
        nativeTextFindings(bitmap),
    ]);
    findings.push(...faces.findings, ...barcodes.findings, ...text.findings);
    capabilities.push(faces.capability, barcodes.capability, text.capability);
    const deduped = deduplicate(findings);
    const status = deriveStatus(capabilities);
    const report = {
        status,
        modelId: 'veilgraph-browser-native-cv-v1',
        backend: 'browser-native',
        elapsedMs: Math.max(0, Math.round(nowMs() - started)),
        imageWidth: bitmap.width,
        imageHeight: bitmap.height,
        capabilities,
        findingCount: deduped.length,
    };
    bitmap.close();
    return { status, findings: deduped, report };
}
