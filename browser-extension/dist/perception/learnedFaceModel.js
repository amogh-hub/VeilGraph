export const ULTRAFACE_MODEL_ID = 'ultraface-rfb-320';
export const ULTRAFACE_MODEL_SHA256 = '34cd7e60aeff28744c657de7a3dc64e872d506741de66987f3426f2b79f88017';
export const ULTRAFACE_MODEL_PATH = 'models/ultraface/version-RFB-320.onnx';
export const ONNX_RUNTIME_ID = 'onnxruntime-web@1.27.0';
export const ORT_WASM_ROOT = 'vendor/onnxruntime/';
const INPUT_WIDTH = 320;
const INPUT_HEIGHT = 240;
const FACE_THRESHOLD = 0.65;
const NMS_IOU_THRESHOLD = 0.30;
const MAX_FACES = 64;
const PROVIDER_INIT_TIMEOUT_MS = 8_000;
const PROVIDER_INFERENCE_TIMEOUT_MS = 12_000;
async function withTimeout(promise, timeoutMs, label) {
    let timer;
    try {
        return await Promise.race([
            promise,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
            }),
        ]);
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}
function nowMs() {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
}
function elapsedMs(started) {
    return Math.max(0, Math.round(nowMs() - started));
}
function clampBp(value) {
    return Math.max(0, Math.min(10_000, Math.round(value)));
}
function toHex(bytes) {
    return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
async function sha256Hex(bytes) {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return toHex(await crypto.subtle.digest('SHA-256', copy.buffer));
}
async function loadVerifiedModel(resolveAssetUrl) {
    const response = await fetch(resolveAssetUrl(ULTRAFACE_MODEL_PATH), {
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
    });
    if (!response.ok)
        throw new Error(`packaged model fetch failed (${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = await sha256Hex(bytes);
    if (digest !== ULTRAFACE_MODEL_SHA256) {
        throw new Error(`packaged model integrity mismatch: expected ${ULTRAFACE_MODEL_SHA256}, got ${digest}`);
    }
    return bytes;
}
function preprocess(bitmap) {
    const canvas = new OffscreenCanvas(INPUT_WIDTH, INPUT_HEIGHT);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context)
        throw new Error('2D canvas context unavailable for learned-model preprocessing');
    context.drawImage(bitmap, 0, 0, INPUT_WIDTH, INPUT_HEIGHT);
    const pixels = context.getImageData(0, 0, INPUT_WIDTH, INPUT_HEIGHT).data;
    const plane = INPUT_WIDTH * INPUT_HEIGHT;
    const tensor = new Float32Array(plane * 3);
    for (let index = 0; index < plane; index += 1) {
        const offset = index * 4;
        tensor[index] = (pixels[offset] - 127) / 128;
        tensor[plane + index] = (pixels[offset + 1] - 127) / 128;
        tensor[plane * 2 + index] = (pixels[offset + 2] - 127) / 128;
    }
    return tensor;
}
function tensorByLastDimension(outputs, outputNames, lastDimension) {
    return outputNames
        .map((name) => outputs[name])
        .find((tensor) => Boolean(tensor && tensor.dims[tensor.dims.length - 1] === lastDimension));
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
function hardNms(candidates) {
    const sorted = [...candidates].sort((left, right) => right.confidence - left.confidence);
    const kept = [];
    for (const candidate of sorted) {
        if (kept.some((existing) => iou(existing.bbox, candidate.bbox) > NMS_IOU_THRESHOLD))
            continue;
        kept.push(candidate);
        if (kept.length >= MAX_FACES)
            break;
    }
    return kept;
}
function postprocess(session, outputs) {
    const scores = tensorByLastDimension(outputs, session.outputNames, 2);
    const boxes = tensorByLastDimension(outputs, session.outputNames, 4);
    if (!scores || !boxes)
        throw new Error('UltraFace output tensors are missing score or box dimensions');
    const scoreData = scores.data;
    const boxData = boxes.data;
    const candidateCount = Math.min(Math.floor(scoreData.length / 2), Math.floor(boxData.length / 4));
    const candidates = [];
    for (let index = 0; index < candidateCount; index += 1) {
        const confidence = Number(scoreData[index * 2 + 1] ?? 0);
        if (!Number.isFinite(confidence) || confidence < FACE_THRESHOLD)
            continue;
        const x0 = clampBp(Number(boxData[index * 4] ?? 0) * 10_000);
        const y0 = clampBp(Number(boxData[index * 4 + 1] ?? 0) * 10_000);
        const x1 = clampBp(Number(boxData[index * 4 + 2] ?? 0) * 10_000);
        const y1 = clampBp(Number(boxData[index * 4 + 3] ?? 0) * 10_000);
        if (x1 <= x0 || y1 <= y0)
            continue;
        candidates.push({ bbox: [x0, y0, x1, y1], confidence });
    }
    return hardNms(candidates).map((candidate, index) => ({
        findingId: `onnx-face-${index}`,
        type: 'FACE',
        confidenceBasisPoints: clampBp(candidate.confidence * 10_000),
        bbox: candidate.bbox,
        provider: `onnx:${ULTRAFACE_MODEL_ID}`,
        modalities: ['VISUAL'],
    }));
}
function unavailableEvidence(reason, modelLoadMs) {
    return {
        modelId: ULTRAFACE_MODEL_ID,
        modelSha256: ULTRAFACE_MODEL_SHA256,
        runtime: ONNX_RUNTIME_ID,
        executionProvider: 'unavailable',
        modelLoadMs,
        inferenceMs: 0,
        inputWidth: INPUT_WIDTH,
        inputHeight: INPUT_HEIGHT,
        detectionCount: 0,
        fallbackUsed: false,
        fallbackReason: reason,
    };
}
/**
 * Creates the packaged learned face detector. The runtime module and model are
 * extension-owned assets. The detector never accepts a remote model URL.
 * WebGPU is preferred; the same packaged runtime falls back to WASM when the
 * platform/provider cannot initialize WebGPU.
 */
export function createOnnxLearnedFaceDetector(ort, resolveAssetUrl) {
    let modelPromise = null;
    let modelLoadMs = 0;
    const sessions = new Map();
    const model = async () => {
        if (!modelPromise) {
            const started = nowMs();
            modelPromise = loadVerifiedModel(resolveAssetUrl).then((bytes) => {
                modelLoadMs = elapsedMs(started);
                return bytes;
            });
        }
        return modelPromise;
    };
    const session = async (provider) => {
        const existing = sessions.get(provider);
        if (existing)
            return existing;
        const created = model().then((bytes) => ort.InferenceSession.create(bytes, {
            executionProviders: [provider],
            graphOptimizationLevel: 'all',
            // 0=verbose, 1=info, 2=warning, 3=error, 4=fatal.
            // Chrome should surface genuine runtime errors, not harmless model
            // optimization warnings from the pinned UltraFace export.
            logSeverityLevel: 3,
        }));
        sessions.set(provider, created);
        try {
            return await created;
        }
        catch (error) {
            sessions.delete(provider);
            throw error;
        }
    };
    return {
        async detect(bitmap) {
            try {
                ort.env.wasm.numThreads = 1;
                ort.env.wasm.wasmPaths = {
                    wasm: resolveAssetUrl(`${ORT_WASM_ROOT}ort-wasm-simd-threaded.wasm`),
                };
                ort.env.logLevel = 'error';
                const inputData = preprocess(bitmap);
                const inputTensor = new ort.Tensor('float32', inputData, [1, 3, INPUT_HEIGHT, INPUT_WIDTH]);
                let selectedProvider = 'wasm';
                let fallbackUsed = false;
                let fallbackReason;
                const executeProvider = async (provider) => {
                    const runtimeSession = await withTimeout(session(provider), PROVIDER_INIT_TIMEOUT_MS, `${provider} UltraFace session initialization`);
                    const inputName = runtimeSession.inputNames[0];
                    if (!inputName)
                        throw new Error('UltraFace model has no input tensor');
                    const inferenceStarted = nowMs();
                    const outputs = await withTimeout(runtimeSession.run({ [inputName]: inputTensor }), PROVIDER_INFERENCE_TIMEOUT_MS, `${provider} UltraFace inference`);
                    return {
                        runtimeSession,
                        outputs,
                        inferenceMs: elapsedMs(inferenceStarted),
                    };
                };
                let execution;
                const webgpuAvailable = false;
                if (webgpuAvailable) {
                    try {
                        execution = await executeProvider('webgpu');
                        selectedProvider = 'webgpu';
                    }
                    catch (error) {
                        fallbackUsed = true;
                        fallbackReason = error instanceof Error
                            ? error.message
                            : 'WebGPU UltraFace execution failed';
                        execution = await executeProvider('wasm');
                        selectedProvider = 'wasm';
                    }
                }
                else {
                    fallbackUsed = true;
                    fallbackReason = 'MV3 live-browser path is using packaged WASM after WebGPU runtime incompatibility';
                    execution = await executeProvider('wasm');
                    selectedProvider = 'wasm';
                }
                const runtimeSession = execution.runtimeSession;
                const outputs = execution.outputs;
                const inferenceMs = execution.inferenceMs;
                const findings = postprocess(runtimeSession, outputs);
                const evidence = {
                    modelId: ULTRAFACE_MODEL_ID,
                    modelSha256: ULTRAFACE_MODEL_SHA256,
                    runtime: ONNX_RUNTIME_ID,
                    executionProvider: selectedProvider,
                    modelLoadMs,
                    inferenceMs,
                    inputWidth: INPUT_WIDTH,
                    inputHeight: INPUT_HEIGHT,
                    detectionCount: findings.length,
                    fallbackUsed,
                    ...(fallbackReason ? { fallbackReason } : {}),
                };
                return {
                    findings,
                    capability: {
                        name: 'LEARNED_FACE_DETECTION',
                        status: 'READY',
                        backend: `${ONNX_RUNTIME_ID}:${selectedProvider}`,
                        required: true,
                        detail: `${ULTRAFACE_MODEL_ID} executed locally via ${selectedProvider}; detections=${findings.length}; model_sha256=${ULTRAFACE_MODEL_SHA256.slice(0, 12)}…`,
                    },
                    evidence,
                };
            }
            catch (error) {
                const reason = error instanceof Error ? error.message : 'packaged learned face inference failed';
                return {
                    findings: [],
                    capability: {
                        name: 'LEARNED_FACE_DETECTION',
                        status: 'ERROR',
                        backend: ONNX_RUNTIME_ID,
                        required: true,
                        detail: reason,
                    },
                    evidence: unavailableEvidence(reason, modelLoadMs),
                };
            }
        },
    };
}
export function unavailableLearnedFaceResult(detail) {
    return {
        findings: [],
        capability: {
            name: 'LEARNED_FACE_DETECTION',
            status: 'UNAVAILABLE',
            backend: ONNX_RUNTIME_ID,
            required: true,
            detail,
        },
        evidence: unavailableEvidence(detail, 0),
    };
}
