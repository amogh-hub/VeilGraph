import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import * as ort from 'onnxruntime-web/wasm'

const root = resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(resolve(root, 'models/ultraface/MODEL_MANIFEST.json'), 'utf8'))
const modelPath = resolve(root, 'models/ultraface', manifest.filename)
const distModelPath = resolve(root, 'dist/models/ultraface', manifest.filename)
const distRuntimePath = resolve(root, 'dist/vendor/onnxruntime/ort.webgpu.bundle.min.mjs')
const distWasmPath = resolve(root, 'dist/vendor/onnxruntime/ort-wasm-simd-threaded.jsep.wasm')
const distManifest = JSON.parse(await readFile(resolve(root, 'dist/manifest.json'), 'utf8'))

const modelBytes = new Uint8Array(await readFile(modelPath))
const modelHash = createHash('sha256').update(modelBytes).digest('hex')
assert.equal(modelHash, manifest.sha256)
assert.equal(modelBytes.byteLength, manifest.size_bytes)
const distBytes = new Uint8Array(await readFile(distModelPath))
assert.equal(createHash('sha256').update(distBytes).digest('hex'), manifest.sha256)
assert.equal((await stat(distRuntimePath)).size > 20_000, true)
assert.equal((await stat(distWasmPath)).size > 1_000_000, true)
assert.match(distManifest.content_security_policy.extension_pages, /'wasm-unsafe-eval'/)

ort.env.wasm.numThreads = 1
const session = await ort.InferenceSession.create(modelBytes, {
  executionProviders: ['wasm'],
  graphOptimizationLevel: 'all',
})
assert.equal(session.inputNames.length, 1)
const input = new ort.Tensor('float32', new Float32Array(1 * 3 * 240 * 320), [1, 3, 240, 320])
const outputs = await session.run({ [session.inputNames[0]]: input })
const shapes = session.outputNames.map((name) => outputs[name]?.dims?.join('x') ?? '')
assert.ok(shapes.includes('1x4420x2'), `missing UltraFace score output: ${shapes.join(', ')}`)
assert.ok(shapes.includes('1x4420x4'), `missing UltraFace box output: ${shapes.join(', ')}`)

const serviceWorker = await readFile(resolve(root, 'dist/background/serviceWorker.js'), 'utf8')
assert.match(serviceWorker, /ort\.webgpu\.bundle\.min\.mjs/)
assert.match(serviceWorker, /createOnnxLearnedFaceDetector/)
const learnedSource = await readFile(resolve(root, 'src/perception/learnedFaceModel.ts'), 'utf8')
assert.match(learnedSource, /executionProviders:\s*\[provider\]/)
assert.match(learnedSource, /webgpu/)
assert.match(learnedSource, /wasm/)
assert.doesNotMatch(learnedSource, /https?:\/\//)

console.log(JSON.stringify({
  status: 'READY',
  contract: 'PACKAGED_LEARNED_VISION_V1',
  modelId: manifest.model_id,
  modelSha256: modelHash,
  modelBytes: modelBytes.byteLength,
  runtime: 'onnxruntime-web@1.27.0',
  verifiedProvider: 'wasm',
  browserPreferredProvider: 'webgpu',
  outputShapes: shapes,
}))
