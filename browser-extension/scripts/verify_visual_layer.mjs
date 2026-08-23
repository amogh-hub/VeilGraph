import assert from 'node:assert/strict'

const onePixelPng = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zp48AAAAASUVORK5CYII='

globalThis.createImageBitmap = async () => ({ width: 1000, height: 800, close() {} })
class Rect { constructor(x, y, width, height) { Object.assign(this, { x, y, width, height, top: y, left: x, right: x + width, bottom: y + height }) } }
globalThis.FaceDetector = class { async detect() { return [{ boundingBox: new Rect(100, 100, 200, 220) }] } }
globalThis.BarcodeDetector = class { async detect() { return [{ boundingBox: new Rect(700, 100, 120, 120), rawValue: 'local-qr' }] } }
globalThis.TextDetector = class {
  async detect() {
    return [
      { boundingBox: new Rect(110, 560, 300, 40), rawValue: 'password row' },
      { boundingBox: new Rect(80, 500, 300, 32), rawValue: 'independent text' },
    ]
  }
}

const { runLocalVision } = await import('../dist/perception/localVision.js')
const result = await runLocalVision(onePixelPng, [{
  frameId: 0,
  isTopFrame: true,
  origin: 'https://example.test',
  href: 'https://example.test',
  title: 'Example',
  viewportWidth: 1000,
  viewportHeight: 800,
  devicePixelRatioBasisPoints: 10000,
  scrollX: 0,
  scrollY: 0,
  documentWidth: 1000,
  documentHeight: 1200,
  eligibleElementCount: 1,
  capturedElementCount: 1,
  captureTruncated: false,
  shadowRootCount: 0,
  captureElapsedMs: 1,
  inaccessibleDescendantFrames: 0,
  elements: [{
    localId: 'vg_password_001',
    tag: 'input',
    role: 'textbox',
    accessibleName: 'Password',
    visibleText: '',
    inputType: 'password',
    rawValue: 'never-export-this',
    disabled: false,
    bbox: [1000, 7000, 5000, 7700],
    privacyHints: ['credential'],
  }],
}])

assert.equal(result.status, 'READY')
assert.equal(result.report.status, 'READY')
assert.equal(result.report.modelId, 'veilgraph-browser-native-cv-v2')
assert.ok(result.findings.some((finding) => finding.type === 'FACE'))
assert.ok(result.findings.some((finding) => finding.type === 'QR_CODE'))
assert.ok(result.findings.some((finding) => finding.type === 'TEXT_REGION'))
const password = result.findings.find((finding) => finding.type === 'PASSWORD_FIELD')
assert.ok(password)
assert.deepEqual(new Set(password.modalities), new Set(['DOM', 'ACCESSIBILITY', 'VISUAL']))
assert.deepEqual(password.relatedElementIds, ['vg_password_001'])
assert.equal(result.report.capabilities.filter((item) => item.required && item.status === 'READY').length, 5)
for (const value of Object.values(result.report.stageTimingsMs)) assert.ok(Number.isInteger(value) && value >= 0)
console.log(JSON.stringify({ status: result.status, findings: result.findings.length, capabilities: result.report.capabilities.length, fusedPasswordModalities: password.modalities.length }))
