import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')
const dist = path.join(root, 'dist-firefox')
const manifest = JSON.parse(fs.readFileSync(path.join(dist, 'manifest.json'), 'utf8'))

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

assert(manifest.manifest_version === 3, 'Firefox package must remain MV3')
assert(!manifest.permissions.includes('sidePanel'), 'Firefox package must not request Chrome sidePanel')
assert(!('side_panel' in manifest), 'Firefox manifest must not contain side_panel')
assert(manifest.action?.default_popup === 'sidepanel/index.html', 'Firefox popup UI missing')
assert(Boolean(manifest.browser_specific_settings?.gecko?.id), 'Firefox Gecko identity missing')
assert(Array.isArray(manifest.background?.scripts), 'Firefox MV3 background.scripts fallback missing')
assert(manifest.background.scripts.includes('background/serviceWorker.js'), 'Firefox background script missing')
assert(!('service_worker' in manifest.background), 'Firefox package must not rely on unsupported background.service_worker')
assert(manifest.background.type === 'module', 'Firefox background module type missing')
assert(manifest.browser_specific_settings?.gecko?.data_collection_permissions?.required?.includes('websiteContent'), 'Firefox data-collection declaration missing')
assert(manifest.host_permissions.includes('http://127.0.0.1:8000/*'), 'companion host missing')
assert(manifest.host_permissions.includes('http://127.0.0.1:8001/*'), 'reasoner host missing')
assert(manifest.host_permissions.includes('http://127.0.0.1:8002/*'), 'witness host missing')
assert(fs.existsSync(path.join(dist, 'background', 'serviceWorker.js')), 'background worker missing')
assert(fs.existsSync(path.join(dist, 'sidepanel', 'index.html')), 'extension UI missing')
assert(fs.existsSync(path.join(dist, 'content', 'contentScript.js')), 'content script missing')
assert(fs.existsSync(path.join(dist, 'models', 'ultraface', 'version-RFB-320.onnx')), 'UltraFace model missing')

const source = fs.readFileSync(path.join(root, 'src', 'background', 'serviceWorker.ts'), 'utf8')
assert(source.includes('chrome.sidePanel?.open'), 'Chrome-only sidePanel call is not runtime-guarded')

console.log('FIREFOX_PACKAGE_V1: READY')
console.log('UI: toolbar popup')
console.log('LOCAL MODEL: packaged UltraFace + ONNX Runtime Web')
console.log('SECURE LOOP: shared TypeScript/browser core')
