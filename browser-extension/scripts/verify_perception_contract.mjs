import assert from 'node:assert/strict'
import { clipRectToViewport } from '../dist/perception/geometry.js'

assert.deepEqual(
  clipRectToViewport({ left: 100, top: 50, right: 500, bottom: 250 }, 1000, 500),
  [1000, 1000, 5000, 5000],
)
assert.deepEqual(
  clipRectToViewport({ left: -200, top: 100, right: 200, bottom: 300 }, 1000, 500),
  [0, 2000, 2000, 6000],
)
assert.equal(
  clipRectToViewport({ left: -400, top: 100, right: -10, bottom: 300 }, 1000, 500),
  null,
)
assert.equal(
  clipRectToViewport({ left: 0, top: 600, right: 300, bottom: 700 }, 1000, 500),
  null,
)
console.log(JSON.stringify({ status: 'READY', contract: 'VIEWPORT_BOUND_V2', geometryCases: 4 }))
