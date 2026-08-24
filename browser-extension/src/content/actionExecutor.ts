import type { BrowserAction } from '../common/protocol.js'
import { assertLiveElementSecurity } from './actionSecurity.js'
import { implicitRole, privacyHints, resolveLocalElement } from './domCapture.js'

function isVisible(element: Element): boolean {
  const style = getComputedStyle(element)
  if (
    style.display === 'none'
    || style.visibility === 'hidden'
    || Number(style.opacity || '1') <= 0
  ) return false

  const rect = element.getBoundingClientRect()
  return (
    rect.width > 0
    && rect.height > 0
    && rect.right > 0
    && rect.bottom > 0
    && rect.left < window.innerWidth
    && rect.top < window.innerHeight
  )
}

function isOccluded(element: Element): boolean {
  const rect = element.getBoundingClientRect()
  const x = Math.max(0, Math.min(window.innerWidth - 1, rect.left + rect.width / 2))
  const y = Math.max(0, Math.min(window.innerHeight - 1, rect.top + rect.height / 2))
  const topmost = document.elementFromPoint(x, y)
  if (!topmost) return true
  return !(element === topmost || element.contains(topmost) || topmost.contains(element))
}

function liveSnapshot(element: Element) {
  const style = getComputedStyle(element)
  const input = element instanceof HTMLInputElement ? element : null
  const control = (
    element instanceof HTMLButtonElement
    || element instanceof HTMLInputElement
    || element instanceof HTMLTextAreaElement
    || element instanceof HTMLSelectElement
  ) ? element : null
  const hints = privacyHints(element)
  return {
    connected: element.isConnected,
    visible: isVisible(element),
    occluded: isOccluded(element),
    disabled: control?.disabled ?? false,
    ariaDisabled: element.getAttribute('aria-disabled')?.toLowerCase() === 'true',
    pointerEventsNone: style.pointerEvents === 'none',
    role: implicitRole(element),
    tag: element.tagName.toLowerCase(),
    inputType: input?.type ?? null,
    credentialLike: hints.includes('credential'),
  }
}

function dispatchValueEvents(element: Element): void {
  element.dispatchEvent(new Event('input', { bubbles: true, composed: true }))
  element.dispatchEvent(new Event('change', { bubbles: true, composed: true }))
}

function executeType(element: Element, value: string): void {
  if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
    element.focus({ preventScroll: true })
    element.value = value
    dispatchValueEvents(element)
    return
  }
  if (element instanceof HTMLElement && element.isContentEditable) {
    element.focus({ preventScroll: true })
    element.textContent = value
    dispatchValueEvents(element)
    return
  }
  throw new Error('live target is not locally typeable')
}

function parseBooleanSelection(value: string): boolean | null {
  const normalized = value.trim().toLowerCase()
  if (['true', 'on', 'yes', 'checked', '1'].includes(normalized)) return true
  if (['false', 'off', 'no', 'unchecked', '0'].includes(normalized)) return false
  return null
}

function executeSelect(element: Element, value: string): void {
  if (element instanceof HTMLSelectElement) {
    const normalized = value.trim().toLowerCase()
    const option = Array.from(element.options).find((candidate) => (
      candidate.value === value
      || candidate.text.trim().toLowerCase() === normalized
    ))
    if (!option) throw new Error('requested select option is not present in the live control')
    element.value = option.value
    dispatchValueEvents(element)
    return
  }

  if (element instanceof HTMLInputElement && (element.type === 'checkbox' || element.type === 'radio')) {
    const desired = parseBooleanSelection(value)
    if (desired === null) throw new Error('checkbox/radio selection value must be a boolean-like value')
    if (element.type === 'radio' && desired === false) {
      if (element.checked) {
        element.checked = false
        dispatchValueEvents(element)
      }
      return
    }
    if (element.checked !== desired) element.click()
    return
  }

  throw new Error('live target is not a supported local selection control')
}

export function executeFrameAction(
  executionId: `VGX-${string}`,
  action: BrowserAction,
): { executionId: `VGX-${string}`; action: string; targetId: `vg_${string}` | null } {
  if (action.action === 'SCROLL') {
    const delta = action.scroll_delta_y
    if (!delta) throw new Error('SCROLL action is missing delta')
    window.scrollBy({ top: delta, left: 0, behavior: 'auto' })
    return { executionId, action: action.action, targetId: null }
  }

  if (action.action === 'NAVIGATE' || action.action === 'WAIT') {
    throw new Error(`${action.action} must be executed by the trusted service worker`)
  }

  if (!action.target_id) throw new Error(`${action.action} requires a local target`)
  const element = resolveLocalElement(action.target_id)
  if (!element) throw new Error('target DOM node is stale or no longer available')

  assertLiveElementSecurity(action, liveSnapshot(element))

  if (action.action === 'CLICK') {
    if (!(element instanceof HTMLElement)) throw new Error('CLICK target is not an HTMLElement')
    element.focus({ preventScroll: true })
    element.click()
  } else if (action.action === 'TYPE') {
    if (action.value === null || action.value === undefined) throw new Error('TYPE action is missing value')
    executeType(element, action.value)
  } else if (action.action === 'SELECT') {
    if (action.value === null || action.value === undefined) throw new Error('SELECT action is missing value')
    executeSelect(element, action.value)
  } else if (action.action === 'READ') {
    // READ is intentionally non-exfiltrating. The next observe cycle will
    // capture/sanitize any resulting semantic context before network release.
  }

  return { executionId, action: action.action, targetId: action.target_id }
}
