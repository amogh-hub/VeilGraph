import type { RuntimeResponse } from '../common/protocol.js'

const status = document.querySelector<HTMLDivElement>('#status')
const analyseButton = document.querySelector<HTMLButtonElement>('#analyse')
const taskInput = document.querySelector<HTMLInputElement>('#task')
const detail = document.querySelector<HTMLPreElement>('#detail')

async function analyse(): Promise<void> {
  if (!status || !detail || !analyseButton || !taskInput) return
  const task = taskInput.value.trim()
  if (!task) {
    status.textContent = 'Describe the browser task first.'
    return
  }
  analyseButton.disabled = true
  status.textContent = 'Analysing locally…'
  try {
    const response = await chrome.runtime.sendMessage<RuntimeResponse>({
      type: 'VG_ANALYSE_ACTIVE_PAGE',
      task,
      audienceProfile: 'PUBLIC_RELEASE',
      privacyLevel: 4,
    })
    if (!response.ok) throw new Error(response.error)
    const result = response.data as Record<string, unknown>
    status.textContent = String(result.readiness ?? 'Local analysis complete')
    detail.textContent = JSON.stringify({
      riskBefore: result.risk_before,
      residualPreview: result.residual_risk_preview,
      utilityPreview: result.utility_preview,
      semanticElements: result.semantic_elements,
      credentialFields: result.credential_fields,
      visualPerceptionStatus: result.visual_perception_status,
      readiness: result.readiness,
    }, null, 2)
  } catch (error) {
    status.textContent = 'Local analysis failed'
    detail.textContent = error instanceof Error ? error.message : 'unknown error'
  } finally {
    analyseButton.disabled = false
  }
}

analyseButton?.addEventListener('click', () => void analyse())
