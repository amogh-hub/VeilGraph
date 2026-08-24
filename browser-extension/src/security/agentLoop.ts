import type {
  BrowserAction,
  BrowserActionType,
  LocalActionExecutionResult,
  PendingActionExecution,
  SecureAgentLoopResult,
  SecureAgentLoopStatus,
  SecureAgentLoopTraceEntry,
} from '../common/protocol.js'

export const MAX_AGENT_LOOP_STEPS = 8
export const MAX_AGENT_LOOP_DURATION_MS = 120_000
export const MIN_AUTONOMOUS_CONFIDENCE_BP = 7_000
const MAX_IDENTICAL_ACTION_STREAK = 2
const MAX_TRACE_ENTRIES = 24

export interface SecureAgentLoopMachine {
  loopId: `VGL-${string}`
  tabId: number
  task: string
  status: SecureAgentLoopStatus
  stepCount: number
  maxSteps: number
  startedAtMs: number
  endedAtMs: number | null
  stopReason: string | null
  boundOrigin: string | null
  actionFingerprints: string[]
  trace: SecureAgentLoopTraceEntry[]
}

export interface LoopActionEvaluation {
  allowed: boolean
  status: SecureAgentLoopStatus
  reason: string
  requiresConfirmation: boolean
}

export interface LoopContinuation {
  allowed: boolean
  status: SecureAgentLoopStatus
  reason: string
}

function clampSteps(value: number): number {
  if (!Number.isFinite(value)) return 6
  return Math.max(1, Math.min(MAX_AGENT_LOOP_STEPS, Math.trunc(value)))
}

export function beginSecureAgentLoop(
  loopId: `VGL-${string}`,
  tabId: number,
  task: string,
  maxSteps: number,
  nowMs: number,
): SecureAgentLoopMachine {
  if (!task.trim()) throw new Error('secure agent loop task is empty')
  if (!Number.isInteger(tabId) || tabId < 0) throw new Error('secure agent loop tab ID is invalid')
  return {
    loopId,
    tabId,
    task: task.trim(),
    status: 'RUNNING',
    stepCount: 0,
    maxSteps: clampSteps(maxSteps),
    startedAtMs: nowMs,
    endedAtMs: null,
    stopReason: null,
    boundOrigin: null,
    actionFingerprints: [],
    trace: [],
  }
}

export function appendLoopTrace(
  machine: SecureAgentLoopMachine,
  entry: {
    stage: SecureAgentLoopTraceEntry['stage']
    action: BrowserActionType | null
    targetId: `vg_${string}` | null
    proofScore: number | null
    residualExposure: number | null
    minimizationBasisPoints: number | null
    elapsedMs: number
    note: string
  },
): void {
  machine.trace.push({
    sequence: machine.trace.length + 1,
    stage: entry.stage,
    action: entry.action,
    target_id: entry.targetId,
    proof_score: entry.proofScore,
    residual_identity_exposure: entry.residualExposure,
    minimization_basis_points: entry.minimizationBasisPoints,
    elapsed_ms: Math.max(0, Math.round(entry.elapsedMs)),
    note: entry.note.slice(0, 500),
  })
  if (machine.trace.length > MAX_TRACE_ENTRIES) {
    machine.trace.splice(0, machine.trace.length - MAX_TRACE_ENTRIES)
    machine.trace.forEach((item, index) => {
      item.sequence = index + 1
    })
  }
}

export function actionFingerprint(action: BrowserAction): string {
  return JSON.stringify([
    action.action,
    action.target_id ?? null,
    action.value ?? null,
    action.url ?? null,
    action.scroll_delta_y ?? null,
    action.wait_ms ?? null,
  ])
}

export function validateLoopOrigin(
  machine: SecureAgentLoopMachine,
  origin: string,
): LoopContinuation {
  let normalized: string
  try {
    normalized = new URL(origin).origin
  } catch {
    return { allowed: false, status: 'BLOCKED', reason: 'INVALID_TOP_FRAME_ORIGIN' }
  }
  if (machine.boundOrigin === null) {
    machine.boundOrigin = normalized
    return { allowed: true, status: 'RUNNING', reason: 'ORIGIN_BOUND' }
  }
  if (machine.boundOrigin !== normalized) {
    return { allowed: false, status: 'BLOCKED', reason: 'ORIGIN_CHANGED_DURING_LOOP' }
  }
  return { allowed: true, status: 'RUNNING', reason: 'ORIGIN_CONTINUITY_OK' }
}

export function validateLoopContinuation(
  machine: SecureAgentLoopMachine,
  activeTabId: number,
  nowMs: number,
): LoopContinuation {
  if (activeTabId !== machine.tabId) {
    return { allowed: false, status: 'BLOCKED', reason: 'ACTIVE_TAB_CHANGED' }
  }
  if (nowMs - machine.startedAtMs > MAX_AGENT_LOOP_DURATION_MS) {
    return { allowed: false, status: 'BLOCKED', reason: 'LOOP_DEADLINE_EXCEEDED' }
  }
  return { allowed: true, status: 'RUNNING', reason: 'CONTINUE' }
}

export function evaluateLoopAction(
  machine: SecureAgentLoopMachine,
  action: BrowserAction,
  nowMs: number,
): LoopActionEvaluation {
  const continuation = validateLoopContinuation(machine, machine.tabId, nowMs)
  if (!continuation.allowed) {
    return {
      allowed: false,
      status: continuation.status,
      reason: continuation.reason,
      requiresConfirmation: false,
    }
  }

  if (machine.stepCount >= machine.maxSteps) {
    return {
      allowed: false,
      status: 'STEP_LIMIT',
      reason: 'MAX_ACTION_STEPS_REACHED',
      requiresConfirmation: false,
    }
  }

  const fingerprint = actionFingerprint(action)
  let identicalStreak = 0
  for (let index = machine.actionFingerprints.length - 1; index >= 0; index -= 1) {
    if (machine.actionFingerprints[index] !== fingerprint) break
    identicalStreak += 1
  }
  if (identicalStreak >= MAX_IDENTICAL_ACTION_STREAK) {
    return {
      allowed: false,
      status: 'LOOP_DETECTED',
      reason: 'REPEATED_IDENTICAL_ACTION_DETECTED',
      requiresConfirmation: false,
    }
  }

  if (action.requires_confirmation) {
    return {
      allowed: true,
      status: 'WAITING_CONFIRMATION',
      reason: 'HIGH_IMPACT_ACTION_REQUIRES_LOCAL_CONFIRMATION',
      requiresConfirmation: true,
    }
  }

  if (action.confidence_basis_points < MIN_AUTONOMOUS_CONFIDENCE_BP) {
    return {
      allowed: true,
      status: 'WAITING_CONFIRMATION',
      reason: 'LOW_CONFIDENCE_ACTION_REQUIRES_LOCAL_CONFIRMATION',
      requiresConfirmation: true,
    }
  }

  return {
    allowed: true,
    status: 'RUNNING',
    reason: 'AUTONOMOUS_LOW_IMPACT_ACTION_ALLOWED',
    requiresConfirmation: false,
  }
}

export function registerLoopExecution(
  machine: SecureAgentLoopMachine,
  action: BrowserAction,
  _executionElapsedMs: number,
  _nowMs: number,
): void {
  machine.actionFingerprints.push(actionFingerprint(action))
  if (machine.actionFingerprints.length > 12) machine.actionFingerprints.shift()
  machine.stepCount += 1
  machine.status = 'RUNNING'
}

export function markLoopComplete(machine: SecureAgentLoopMachine, nowMs: number): void {
  machine.status = 'COMPLETE'
  machine.endedAtMs = nowMs
  machine.stopReason = null
  appendLoopTrace(machine, {
    stage: 'STOP',
    action: null,
    targetId: null,
    proofScore: null,
    residualExposure: null,
    minimizationBasisPoints: null,
    elapsedMs: 0,
    note: 'Reasoning server reported task complete after a fresh sanitized observation.',
  })
}

export function markLoopCancelled(machine: SecureAgentLoopMachine, reason: string, nowMs: number): void {
  machine.status = 'CANCELLED'
  machine.endedAtMs = nowMs
  machine.stopReason = reason
  appendLoopTrace(machine, {
    stage: 'STOP',
    action: null,
    targetId: null,
    proofScore: null,
    residualExposure: null,
    minimizationBasisPoints: null,
    elapsedMs: 0,
    note: reason,
  })
}

export function markLoopStopped(
  machine: SecureAgentLoopMachine,
  status: SecureAgentLoopStatus,
  reason: string,
  nowMs: number,
): void {
  if (status === 'RUNNING' || status === 'WAITING_CONFIRMATION' || status === 'COMPLETE' || status === 'CANCELLED') {
    throw new Error(`markLoopStopped requires a terminal failure status, got ${status}`)
  }
  machine.status = status
  machine.endedAtMs = nowMs
  machine.stopReason = reason
  appendLoopTrace(machine, {
    stage: 'STOP',
    action: null,
    targetId: null,
    proofScore: null,
    residualExposure: null,
    minimizationBasisPoints: null,
    elapsedMs: 0,
    note: reason,
  })
}

export function publicLoopResult(
  machine: SecureAgentLoopMachine,
  pendingExecution: PendingActionExecution | null,
): SecureAgentLoopResult {
  return {
    contract: 'SECURE_AGENT_LOOP_V1',
    loop_id: machine.loopId,
    status: machine.status,
    task: machine.task,
    step_count: machine.stepCount,
    max_steps: machine.maxSteps,
    started_at: new Date(machine.startedAtMs).toISOString(),
    ended_at: machine.endedAtMs === null ? null : new Date(machine.endedAtMs).toISOString(),
    pending_execution: pendingExecution,
    stop_reason: machine.stopReason,
    trace: machine.trace.map((entry) => ({ ...entry })),
  }
}
