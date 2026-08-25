export const MAX_AGENT_LOOP_STEPS = 8;
export const MAX_AGENT_LOOP_DURATION_MS = 120_000;
export const MIN_AUTONOMOUS_CONFIDENCE_BP = 7_000;
const MAX_IDENTICAL_ACTION_STREAK = 2;
const MAX_TRACE_ENTRIES = 24;
function clampSteps(value) {
    if (!Number.isFinite(value))
        return 6;
    return Math.max(1, Math.min(MAX_AGENT_LOOP_STEPS, Math.trunc(value)));
}
export function beginSecureAgentLoop(loopId, tabId, task, maxSteps, nowMs) {
    if (!task.trim())
        throw new Error('secure agent loop task is empty');
    if (!Number.isInteger(tabId) || tabId < 0)
        throw new Error('secure agent loop tab ID is invalid');
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
    };
}
export function appendLoopTrace(machine, entry) {
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
    });
    if (machine.trace.length > MAX_TRACE_ENTRIES) {
        machine.trace.splice(0, machine.trace.length - MAX_TRACE_ENTRIES);
        machine.trace.forEach((item, index) => {
            item.sequence = index + 1;
        });
    }
}
export function actionFingerprint(action) {
    return JSON.stringify([
        action.action,
        action.target_id ?? null,
        action.value ?? null,
        action.url ?? null,
        action.scroll_delta_y ?? null,
        action.wait_ms ?? null,
    ]);
}
export function validateLoopOrigin(machine, origin) {
    let normalized;
    try {
        normalized = new URL(origin).origin;
    }
    catch {
        return { allowed: false, status: 'BLOCKED', reason: 'INVALID_TOP_FRAME_ORIGIN' };
    }
    if (machine.boundOrigin === null) {
        machine.boundOrigin = normalized;
        return { allowed: true, status: 'RUNNING', reason: 'ORIGIN_BOUND' };
    }
    if (machine.boundOrigin !== normalized) {
        return { allowed: false, status: 'BLOCKED', reason: 'ORIGIN_CHANGED_DURING_LOOP' };
    }
    return { allowed: true, status: 'RUNNING', reason: 'ORIGIN_CONTINUITY_OK' };
}
export function validateLoopContinuation(machine, activeTabId, nowMs) {
    if (activeTabId !== machine.tabId) {
        return { allowed: false, status: 'BLOCKED', reason: 'ACTIVE_TAB_CHANGED' };
    }
    if (nowMs - machine.startedAtMs > MAX_AGENT_LOOP_DURATION_MS) {
        return { allowed: false, status: 'BLOCKED', reason: 'LOOP_DEADLINE_EXCEEDED' };
    }
    return { allowed: true, status: 'RUNNING', reason: 'CONTINUE' };
}
export function terminalReasoningStopReason(terminalEvidence, plan) {
    if (terminalEvidence !== 'POSITIVE_COMPLETION'
        || plan.complete) {
        return null;
    }
    if (plan.actions.length === 1
        && plan.actions[0]?.action === 'WAIT') {
        return 'TERMINAL_COMPLETION_UNCERTAIN';
    }
    return 'TERMINAL_REASONING_CONTRACT_VIOLATION';
}
export function evaluateLoopAction(machine, action, nowMs) {
    const continuation = validateLoopContinuation(machine, machine.tabId, nowMs);
    if (!continuation.allowed) {
        return {
            allowed: false,
            status: continuation.status,
            reason: continuation.reason,
            requiresConfirmation: false,
        };
    }
    if (machine.stepCount >= machine.maxSteps) {
        return {
            allowed: false,
            status: 'STEP_LIMIT',
            reason: 'MAX_ACTION_STEPS_REACHED',
            requiresConfirmation: false,
        };
    }
    const fingerprint = actionFingerprint(action);
    let identicalStreak = 0;
    for (let index = machine.actionFingerprints.length - 1; index >= 0; index -= 1) {
        if (machine.actionFingerprints[index] !== fingerprint)
            break;
        identicalStreak += 1;
    }
    if (identicalStreak >= MAX_IDENTICAL_ACTION_STREAK) {
        return {
            allowed: false,
            status: 'LOOP_DETECTED',
            reason: 'REPEATED_IDENTICAL_ACTION_DETECTED',
            requiresConfirmation: false,
        };
    }
    if (action.requires_confirmation) {
        return {
            allowed: true,
            status: 'WAITING_CONFIRMATION',
            reason: 'HIGH_IMPACT_ACTION_REQUIRES_LOCAL_CONFIRMATION',
            requiresConfirmation: true,
        };
    }
    if (action.confidence_basis_points < MIN_AUTONOMOUS_CONFIDENCE_BP) {
        return {
            allowed: true,
            status: 'WAITING_CONFIRMATION',
            reason: 'LOW_CONFIDENCE_ACTION_REQUIRES_LOCAL_CONFIRMATION',
            requiresConfirmation: true,
        };
    }
    return {
        allowed: true,
        status: 'RUNNING',
        reason: 'AUTONOMOUS_LOW_IMPACT_ACTION_ALLOWED',
        requiresConfirmation: false,
    };
}
export function registerLoopExecution(machine, action, _executionElapsedMs, _nowMs) {
    machine.actionFingerprints.push(actionFingerprint(action));
    if (machine.actionFingerprints.length > 12)
        machine.actionFingerprints.shift();
    machine.stepCount += 1;
    machine.status = 'RUNNING';
}
export function markLoopComplete(machine, nowMs) {
    machine.status = 'COMPLETE';
    machine.endedAtMs = nowMs;
    machine.stopReason = null;
    appendLoopTrace(machine, {
        stage: 'STOP',
        action: null,
        targetId: null,
        proofScore: null,
        residualExposure: null,
        minimizationBasisPoints: null,
        elapsedMs: 0,
        note: 'Reasoning server reported task complete after a fresh sanitized observation.',
    });
}
export function markLoopCancelled(machine, reason, nowMs) {
    machine.status = 'CANCELLED';
    machine.endedAtMs = nowMs;
    machine.stopReason = reason;
    appendLoopTrace(machine, {
        stage: 'STOP',
        action: null,
        targetId: null,
        proofScore: null,
        residualExposure: null,
        minimizationBasisPoints: null,
        elapsedMs: 0,
        note: reason,
    });
}
export function markLoopStopped(machine, status, reason, nowMs) {
    if (status === 'RUNNING' || status === 'WAITING_CONFIRMATION' || status === 'COMPLETE' || status === 'CANCELLED') {
        throw new Error(`markLoopStopped requires a terminal failure status, got ${status}`);
    }
    machine.status = status;
    machine.endedAtMs = nowMs;
    machine.stopReason = reason;
    appendLoopTrace(machine, {
        stage: 'STOP',
        action: null,
        targetId: null,
        proofScore: null,
        residualExposure: null,
        minimizationBasisPoints: null,
        elapsedMs: 0,
        note: reason,
    });
}
export function publicLoopResult(machine, pendingExecution) {
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
    };
}
