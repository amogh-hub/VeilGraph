const EXECUTION_TTL_MS = 45_000;
const HIGH_IMPACT = new Set([
    'submit', 'confirm', 'send', 'pay', 'purchase', 'buy', 'checkout', 'delete',
    'remove', 'transfer', 'book', 'reserve', 'save', 'sign', 'agree', 'authorize',
]);
const DIRECT_PATTERNS = [
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,
    /[A-Z]{5}[0-9]{4}[A-Z]/i,
    /(?:\d[ -]?){12}/,
    /(?:\d[ -]?){13,19}/,
    /(?:\+?\d[\s().-]*){10,15}/,
];
function normalizedWords(value) {
    return value.toLowerCase().match(/[a-z]+/g) ?? [];
}
function requiresLocalConfirmation(payload, action) {
    if (action.requires_confirmation)
        return true;
    const target = action.target_id
        ? payload.page.elements.find((element) => element.element_id === action.target_id)
        : undefined;
    const text = [
        payload.task,
        action.reason,
        action.value ?? '',
        action.url ?? '',
        target?.label ?? '',
        target?.text ?? '',
    ].join(' ');
    return normalizedWords(text).some((word) => HIGH_IMPACT.has(word));
}
function containsDirectIdentifier(value) {
    return Boolean(value && DIRECT_PATTERNS.some((pattern) => pattern.test(value)));
}
function sameOrigin(left, right) {
    try {
        const a = new URL(left);
        const b = new URL(right);
        return a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
    }
    catch {
        return false;
    }
}
export function createPendingExecution(executionId, tabId, frames, payload, reasoning, nowMs) {
    if (reasoning.plan.complete || reasoning.plan.actions.length === 0)
        return null;
    // Never execute a multi-step server plan blindly. V1 executes only the first
    // action, then requires a complete new observation/privacy/reasoning cycle.
    const proposed = reasoning.plan.actions[0];
    if (!proposed)
        return null;
    if (containsDirectIdentifier(proposed.value)) {
        throw new Error('local execution rejected direct-identifier-like generated value');
    }
    if (proposed.action === 'NAVIGATE' && (!proposed.url || !sameOrigin(proposed.url, payload.page.origin))) {
        throw new Error('local execution rejected cross-origin or malformed navigation');
    }
    const action = {
        ...proposed,
        requires_confirmation: requiresLocalConfirmation(payload, proposed),
    };
    let frameId = null;
    let frameOrigin = null;
    let releasedTargetRole = null;
    if (action.target_id) {
        const released = payload.page.elements.find((element) => element.element_id === action.target_id);
        if (!released)
            throw new Error(`target ${action.target_id} is absent from released context`);
        const frame = frames.find((candidate) => candidate.elements.some((element) => element.localId === action.target_id));
        if (!frame)
            throw new Error(`target ${action.target_id} is absent from original local capture`);
        frameId = frame.frameId;
        frameOrigin = frame.origin;
        releasedTargetRole = released.role;
    }
    else if (action.action === 'SCROLL') {
        const top = frames.find((frame) => frame.isTopFrame);
        if (!top)
            throw new Error('top frame is unavailable for scroll execution');
        frameId = top.frameId;
        frameOrigin = top.origin;
    }
    return {
        public: {
            contract: 'LOCAL_ACTION_SECURITY_EXECUTION_V1',
            execution_id: executionId,
            session_id: payload.session_id,
            task_id: payload.task_id,
            action,
            frame_id: frameId,
            target_id: action.target_id ?? null,
            requires_confirmation: action.requires_confirmation,
            expires_at: new Date(nowMs + EXECUTION_TTL_MS).toISOString(),
        },
        tabId,
        payloadOrigin: payload.page.origin,
        frameOrigin,
        releasedTargetRole,
    };
}
export function validatePendingExecution(record, activeTabId, activeOrigin, freshFrame, confirmed, nowMs) {
    if (activeTabId !== record.tabId)
        throw new Error('active tab changed after reasoning');
    if (!sameOrigin(activeOrigin, record.payloadOrigin))
        throw new Error('page origin changed after reasoning');
    if (nowMs > Date.parse(record.public.expires_at))
        throw new Error('pending action expired');
    if (record.public.requires_confirmation && !confirmed)
        throw new Error('high-impact action requires explicit local confirmation');
    const action = record.public.action;
    if (containsDirectIdentifier(action.value)) {
        throw new Error('local execution rejected direct-identifier-like generated value');
    }
    if (action.action === 'NAVIGATE') {
        if (!action.url || !sameOrigin(action.url, record.payloadOrigin)) {
            throw new Error('local execution rejected cross-origin navigation');
        }
        return { frameId: null };
    }
    if (action.action === 'WAIT')
        return { frameId: null };
    const frameId = record.public.frame_id;
    if (frameId === null || freshFrame === null)
        throw new Error('fresh frame evidence is required before local execution');
    if (freshFrame.frameId !== frameId)
        throw new Error('fresh frame identity does not match pending action');
    if (record.frameOrigin && !sameOrigin(freshFrame.origin, record.frameOrigin)) {
        throw new Error('target frame origin changed after reasoning');
    }
    if (action.target_id) {
        const freshTarget = freshFrame.elements.find((element) => element.localId === action.target_id);
        if (!freshTarget)
            throw new Error('target DOM node is stale, hidden, offscreen, replaced, or missing');
        if (freshTarget.disabled)
            throw new Error('target became disabled after reasoning');
        if (record.releasedTargetRole && freshTarget.role.toLowerCase() !== record.releasedTargetRole.toLowerCase()) {
            throw new Error('target role changed after reasoning');
        }
    }
    return { frameId };
}
