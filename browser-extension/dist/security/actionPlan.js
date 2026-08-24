const ACTIONS = new Set(['CLICK', 'SCROLL', 'TYPE', 'SELECT', 'NAVIGATE', 'READ', 'WAIT']);
const HIGH_IMPACT = new Set([
    'submit', 'confirm', 'send', 'pay', 'purchase', 'buy', 'checkout', 'delete',
    'remove', 'transfer', 'book', 'reserve', 'save', 'sign', 'agree', 'authorize',
]);
const TARGET_ROLES = {
    CLICK: new Set(['button', 'link', 'menuitem', 'checkbox', 'radio', 'option']),
    TYPE: new Set(['textbox', 'combobox']),
    SELECT: new Set(['combobox', 'checkbox', 'radio', 'option', 'menuitem']),
};
const DIRECT_PATTERNS = [
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,
    /[A-Z]{5}[0-9]{4}[A-Z]/i,
    /(?:\d[ -]?){12}/,
    /(?:\d[ -]?){13,19}/,
    /(?:\+?\d[\s().-]*){10,15}/,
];
function record(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('reasoning response must be an object');
    return value;
}
function sameOrigin(left, right) {
    const a = new URL(left);
    const b = new URL(right);
    return a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
}
function targetText(payload, action) {
    const target = action.target_id
        ? payload.page.elements.find((element) => element.element_id === action.target_id)
        : undefined;
    return [
        payload.task,
        action.reason,
        action.value ?? '',
        action.url ?? '',
        target?.label ?? '',
        target?.text ?? '',
        target?.role ?? '',
    ].join(' ').toLowerCase();
}
function highImpact(payload, action) {
    const words = targetText(payload, action).match(/[a-z]+/g) ?? [];
    return words.some((word) => HIGH_IMPACT.has(word));
}
function validateActionShape(action) {
    if (!ACTIONS.has(action.action))
        throw new Error(`unsupported action ${String(action.action)}`);
    const targeted = new Set(['CLICK', 'TYPE', 'SELECT', 'READ']);
    if (targeted.has(action.action) !== Boolean(action.target_id)) {
        throw new Error(`${action.action} target_id shape is invalid`);
    }
    if ((action.action === 'TYPE' || action.action === 'SELECT') !== Boolean(action.value)) {
        throw new Error(`${action.action} value shape is invalid`);
    }
    if ((action.action === 'NAVIGATE') !== Boolean(action.url)) {
        throw new Error(`${action.action} url shape is invalid`);
    }
    if ((action.action === 'SCROLL') !== (typeof action.scroll_delta_y === 'number' && action.scroll_delta_y !== 0)) {
        throw new Error(`${action.action} scroll_delta_y shape is invalid`);
    }
    if ((action.action === 'WAIT') !== (typeof action.wait_ms === 'number' && action.wait_ms > 0)) {
        throw new Error(`${action.action} wait_ms shape is invalid`);
    }
    if (!Number.isInteger(action.confidence_basis_points) || action.confidence_basis_points < 0 || action.confidence_basis_points > 10000) {
        throw new Error('action confidence is outside 0..10000 basis points');
    }
    if (!action.reason || action.reason.length > 300)
        throw new Error('action reason is invalid');
}
export function validateReasoningResponse(raw, payload, expectedPayloadSha256) {
    const response = record(raw);
    if (response.schema !== 'veilgraph.browser-reasoning-response.v1')
        throw new Error('unsupported reasoning response schema');
    const plan = record(response.plan);
    if (plan.schema !== 'veilgraph.browser-action-plan.v1')
        throw new Error('unsupported action-plan schema');
    if (plan.session_id !== payload.session_id || plan.task_id !== payload.task_id) {
        throw new Error('reasoning action plan is not bound to this release payload');
    }
    if (!Array.isArray(plan.actions) || plan.actions.length > 8) {
        throw new Error('reasoning action plan exceeds 8 actions');
    }
    if (plan.complete === true && plan.actions.length !== 0) {
        throw new Error('complete reasoning plan must not contain further actions');
    }
    if (plan.complete !== true && plan.actions.length === 0) {
        throw new Error('incomplete reasoning plan requires at least one action');
    }
    const elements = new Map(payload.page.elements.map((element) => [element.element_id, element]));
    for (const rawAction of plan.actions) {
        const action = record(rawAction);
        validateActionShape(action);
        if (action.target_id) {
            const target = elements.get(action.target_id);
            if (!target)
                throw new Error(`reasoning server invented target ${action.target_id}`);
            if (target.disabled && action.action !== 'READ')
                throw new Error(`reasoning server targeted disabled element ${action.target_id}`);
            const allowed = TARGET_ROLES[action.action];
            if (allowed && !allowed.has(target.role.toLowerCase())) {
                throw new Error(`${action.action} is incompatible with target role ${target.role}`);
            }
        }
        if (action.value && DIRECT_PATTERNS.some((pattern) => pattern.test(action.value ?? ''))) {
            throw new Error('reasoning server generated direct-identifier-like input');
        }
        if (action.action === 'NAVIGATE' && action.url && !sameOrigin(action.url, payload.page.origin)) {
            throw new Error('cross-origin NAVIGATE is blocked by SANITIZED_REASONING_ACTION_V1');
        }
        if (highImpact(payload, action) && !action.requires_confirmation) {
            throw new Error('high-impact server action omitted required local confirmation');
        }
    }
    const evidence = record(response.evidence);
    if (evidence.authorization_verified !== true
        || evidence.structured_output_validated !== true
        || evidence.target_ids_validated !== true
        || evidence.signer_trusted !== true
        || evidence.replay_protected !== true) {
        throw new Error('reasoning server did not prove required validation invariants');
    }
    if (typeof evidence.payload_sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(evidence.payload_sha256)
        || evidence.payload_sha256 !== expectedPayloadSha256) {
        throw new Error('reasoning response payload commitment does not match the signed release');
    }
    return raw;
}
