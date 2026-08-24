const ROLE_COMPATIBILITY = {
    CLICK: new Set(['button', 'link', 'menuitem', 'checkbox', 'radio', 'option']),
    TYPE: new Set(['textbox', 'combobox']),
    SELECT: new Set(['combobox', 'checkbox', 'radio', 'option', 'menuitem']),
};
export function assertLiveElementSecurity(action, snapshot) {
    if (!snapshot.connected)
        throw new Error('target DOM node is no longer connected');
    if (!snapshot.visible)
        throw new Error('target is not visibly present in the viewport');
    const mutating = action.action !== 'READ';
    if (mutating && snapshot.occluded)
        throw new Error('target is visually occluded');
    if (mutating && snapshot.pointerEventsNone)
        throw new Error('target cannot receive pointer interaction');
    if (mutating && (snapshot.disabled || snapshot.ariaDisabled))
        throw new Error('target is disabled');
    const allowed = ROLE_COMPATIBILITY[action.action];
    if (allowed && !allowed.has(snapshot.role.toLowerCase())) {
        throw new Error(`${action.action} is incompatible with live target role ${snapshot.role}`);
    }
    if (action.action === 'TYPE') {
        if (snapshot.credentialLike || snapshot.inputType === 'password' || snapshot.inputType === 'file') {
            throw new Error('server-generated typing into credential/file fields is forbidden');
        }
        const typeable = snapshot.tag === 'input' || snapshot.tag === 'textarea' || snapshot.role.toLowerCase() === 'textbox';
        if (!typeable)
            throw new Error('live target is not locally typeable');
    }
    if (action.action === 'SELECT') {
        const selectable = (snapshot.tag === 'select'
            || snapshot.inputType === 'checkbox'
            || snapshot.inputType === 'radio');
        if (!selectable)
            throw new Error('live target is not a supported local selection control');
    }
}
