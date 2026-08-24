import { clipRectToViewport } from '../perception/geometry.js';
const MAX_CAPTURED_ELEMENTS = 2000;
const ids = new WeakMap();
const elementsById = new Map();
function nowMs() {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
}
function localId(element) {
    const existing = ids.get(element);
    if (existing) {
        elementsById.set(existing, element);
        return existing;
    }
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    const token = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    const created = `vg_${token}`;
    ids.set(element, created);
    elementsById.set(created, element);
    return created;
}
export function resolveLocalElement(localIdValue) {
    const element = elementsById.get(localIdValue);
    if (!element || !element.isConnected || ids.get(element) !== localIdValue) {
        elementsById.delete(localIdValue);
        return null;
    }
    return element;
}
function viewportSize() {
    return {
        width: Math.max(document.documentElement.clientWidth, window.innerWidth || 0, 1),
        height: Math.max(document.documentElement.clientHeight, window.innerHeight || 0, 1),
    };
}
function normalizedBox(element) {
    const { width, height } = viewportSize();
    const rect = element.getBoundingClientRect();
    return clipRectToViewport({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }, width, height);
}
function isVisibleInViewport(element) {
    const style = getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity || '1') <= 0)
        return false;
    return normalizedBox(element) !== null;
}
function labelledBy(element) {
    const idsValue = element.getAttribute('aria-labelledby')?.trim();
    if (!idsValue)
        return '';
    return idsValue
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? '')
        .filter(Boolean)
        .join(' ');
}
function associatedLabel(element) {
    if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement))
        return '';
    return Array.from(element.labels ?? []).map((label) => label.textContent?.trim() ?? '').filter(Boolean).join(' ');
}
function accessibleName(element) {
    const candidates = [
        element.getAttribute('aria-label')?.trim() ?? '',
        labelledBy(element),
        associatedLabel(element),
        element.getAttribute('title')?.trim() ?? '',
        element instanceof HTMLInputElement ? element.placeholder.trim() : '',
        element.textContent?.trim() ?? '',
    ];
    return candidates.find(Boolean)?.slice(0, 512) ?? '';
}
export function implicitRole(element) {
    const explicit = element.getAttribute('role')?.trim();
    if (explicit)
        return explicit;
    const tag = element.tagName.toLowerCase();
    if (tag === 'button')
        return 'button';
    if (tag === 'a' && element.hasAttribute('href'))
        return 'link';
    if (tag === 'textarea')
        return 'textbox';
    if (tag === 'select')
        return 'combobox';
    if (tag === 'input') {
        const input = element;
        if (input.type === 'checkbox')
            return 'checkbox';
        if (input.type === 'radio')
            return 'radio';
        if (input.type === 'button' || input.type === 'submit' || input.type === 'reset')
            return 'button';
        return 'textbox';
    }
    if (/^h[1-6]$/.test(tag))
        return 'heading';
    return tag;
}
export function privacyHints(element) {
    const hints = [];
    const tokens = [
        element.getAttribute('name'),
        element.getAttribute('id'),
        element.getAttribute('autocomplete'),
        element.getAttribute('aria-label'),
        element.getAttribute('placeholder'),
        element instanceof HTMLInputElement ? element.type : null,
    ]
        .filter((value) => Boolean(value))
        .join(' ')
        .toLowerCase();
    const classes = [
        [/pass(word|code)?|pin|otp|cvv|secret/, 'credential'],
        [/email|e-mail/, 'email'],
        [/phone|mobile|tel/, 'phone'],
        [/name|given-name|family-name/, 'person_name'],
        [/aadhaar|aadhar|pan|passport|license|licence|national.?id/, 'government_identifier'],
        [/address|postcode|postal|zip|city|locality/, 'location'],
        [/card|account|iban|ifsc|upi|bank/, 'financial'],
        [/dob|birth|age/, 'quasi_identifier'],
        [/patient|medical|health|diagnos/, 'health'],
    ];
    for (const [pattern, label] of classes)
        if (pattern.test(tokens))
            hints.push(label);
    return hints;
}
function shouldCapture(element) {
    if (!isVisibleInViewport(element))
        return false;
    const tag = element.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'svg', 'path', 'meta', 'link'].includes(tag))
        return false;
    if (element.matches('button,a[href],input,textarea,select,[role],[contenteditable="true"],h1,h2,h3,h4,h5,h6,label'))
        return true;
    const text = element.textContent?.trim() ?? '';
    return text.length > 0 && text.length <= 512 && element.children.length === 0;
}
function collectRoots() {
    const roots = [document];
    const visit = (root) => {
        for (const element of Array.from(root.querySelectorAll('*'))) {
            if (element.shadowRoot) {
                roots.push(element.shadowRoot);
                visit(element.shadowRoot);
            }
        }
    };
    visit(document);
    return roots;
}
export function captureFrame() {
    const started = nowMs();
    for (const [localIdValue, element] of elementsById) {
        if (!element.isConnected)
            elementsById.delete(localIdValue);
    }
    const roots = collectRoots();
    const candidates = [];
    for (const root of roots)
        candidates.push(...Array.from(root.querySelectorAll('*')).filter(shouldCapture));
    // Deduplicate elements that can appear in nested root traversals. We record
    // truncation explicitly instead of silently pretending the DOM view is whole.
    const eligible = Array.from(new Set(candidates));
    const unique = eligible.slice(0, MAX_CAPTURED_ELEMENTS);
    const elements = [];
    for (const element of unique) {
        const bbox = normalizedBox(element);
        if (!bbox)
            continue;
        const input = element instanceof HTMLInputElement ? element : null;
        const textarea = element instanceof HTMLTextAreaElement ? element : null;
        const select = element instanceof HTMLSelectElement ? element : null;
        const rawValue = input?.value ?? textarea?.value ?? select?.value;
        elements.push({
            localId: localId(element),
            tag: element.tagName.toLowerCase(),
            role: implicitRole(element),
            accessibleName: accessibleName(element),
            visibleText: (element.textContent?.trim() ?? '').slice(0, 512),
            ...(input ? { inputType: input.type } : {}),
            ...(rawValue ? { rawValue: rawValue.slice(0, 2048) } : {}),
            disabled: (element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) ? element.disabled : false,
            ...(input?.type === 'checkbox' || input?.type === 'radio' ? { checked: input.checked } : {}),
            ...(element instanceof HTMLOptionElement ? { selected: element.selected } : {}),
            bbox,
            privacyHints: privacyHints(element),
        });
    }
    let inaccessibleDescendantFrames = 0;
    for (const frame of Array.from(document.querySelectorAll('iframe'))) {
        try {
            void frame.contentDocument?.documentElement;
        }
        catch {
            inaccessibleDescendantFrames += 1;
        }
    }
    const { width: viewportWidth, height: viewportHeight } = viewportSize();
    const documentElement = document.documentElement;
    return {
        frameId: -1,
        isTopFrame: window.top === window,
        origin: location.origin,
        href: location.href,
        title: document.title.slice(0, 512),
        viewportWidth,
        viewportHeight,
        devicePixelRatioBasisPoints: Math.max(1000, Math.min(80_000, Math.round((window.devicePixelRatio || 1) * 10_000))),
        scrollX: Math.round(window.scrollX),
        scrollY: Math.round(window.scrollY),
        documentWidth: Math.max(documentElement.scrollWidth, documentElement.clientWidth, 1),
        documentHeight: Math.max(documentElement.scrollHeight, documentElement.clientHeight, 1),
        elements,
        eligibleElementCount: eligible.length,
        capturedElementCount: elements.length,
        captureTruncated: eligible.length > MAX_CAPTURED_ELEMENTS,
        shadowRootCount: Math.max(0, roots.length - 1),
        captureElapsedMs: Math.max(0, Math.round(nowMs() - started)),
        inaccessibleDescendantFrames,
    };
}
