import { canonicalJson } from './canonicalJson.js';
const TRUST_KEY = 'veilgraphTrustedCompanionSignerV1';
function base64ToBytes(value) {
    const raw = atob(value);
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) {
        bytes[index] = raw.charCodeAt(index);
    }
    return bytes;
}
function bytesToBase64(bytes) {
    let binary = '';
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary);
}
function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}
function toHex(bytes) {
    return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
async function publicKeyFingerprint(publicKeyB64) {
    const digest = await crypto.subtle.digest('SHA-256', base64ToBytes(publicKeyB64));
    return toHex(digest);
}
function randomChallenge() {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}
function isTrustedSigner(value) {
    if (!value
        || typeof value !== 'object')
        return false;
    const item = value;
    return (typeof item.publicKeyB64 === 'string'
        && typeof item.publicKeySha256 === 'string'
        && /^[0-9a-f]{64}$/.test(item.publicKeySha256)
        && typeof item.pairedAt === 'string');
}
export async function getTrustedCompanionSigner() {
    const stored = await chrome.storage.local.get(TRUST_KEY);
    const value = stored[TRUST_KEY];
    return isTrustedSigner(value)
        ? value
        : null;
}
function validateAttestationWindow(issuedAt, expiresAt, nowMs) {
    const issued = Date.parse(issuedAt);
    const expires = Date.parse(expiresAt);
    if (!Number.isFinite(issued)
        || !Number.isFinite(expires)
        || nowMs < issued
        || nowMs > expires
        || expires <= issued) {
        throw new Error('local companion attestation is outside its validity window');
    }
}
async function verifyEd25519Attestation(payload, signatureB64, publicKeyB64) {
    const publicKey = await crypto.subtle.importKey('raw', base64ToBytes(publicKeyB64), { name: 'Ed25519' }, false, ['verify']);
    const valid = await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, base64ToBytes(signatureB64), new TextEncoder().encode(canonicalJson(payload)));
    if (!valid) {
        throw new Error('local companion attestation signature is invalid');
    }
}
export async function pairLocalCompanion(nowMs) {
    const challenge = randomChallenge();
    const response = await fetch('http://127.0.0.1:8000/api/v1/browser/pair', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
        },
        body: JSON.stringify({ challenge }),
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
    });
    if (!response.ok) {
        throw new Error(`local pairing endpoint returned HTTP ${response.status}`);
    }
    const raw = await response.json();
    if (!raw?.payload
        || raw.payload.schema
            !== 'veilgraph.browser-companion-pairing.v1') {
        throw new Error('local companion pairing schema is invalid');
    }
    if (raw.signature_algorithm !== 'Ed25519') {
        throw new Error('local companion pairing signature algorithm is unsupported');
    }
    if (raw.payload.challenge !== challenge
        || raw.payload.purpose
            !== 'PAIR_LOCAL_VEILGRAPH_COMPANION') {
        throw new Error('local companion pairing challenge mismatch');
    }
    const verificationNowMs = nowMs ?? Date.now();
    validateAttestationWindow(raw.payload.issued_at, raw.payload.expires_at, verificationNowMs);
    const computedFingerprint = await publicKeyFingerprint(raw.payload.signer.public_key_b64);
    if (computedFingerprint
        !== raw.payload.signer.public_key_sha256) {
        throw new Error('local companion public-key fingerprint mismatch');
    }
    await verifyEd25519Attestation(raw.payload, raw.signature_b64, raw.payload.signer.public_key_b64);
    const existing = await getTrustedCompanionSigner();
    if (existing
        && (existing.publicKeySha256
            !== computedFingerprint
            || existing.publicKeyB64
                !== raw.payload.signer.public_key_b64)) {
        throw new Error('local companion signing identity changed; trust reset is required before re-pairing');
    }
    const trusted = {
        publicKeyB64: raw.payload.signer.public_key_b64,
        publicKeySha256: computedFingerprint,
        pairedAt: new Date(verificationNowMs).toISOString(),
    };
    await chrome.storage.local.set({
        [TRUST_KEY]: trusted,
    });
    return trusted;
}
export async function signerMatchesPinnedTrust(publicKeyB64, fingerprint) {
    const trusted = await getTrustedCompanionSigner();
    if (!trusted)
        return false;
    if (trusted.publicKeyB64 !== publicKeyB64
        || trusted.publicKeySha256 !== fingerprint)
        return false;
    return (await publicKeyFingerprint(publicKeyB64)) === fingerprint;
}
export async function createTrustedCompanionTransportSession(endpoint, nowMs) {
    const trusted = await getTrustedCompanionSigner();
    if (!trusted) {
        throw new Error('Pair the trusted local companion before any raw browser capture can be delivered.');
    }
    const challenge = randomChallenge();
    const ephemeral = (await crypto.subtle.generateKey({
        name: 'ECDH',
        namedCurve: 'P-256',
    }, true, ['deriveBits']));
    const clientPublicBytes = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
    const clientPublicKeyB64 = bytesToBase64(clientPublicBytes);
    // This request contains only a random challenge + ephemeral public
    // key. No DOM text, screenshot, task, or user data is present.
    const response = await fetch('http://127.0.0.1:8000/api/v1/browser/transport-session', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
        },
        body: JSON.stringify({
            challenge,
            client_public_key_b64: clientPublicKeyB64,
            endpoint,
        }),
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
    });
    if (!response.ok) {
        throw new Error(`local encrypted-transport session returned HTTP ${response.status}`);
    }
    const raw = await response.json();
    if (!raw?.payload
        || raw.payload.schema
            !== 'veilgraph.browser-companion-transport.v1') {
        throw new Error('local encrypted-transport schema is invalid');
    }
    if (raw.signature_algorithm !== 'Ed25519'
        || raw.payload.purpose
            !== 'PROTECT_RAW_BROWSER_CAPTURE'
        || raw.payload.challenge !== challenge
        || raw.payload.endpoint !== endpoint
        || raw.payload.client_public_key_b64
            !== clientPublicKeyB64) {
        throw new Error('local encrypted-transport attestation binding mismatch');
    }
    const verificationNowMs = nowMs ?? Date.now();
    validateAttestationWindow(raw.payload.issued_at, raw.payload.expires_at, verificationNowMs);
    const signerFingerprint = await publicKeyFingerprint(raw.payload.signer.public_key_b64);
    if (signerFingerprint
        !== raw.payload.signer.public_key_sha256
        || signerFingerprint
            !== trusted.publicKeySha256
        || raw.payload.signer.public_key_b64
            !== trusted.publicKeyB64) {
        throw new Error('encrypted transport was not authenticated by the pinned companion identity');
    }
    await verifyEd25519Attestation(raw.payload, raw.signature_b64, trusted.publicKeyB64);
    const companionPublic = await crypto.subtle.importKey('raw', base64ToBytes(raw.payload
        .companion_ephemeral_public_key_b64), {
        name: 'ECDH',
        namedCurve: 'P-256',
    }, false, []);
    const sharedSecret = await crypto.subtle.deriveBits({
        name: 'ECDH',
        public: companionPublic,
    }, ephemeral.privateKey, 256);
    const hkdfInput = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const salt = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${raw.payload.session_id}|${challenge}`));
    const key = await crypto.subtle.deriveKey({
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: new TextEncoder().encode(`veilgraph.browser-local-transport.v1|${endpoint}`),
    }, hkdfInput, {
        name: 'AES-GCM',
        length: 256,
    }, false, ['encrypt']);
    return {
        sessionId: raw.payload.session_id,
        endpoint,
        key,
    };
}
