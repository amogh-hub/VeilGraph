import type { BrowserPairingAttestation, TrustedCompanionSigner } from '../common/protocol.js'
import { canonicalJson } from './canonicalJson.js'

const TRUST_KEY = 'veilgraphTrustedCompanionSignerV1'

function base64ToBytes(value: string): Uint8Array {
  const raw = atob(value)
  const bytes = new Uint8Array(raw.length)
  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index)
  return bytes
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function publicKeyFingerprint(publicKeyB64: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', base64ToBytes(publicKeyB64))
  return toHex(digest)
}

function randomChallenge(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function isTrustedSigner(value: unknown): value is TrustedCompanionSigner {
  if (!value || typeof value !== 'object') return false
  const item = value as Partial<TrustedCompanionSigner>
  return typeof item.publicKeyB64 === 'string'
    && typeof item.publicKeySha256 === 'string'
    && /^[0-9a-f]{64}$/.test(item.publicKeySha256)
    && typeof item.pairedAt === 'string'
}

export async function getTrustedCompanionSigner(): Promise<TrustedCompanionSigner | null> {
  const stored = await chrome.storage.local.get(TRUST_KEY)
  const value = stored[TRUST_KEY]
  return isTrustedSigner(value) ? value : null
}

export async function pairLocalCompanion(nowMs?: number): Promise<TrustedCompanionSigner> {
  const challenge = randomChallenge()
  const response = await fetch('http://127.0.0.1:8000/api/v1/browser/pair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    body: JSON.stringify({ challenge }),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) throw new Error(`local pairing endpoint returned HTTP ${response.status}`)
  const raw = await response.json() as BrowserPairingAttestation
  if (!raw?.payload || raw.payload.schema !== 'veilgraph.browser-companion-pairing.v1') {
    throw new Error('local companion pairing schema is invalid')
  }
  if (raw.signature_algorithm !== 'Ed25519') throw new Error('local companion pairing signature algorithm is unsupported')
  if (raw.payload.challenge !== challenge || raw.payload.purpose !== 'PAIR_LOCAL_VEILGRAPH_COMPANION') {
    throw new Error('local companion pairing challenge mismatch')
  }
  const issued = Date.parse(raw.payload.issued_at)
  const expires = Date.parse(raw.payload.expires_at)
  const verificationNowMs = nowMs ?? Date.now()
  if (
    !Number.isFinite(issued)
    || !Number.isFinite(expires)
    || verificationNowMs < issued
    || verificationNowMs > expires
    || expires <= issued
  ) {
    throw new Error('local companion pairing attestation is outside its validity window')
  }

  const computedFingerprint = await publicKeyFingerprint(raw.payload.signer.public_key_b64)
  if (computedFingerprint !== raw.payload.signer.public_key_sha256) {
    throw new Error('local companion public-key fingerprint mismatch')
  }
  const publicKey = await crypto.subtle.importKey(
    'raw',
    base64ToBytes(raw.payload.signer.public_key_b64),
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
  const signatureValid = await crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    base64ToBytes(raw.signature_b64),
    new TextEncoder().encode(canonicalJson(raw.payload)),
  )
  if (!signatureValid) throw new Error('local companion pairing signature is invalid')

  const existing = await getTrustedCompanionSigner()
  if (existing && (existing.publicKeySha256 !== computedFingerprint || existing.publicKeyB64 !== raw.payload.signer.public_key_b64)) {
    throw new Error('local companion signing identity changed; trust reset is required before re-pairing')
  }

  const trusted: TrustedCompanionSigner = {
    publicKeyB64: raw.payload.signer.public_key_b64,
    publicKeySha256: computedFingerprint,
    pairedAt: new Date(verificationNowMs).toISOString(),
  }
  await chrome.storage.local.set({ [TRUST_KEY]: trusted })
  return trusted
}

export async function signerMatchesPinnedTrust(publicKeyB64: string, fingerprint: string): Promise<boolean> {
  const trusted = await getTrustedCompanionSigner()
  if (!trusted) return false
  if (trusted.publicKeyB64 !== publicKeyB64 || trusted.publicKeySha256 !== fingerprint) return false
  return await publicKeyFingerprint(publicKeyB64) === fingerprint
}
