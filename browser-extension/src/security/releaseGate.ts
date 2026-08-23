import type { BrowserNetworkAuthorization, BrowserReleasePayload } from '../common/protocol.js'
import { BROWSER_AUTH_SCHEMA, BROWSER_RELEASE_SCHEMA } from '../common/protocol.js'
import { canonicalJson, sha256Hex } from './canonicalJson.js'

function base64ToBytes(value: string): Uint8Array {
  const raw = atob(value)
  const bytes = new Uint8Array(raw.length)
  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index)
  return bytes
}

function isHex64(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value)
}

export async function verifyNetworkAuthorization(
  authorization: BrowserNetworkAuthorization,
  payload: BrowserReleasePayload,
  nowMs = Date.now(),
): Promise<{ allowed: boolean; reason: string }> {
  if (payload.schema !== BROWSER_RELEASE_SCHEMA) return { allowed: false, reason: 'unsupported release payload schema' }
  if (authorization.payload.schema !== BROWSER_AUTH_SCHEMA) return { allowed: false, reason: 'unsupported authorization schema' }
  if (authorization.signature_algorithm !== 'Ed25519') return { allowed: false, reason: 'unsupported signature algorithm' }
  if (authorization.payload.decision !== 'ALLOW_NETWORK_RELEASE') return { allowed: false, reason: 'local privacy gate denied network release' }
  if (authorization.payload.critical_failures !== 0) return { allowed: false, reason: 'critical privacy blocker recorded' }
  if (authorization.payload.proof_score !== 100) return { allowed: false, reason: 'browser privacy proof is incomplete' }
  if (authorization.payload.mandatory_gates < 1 || authorization.payload.mandatory_passed !== authorization.payload.mandatory_gates) {
    return { allowed: false, reason: 'not all mandatory browser privacy gates passed' }
  }
  if (payload.privacy_level < payload.network_privacy_floor) return { allowed: false, reason: 'network privacy floor is not satisfied' }
  if (authorization.payload.session_id !== payload.session_id || authorization.payload.task_id !== payload.task_id) {
    return { allowed: false, reason: 'authorization is bound to another session/task' }
  }

  const issued = Date.parse(authorization.payload.issued_at)
  const expires = Date.parse(authorization.payload.expires_at)
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || nowMs < issued || nowMs > expires || expires <= issued) {
    return { allowed: false, reason: 'network authorization is outside its validity window' }
  }

  const payloadSha = await sha256Hex(payload)
  if (!isHex64(authorization.payload.payload_sha256) || authorization.payload.payload_sha256 !== payloadSha) {
    return { allowed: false, reason: 'release payload commitment mismatch' }
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      base64ToBytes(authorization.payload.signer.public_key_b64),
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    const verified = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      base64ToBytes(authorization.signature_b64),
      new TextEncoder().encode(canonicalJson(authorization.payload)),
    )
    return verified ? { allowed: true, reason: 'signed browser network authorization valid' } : { allowed: false, reason: 'invalid release authorization signature' }
  } catch {
    return { allowed: false, reason: 'unable to verify release authorization signature' }
  }
}
