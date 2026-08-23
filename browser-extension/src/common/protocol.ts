export const BROWSER_RELEASE_SCHEMA = 'veilgraph.browser-release-payload.v1' as const
export const BROWSER_AUTH_SCHEMA = 'veilgraph.browser-network-authorization.v1' as const

export type NetworkDecision = 'ALLOW_NETWORK_RELEASE' | 'DENY_NETWORK_RELEASE'
export type LocalPerceptionStatus = 'READY' | 'PARTIAL' | 'UNAVAILABLE' | 'ERROR'
export type PerceptionModality = 'DOM' | 'ACCESSIBILITY' | 'VISUAL'

export interface PublicElement {
  element_id: `vg_${string}`
  role: string
  label: string
  text: string
  control_type?: string | null
  disabled: boolean
  checked?: boolean | null
  selected?: boolean | null
  /** Viewport basis points [x0,y0,x1,y1], each 0..10000. */
  bbox?: [number, number, number, number] | null
}

export interface PublicVisualContext {
  mime_type: 'image/webp' | 'image/png'
  width: number
  height: number
  image_base64: string
  sanitized_sha256: string
  redacted_regions: number
}

export interface PublicPage {
  origin: string
  page_class: string
  title: string
  elements: PublicElement[]
  visual_context?: PublicVisualContext | null
}

export interface BrowserReleasePayload {
  schema: typeof BROWSER_RELEASE_SCHEMA
  session_id: string
  task_id: string
  task: string
  page: PublicPage
  privacy_level: number
  network_privacy_floor: number
  identity_exposure_before: number
  residual_identity_exposure: number
  task_utility_score: number
  minimization_basis_points: number
}

export interface BrowserNetworkAuthorizationPayload {
  schema: typeof BROWSER_AUTH_SCHEMA
  authorization_id: `VGN-${string}`
  decision: NetworkDecision
  payload_sha256: string
  session_id: string
  task_id: string
  issued_at: string
  expires_at: string
  nonce: string
  proof_score: number
  mandatory_gates: number
  mandatory_passed: number
  critical_failures: number
  identity_exposure_before: number
  residual_identity_exposure: number
  task_utility_score: number
  signer: {
    algorithm: 'Ed25519'
    public_key_b64: string
    public_key_sha256: string
  }
  disclaimer: string
}

export interface BrowserNetworkAuthorization {
  payload: BrowserNetworkAuthorizationPayload
  signature_algorithm: 'Ed25519'
  signature_b64: string
}

export interface BrowserPairingPayload {
  schema: 'veilgraph.browser-companion-pairing.v1'
  challenge: string
  purpose: 'PAIR_LOCAL_VEILGRAPH_COMPANION'
  issued_at: string
  expires_at: string
  signer: {
    algorithm: 'Ed25519'
    public_key_b64: string
    public_key_sha256: string
  }
}

export interface BrowserPairingAttestation {
  payload: BrowserPairingPayload
  signature_algorithm: 'Ed25519'
  signature_b64: string
}

export interface TrustedCompanionSigner {
  publicKeyB64: string
  publicKeySha256: string
  pairedAt: string
}

export interface BrowserGateResult {
  name: string
  status: 'PASS' | 'FAIL' | 'INCONCLUSIVE'
  detail: string
  attack_class: string
  severity: 'critical' | 'high' | 'medium'
  mandatory: boolean
}

export interface BrowserVerificationSummary {
  tests: BrowserGateResult[]
  proof_score: number
  critical_failures: number
  policy_floor_satisfied: boolean
  forbidden_raw_fields_present: boolean
  payload_commitment_valid: boolean
  critical_exposure_present: boolean
}

export interface BrowserReleasePreparation {
  schema: 'veilgraph.browser-release-preparation.v1'
  analysis: Record<string, unknown>
  payload: BrowserReleasePayload
  verification: BrowserVerificationSummary
  authorization: BrowserNetworkAuthorization
}

export interface CapturedElement {
  localId: `vg_${string}`
  tag: string
  role: string
  accessibleName: string
  visibleText: string
  inputType?: string
  rawValue?: string
  disabled: boolean
  checked?: boolean
  selected?: boolean
  bbox: [number, number, number, number]
  privacyHints: string[]
}

export interface FrameCapture {
  frameId: number
  isTopFrame: boolean
  origin: string
  href: string
  title: string
  viewportWidth: number
  viewportHeight: number
  devicePixelRatioBasisPoints: number
  scrollX: number
  scrollY: number
  documentWidth: number
  documentHeight: number
  elements: CapturedElement[]
  eligibleElementCount: number
  capturedElementCount: number
  captureTruncated: boolean
  shadowRootCount: number
  captureElapsedMs: number
  inaccessibleDescendantFrames: number
}

export interface VisualCapability {
  name: 'SCREENSHOT_DECODE' | 'FACE_DETECTION' | 'QR_DETECTION' | 'TEXT_REGION_DETECTION' | 'DOM_SENSITIVE_PROJECTION'
  status: 'READY' | 'UNAVAILABLE' | 'ERROR'
  backend: string
  required: boolean
  detail: string
}

export interface VisualStageTimings {
  screenshotDecodeMs: number
  domProjectionMs: number
  faceDetectionMs: number
  qrDetectionMs: number
  textRegionMs: number
  fusionMs: number
}

export interface VisualPerceptionReport {
  status: LocalPerceptionStatus
  modelId: string
  backend: 'browser-native'
  elapsedMs: number
  imageWidth: number
  imageHeight: number
  capabilities: VisualCapability[]
  findingCount: number
  stageTimingsMs: VisualStageTimings
}

export interface CaptureTimings {
  frameDomMs: number
  screenshotCaptureMs: number
  visualPerceptionMs: number
  totalLocalMs: number
}

export interface CaptureCoverageItem {
  name: 'DOM' | 'ACCESSIBILITY' | 'VISUAL' | 'TEXT_REGIONS' | 'FACE' | 'QR'
  status: LocalPerceptionStatus
  required: boolean
  detail: string
}

export interface PageCaptureBundle {
  schema: 'veilgraph.browser-local-capture.v1'
  captureId: `VGC-${string}`
  capturedAt: string
  tabId: number
  screenshotDataUrl: string
  frames: FrameCapture[]
  expectedFrameCount: number
  capturedFrameCount: number
  failedFrameIds: number[]
  captureTimings: CaptureTimings
  coverage: CaptureCoverageItem[]
  visualPerceptionStatus: LocalPerceptionStatus
  visualPerceptionReport: VisualPerceptionReport
  visualFindings: VisualFinding[]
}

export interface VisualFinding {
  findingId: string
  type: 'FACE' | 'QR_CODE' | 'TEXT_REGION' | 'PASSWORD_FIELD' | 'SENSITIVE_REGION' | 'OTHER'
  confidenceBasisPoints: number
  bbox: [number, number, number, number]
  label?: string
  provider?: string
  modalities?: PerceptionModality[]
  relatedElementIds?: Array<`vg_${string}`>
}

export type BrowserActionType = 'CLICK' | 'SCROLL' | 'TYPE' | 'SELECT' | 'NAVIGATE' | 'READ' | 'WAIT'

export interface BrowserAction {
  action: BrowserActionType
  target_id?: `vg_${string}`
  value?: string
  confidence_basis_points: number
  reason: string
  requires_confirmation: boolean
}

export interface BrowserActionPlan {
  schema: 'veilgraph.browser-action-plan.v1'
  session_id: string
  task_id: string
  actions: BrowserAction[]
}

export type RuntimeRequest =
  | { type: 'VG_CAPTURE_ACTIVE_PAGE' }
  | { type: 'VG_PAIR_LOCAL_COMPANION' }
  | { type: 'VG_ANALYSE_ACTIVE_PAGE'; task: string; audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS'; privacyLevel: 1 | 2 | 3 | 4 | 5 }
  | { type: 'VG_PREPARE_ACTIVE_PAGE'; task: string; audienceProfile: 'PUBLIC_RELEASE' | 'RESEARCH_PARTNER' | 'INTERNAL_OPERATIONS'; privacyLevel: 1 | 2 | 3 | 4 | 5 }
  | { type: 'VG_CAPTURE_FRAME' }
  | { type: 'VG_GET_STATUS' }

export type RuntimeResponse =
  | { ok: true; data: unknown }
  | { ok: false; error: string }
