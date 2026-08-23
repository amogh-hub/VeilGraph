import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { api } from './api/client'
import type {
  Analysis,
  AuditLedger,
  AudienceProfile,
  Certificate,
  Destruction,
  EntityWithMentions,
  ExposureGraph,
  FileRecord,
  GraphNode,
  Job,
  OfflineStatus,
  PrivacyLevel,
  PrivacyRecommendation,
  TransformResult,
  Verification,
} from './api/types'

type BusyStep = 'create' | 'upload' | 'analyse' | 'review' | 'graph' | 'transform' | 'verify' | 'destroy' | null
type WorkspaceStep = 'understand' | 'protect' | 'verify' | 'release'
type ThemeMode = 'dark' | 'light'

const levelDetails: Record<PrivacyLevel, { title: string; description: string }> = {
  1: {
    title: 'Level 1 · Direct masking',
    description: 'Masks obvious contact and credential values. Indirect reconstruction clues remain visible.',
  },
  2: {
    title: 'Level 2 · Opaque pseudonymization',
    description: 'Replaces names, credentials, exact dates and precise address identifiers with opaque structural tokens.',
  },
  3: {
    title: 'Level 3 · Context generalization',
    description: 'Masks direct identifiers and converts exact age, birth, location and employment clues into broader categories.',
  },
  4: {
    title: 'Level 4 · Relationship-safe pseudonymization',
    description: 'Uses stable aliases across pages and relationships while generalizing high-uniqueness context.',
  },
  5: {
    title: 'Level 5 · Synthetic Twin',
    description: 'For structured datasets: generates a source-independent Synthetic Twin, then can export the verified synthetic population as CSV, JSON, XLSX, DOCX or PDF without re-reading the original source.',
  },
}

const audienceLabels: Record<AudienceProfile, string> = {
  PUBLIC_RELEASE: 'Public release',
  RESEARCH_PARTNER: 'Research partner',
  INTERNAL_OPERATIONS: 'Internal operations',
}

const visualTypes = new Set(['FACE', 'QR_CODE', 'SIGNATURE_CANDIDATE'])
const quasiTypes = new Set(['DATE_OF_BIRTH', 'GENERIC_DATE', 'AGE', 'STREET_ADDRESS', 'BUILDING_NUMBER', 'LOCALITY', 'POSTCODE', 'EMPLOYER', 'JOB_TITLE', 'PERSON_TITLE', 'DEMOGRAPHIC_ATTRIBUTE'])

function truncate(value: string, max = 27) {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}

const entityTypeLabels: Record<string, string> = {
  PHONE: 'Phone number', EMAIL: 'Email address', AADHAAR_LIKE: 'Aadhaar-like identifier', PAN_LIKE: 'PAN-like identifier',
  PERSON_NAME: 'Person name', PERSON_TITLE: 'Person title', DATE_OF_BIRTH: 'Date of birth', GENERIC_DATE: 'Date', AGE: 'Age',
  STREET_ADDRESS: 'Street address', BUILDING_NUMBER: 'Building number', LOCALITY: 'Location', POSTCODE: 'Postal code', EMPLOYER: 'Organisation',
  JOB_TITLE: 'Job title', CASE_REFERENCE: 'Case reference', NATIONAL_ID: 'National identifier', PASSPORT_NUMBER: 'Passport number',
  DRIVER_LICENSE_NUMBER: 'Driver licence number', TAX_IDENTIFIER: 'Tax identifier', SOCIAL_IDENTIFIER: 'Social identifier',
  PAYMENT_CARD_NUMBER: 'Payment card', DEMOGRAPHIC_ATTRIBUTE: 'Demographic attribute', FACE: 'Face', QR_CODE: 'QR code',
  SIGNATURE_CANDIDATE: 'Signature',
}

function humanizeToken(value?: string | null) {
  if (!value) return 'Identity evidence'
  return entityTypeLabels[value] ?? value.toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function graphNodeText(node: GraphNode) {
  if (node.kind === 'DOCUMENT') return { title: 'Source document', meta: node.label }
  if (node.kind === 'SUBJECT') return { title: 'Primary subject', meta: node.label }
  if (node.kind === 'RELATED_PERSON') return { title: 'Related person', meta: node.label }
  return {
    title: humanizeToken(node.entity_type ?? node.kind),
    meta: `${node.label}${node.mention_count ? ` · ${node.mention_count} mention${node.mention_count === 1 ? '' : 's'}` : ''}`,
  }
}

function humanizeGate(value: string) {
  return value
    .replaceAll('_', ' ')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function ImportMark({ ready = false }: { ready?: boolean }) {
  return (
    <svg className="import-mark" viewBox="0 0 48 48" aria-hidden="true">
      <path className="import-document" d="M13.5 7.5h13.8l7.2 7.2v25.8h-21z" />
      <path className="import-fold" d="M27.3 7.5v7.3h7.2" />
      <path className="import-link" d="M19 24.5l5-4.2 6 5.2M19 24.5l5 6.2 6-5.2" />
      <circle className="import-node" cx="19" cy="24.5" r="2.15" />
      <circle className="import-node" cx="24" cy="20.3" r="2.15" />
      <circle className="import-node" cx="30" cy="25.5" r="2.15" />
      <circle className="import-node" cx="24" cy="30.7" r="2.15" />
      {ready && <path className="import-ready" d="M18.7 25.4l3.1 3.2 7.6-8.1" />}
    </svg>
  )
}

type DisplayGraphNode = {
  id: string
  kind: GraphNode['kind']
  label: string
  meta: string
}

type DisplayGraphEdge = {
  id: string
  source: string
  target: string
  edge_type: string
}

function GraphCanvas({
  graph,
  compact = false,
  focusNodeIds = null,
  focusLabel = null,
}: {
  graph: ExposureGraph
  compact?: boolean
  focusNodeIds?: string[] | null
  focusLabel?: string | null
}) {
  const [showDetailed, setShowDetailed] = useState(false)
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null)
  const summarized = compact && !showDetailed

  const displayGraph = useMemo(() => {
    const originalToDisplay = new Map<string, string>()
    if (!summarized) {
      const nodes = graph.nodes.map((node) => {
        originalToDisplay.set(node.id, node.id)
        const presentation = graphNodeText(node)
        return {
          id: node.id,
          kind: node.kind,
          label: presentation.title,
          meta: presentation.meta,
        } as DisplayGraphNode
      })
      return {
        nodes,
        edges: graph.edges.map((edge) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          edge_type: edge.edge_type,
        } as DisplayGraphEdge)),
        collapsedCount: 0,
        originalToDisplay,
      }
    }

    const fixedNodes: DisplayGraphNode[] = []
    const clusters = new Map<string, {
      id: string
      kind: GraphNode['kind']
      entityType: string
      entityCount: number
      mentionCount: number
    }>()

    graph.nodes.forEach((node) => {
      if (node.kind === 'DOCUMENT' || node.kind === 'SUBJECT') {
        originalToDisplay.set(node.id, node.id)
        const presentation = graphNodeText(node)
        fixedNodes.push({ id: node.id, kind: node.kind, label: presentation.title, meta: presentation.meta })
        return
      }

      const entityType = String(node.entity_type ?? node.kind)
      const clusterId = `cluster:${entityType}`
      originalToDisplay.set(node.id, clusterId)
      const current = clusters.get(clusterId)
      if (current) {
        current.entityCount += 1
        current.mentionCount += node.mention_count ?? 0
      } else {
        clusters.set(clusterId, {
          id: clusterId,
          kind: node.kind,
          entityType,
          entityCount: 1,
          mentionCount: node.mention_count ?? 0,
        })
      }
    })

    const clusterNodes: DisplayGraphNode[] = Array.from(clusters.values())
      .sort((a, b) => a.entityType.localeCompare(b.entityType))
      .map((cluster) => ({
        id: cluster.id,
        kind: cluster.kind,
        label: humanizeToken(cluster.entityType),
        meta: `${cluster.entityCount} entit${cluster.entityCount === 1 ? 'y' : 'ies'} · ${cluster.mentionCount} mention${cluster.mentionCount === 1 ? '' : 's'}`,
      }))

    const edgeMap = new Map<string, DisplayGraphEdge>()
    graph.edges.forEach((edge) => {
      const source = originalToDisplay.get(edge.source)
      const target = originalToDisplay.get(edge.target)
      if (!source || !target || source === target) return
      const key = `${source}|${target}|${edge.edge_type}`
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { id: `summary:${edgeMap.size}:${edge.edge_type}`, source, target, edge_type: edge.edge_type })
      }
    })

    return {
      nodes: [...fixedNodes, ...clusterNodes],
      edges: Array.from(edgeMap.values()),
      collapsedCount: Math.max(0, graph.nodes.length - fixedNodes.length - clusterNodes.length),
      originalToDisplay,
    }
  }, [graph, summarized])

  useEffect(() => { setFocusedNodeId(null) }, [graph, summarized])

  const grouped = useMemo(() => {
    const result: Record<string, DisplayGraphNode[]> = {
      DOCUMENT: [], SUBJECT: [], RELATED_PERSON: [], DIRECT_IDENTIFIER: [], VISUAL_IDENTIFIER: [], QUASI_IDENTIFIER: [],
    }
    displayGraph.nodes.forEach((node) => result[node.kind]?.push(node))
    return result
  }, [displayGraph.nodes])

  const directLane = grouped.DIRECT_IDENTIFIER.length + grouped.VISUAL_IDENTIFIER.length
  const quasiLane = grouped.QUASI_IDENTIFIER.length
  const relationLane = grouped.RELATED_PERSON.length
  const maxLane = Math.max(directLane, quasiLane, relationLane + 2, 4)
  const nodeGap = summarized ? 92 : 78
  const height = Math.max(510, 156 + maxLane * nodeGap)
  const nodeWidth = 184
  const nodeHalf = nodeWidth / 2

  const positions = useMemo(() => {
    const result = new Map<string, { x: number; y: number }>()
    const place = (nodes: DisplayGraphNode[], x: number, startY: number, gap: number) => {
      nodes.forEach((node, index) => result.set(node.id, { x, y: startY + index * gap }))
    }
    const centerY = height / 2 - 29
    place(grouped.DOCUMENT, 116, centerY, 90)
    place(grouped.SUBJECT, 390, centerY, 90)
    place(grouped.RELATED_PERSON, 390, centerY + 112, 82)
    place(grouped.DIRECT_IDENTIFIER, 704, 76, nodeGap)
    place(grouped.VISUAL_IDENTIFIER, 704, 76 + grouped.DIRECT_IDENTIFIER.length * nodeGap, nodeGap)
    place(grouped.QUASI_IDENTIFIER, 1030, 76, nodeGap)
    return result
  }, [grouped, height, nodeGap])

  const externalDisplayFocus = useMemo(() => {
    if (!focusNodeIds?.length) return null
    const mapped = new Set<string>()
    focusNodeIds.forEach((id) => mapped.add(displayGraph.originalToDisplay.get(id) ?? id))
    return mapped
  }, [focusNodeIds, displayGraph.originalToDisplay])

  const focusState = useMemo(() => {
    const pathFocus = externalDisplayFocus && externalDisplayFocus.size > 0
    if (pathFocus) {
      const connectedNodes = new Set<string>(externalDisplayFocus)
      const subjectIds = new Set(displayGraph.nodes.filter((node) => node.kind === 'SUBJECT').map((node) => node.id))
      const documentIds = new Set(displayGraph.nodes.filter((node) => node.kind === 'DOCUMENT').map((node) => node.id))
      // High-risk paths are entity-centric. Pull the signed subject/document anchors into focus
      // only when they connect to the selected evidence, so the full reconstruction route is visible.
      displayGraph.edges.forEach((edge) => {
        if ((connectedNodes.has(edge.source) && subjectIds.has(edge.target)) || (connectedNodes.has(edge.target) && subjectIds.has(edge.source))) {
          connectedNodes.add(edge.source)
          connectedNodes.add(edge.target)
        }
      })
      displayGraph.edges.forEach((edge) => {
        if ((connectedNodes.has(edge.source) && documentIds.has(edge.target)) || (connectedNodes.has(edge.target) && documentIds.has(edge.source))) {
          connectedNodes.add(edge.source)
          connectedNodes.add(edge.target)
        }
      })
      const connectedEdges = new Set<string>()
      displayGraph.edges.forEach((edge) => {
        if (connectedNodes.has(edge.source) && connectedNodes.has(edge.target)) connectedEdges.add(edge.id)
      })
      return { connectedNodes, connectedEdges, mode: 'path' as const }
    }
    if (!focusedNodeId) return { connectedNodes: new Set<string>(), connectedEdges: new Set<string>(), mode: 'none' as const }
    const connectedNodes = new Set<string>([focusedNodeId])
    const connectedEdges = new Set<string>()
    displayGraph.edges.forEach((edge) => {
      if (edge.source === focusedNodeId || edge.target === focusedNodeId) {
        connectedEdges.add(edge.id)
        connectedNodes.add(edge.source)
        connectedNodes.add(edge.target)
      }
    })
    return { connectedNodes, connectedEdges, mode: 'node' as const }
  }, [displayGraph.edges, externalDisplayFocus, focusedNodeId])

  const hasFocus = focusState.mode !== 'none'
  const focusedNode = displayGraph.nodes.find((node) => node.id === focusedNodeId) ?? null

  return (
    <div className={`graph-canvas-wrap ${summarized ? 'compact' : ''} ${hasFocus ? 'has-focus' : ''}`}>
      {compact && (
        <div className="graph-canvas-toolbar">
          <div>
            <strong>{summarized ? 'Population summary' : 'Detailed exposure graph'}</strong>
            <span>{summarized ? `${displayGraph.collapsedCount} repeated nodes collapsed into typed clusters` : `${graph.nodes.length} signed graph nodes · underlying graph unchanged`}</span>
          </div>
          <button onClick={() => setShowDetailed((value) => !value)}>{summarized ? 'Inspect detailed graph' : 'Back to summary'}</button>
        </div>
      )}
      <div className="graph-scroll-region">
        <svg className="graph-canvas" viewBox={`0 0 1160 ${height}`} role="img" aria-label={summarized ? 'Summarized Identity Exposure Graph' : 'Identity Exposure Graph'}>
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" />
            </marker>
          </defs>
          {displayGraph.edges.map((edge, index) => {
            const source = positions.get(edge.source)
            const target = positions.get(edge.target)
            if (!source || !target) return null
            const x1 = source.x + nodeHalf
            const y1 = source.y + 29
            const x2 = target.x - nodeHalf
            const y2 = target.y + 29
            const span = Math.max(50, x2 - x1)
            const bundleX = x1 + span * .52
            const offset = ((index % 5) - 2) * 4
            const focused = !hasFocus || focusState.connectedEdges.has(edge.id)
            return (
              <path
                key={edge.id}
                d={`M ${x1} ${y1} C ${x1 + Math.min(72, span * .24)} ${y1}, ${bundleX - 34} ${y1 + offset}, ${bundleX} ${y1 + offset} S ${x2 - Math.min(72, span * .24)} ${y2}, ${x2} ${y2}`}
                className={`graph-edge edge-${edge.edge_type.toLowerCase()} ${focused ? 'is-linked' : 'is-dimmed'} ${focusState.connectedEdges.has(edge.id) ? 'is-route' : ''}`}
                markerEnd="url(#arrow)"
                vectorEffect="non-scaling-stroke"
              />
            )
          })}
          {displayGraph.nodes.map((node) => {
            const position = positions.get(node.id)
            if (!position) return null
            const focused = focusedNodeId === node.id || (focusState.mode === 'path' && focusState.connectedNodes.has(node.id))
            const linked = !hasFocus || focusState.connectedNodes.has(node.id)
            return (
              <g
                key={node.id}
                transform={`translate(${position.x - nodeHalf}, ${position.y})`}
                className={`graph-node node-${node.kind.toLowerCase()} ${focused ? 'is-focused' : ''} ${linked ? 'is-linked' : 'is-dimmed'}`}
                role="button"
                tabIndex={0}
                aria-label={`${node.label}, ${node.meta}`}
                onClick={() => setFocusedNodeId((current) => current === node.id ? null : node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    setFocusedNodeId((current) => current === node.id ? null : node.id)
                  }
                }}
              >
                <rect width={nodeWidth} height="58" rx="13" />
                <text x="14" y="24" className="node-title">{truncate(node.label, 28)}</text>
                <text x="14" y="43" className="node-meta">{truncate(node.meta, 31)}</text>
              </g>
            )
          })}
        </svg>
      </div>
      <div className="graph-focus-bar" aria-live="polite">
        {focusState.mode === 'path' ? (
          <div><span className="overline">RECONSTRUCTION PATH</span><strong>{focusLabel ?? 'Highest-risk reconstruction route'}</strong><small>Only evidence participating in this path is emphasized. Select another path or node to inspect it.</small></div>
        ) : focusedNode ? (
          <>
            <div><span className="overline">FOCUSED EVIDENCE</span><strong>{focusedNode.label}</strong><small>{focusedNode.meta} · connected reconstruction links emphasized</small></div>
            <button onClick={() => setFocusedNodeId(null)}>Clear focus</button>
          </>
        ) : (
          <div><span className="overline">SPATIAL INSPECTION</span><strong>Select a node or a highest-risk path.</strong><small>Unrelated evidence fades so reconstruction logic can be inspected without graph noise.</small></div>
        )}
      </div>
      <div className="graph-legend">
        <span><i className="legend-subject" />Subject / population</span>
        <span><i className="legend-direct" />Direct or visual identifier</span>
        <span><i className="legend-quasi" />Quasi-identifier</span>
        <span><i className="legend-link" />Relationship / combination path</span>
      </div>
    </div>
  )
}

function RiskPanel({ graph }: { graph: ExposureGraph }) {
  const { risk } = graph
  return (
    <div className="risk-panel">
      <div className="risk-score-block before">
        <span>Original exposure</span>
        <strong>{risk.before}</strong>
        <small>{risk.band_before.toUpperCase()}</small>
      </div>
      <div className="risk-arrow">→</div>
      <div className="risk-score-block after">
        <span>Residual exposure</span>
        <strong>{risk.after}</strong>
        <small>{risk.band_after.toUpperCase()}</small>
      </div>
      <div className="risk-score-block utility">
        <span>Projected policy utility</span>
        <strong>{risk.utility_score}</strong>
        <small>PRE-TRANSFORM PRODUCT SCORE</small>
      </div>
      <div className="risk-bars">
        {([
          ['Direct', risk.breakdown_after.direct],
          ['Quasi', risk.breakdown_after.quasi_identifier],
          ['Relationship', risk.breakdown_after.relationship],
          ['Combination', risk.breakdown_after.combination_bonus],
        ] as const).map(([label, score]) => (
          <div key={label}>
            <span>{label}</span>
            <div><i style={{ width: `${Math.min(100, score * 3)}%` }} /></div>
            <b>{score}</b>
          </div>
        ))}
      </div>
      <p className="disclaimer">{risk.disclaimer}</p>
    </div>
  )
}

function CompetitionProgress({
  analysed,
  transformed,
  verified,
  certified,
}: {
  analysed: boolean
  transformed: boolean
  verified: boolean
  certified: boolean
}) {
  const steps = [
    { label: 'Discover', detail: 'Map identity exposure', done: analysed },
    { label: 'Transform', detail: 'Break reconstruction paths', done: transformed },
    { label: 'Attack', detail: 'Fail-closed adversarial gates', done: verified },
    { label: 'Prove', detail: 'Signed release evidence', done: certified },
  ]
  return (
    <section className="competition-progress" aria-label="VeilGraph competition workflow">
      <div className="competition-progress-title">
        <span>JUDGE FLOW</span>
        <strong>Detect → Transform → Attack → Prove</strong>
      </div>
      <div className="competition-progress-steps">
        {steps.map((step, index) => (
          <div key={step.label} className={`competition-step ${step.done ? 'done' : ''}`}>
            <i>{step.done ? '✓' : index + 1}</i>
            <div><b>{step.label}</b><span>{step.detail}</span></div>
          </div>
        ))}
      </div>
    </section>
  )
}


function BrandLockup() {
  return (
    <div className="brand-lockup" aria-label="VeilGraph Privacy Intelligence">
      <img className="brand-wordmark brand-wordmark-light" src="/veilgraph-brand-light.png" alt="VeilGraph Privacy Intelligence" />
      <img className="brand-wordmark brand-wordmark-dark" src="/veilgraph-brand-dark.png" alt="" aria-hidden="true" />
    </div>
  )
}

export default function App() {
  const [status, setStatus] = useState<OfflineStatus | null>(null)
  const [purpose, setPurpose] = useState('Public evidence release')
  const [recipient, setRecipient] = useState('Citizen information portal')
  const [audience, setAudience] = useState<AudienceProfile>('PUBLIC_RELEASE')
  const [privacyLevel, setPrivacyLevel] = useState<PrivacyLevel>(4)
  const [retentionSeconds, setRetentionSeconds] = useState(3600)
  const [retentionClock, setRetentionClock] = useState(() => Date.now())
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [job, setJob] = useState<Job | null>(null)
  const [fileRecord, setFileRecord] = useState<FileRecord | null>(null)
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [entities, setEntities] = useState<EntityWithMentions[]>([])
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [recommendation, setRecommendation] = useState<PrivacyRecommendation | null>(null)
  const [transformed, setTransformed] = useState<TransformResult | null>(null)
  const [verification, setVerification] = useState<Verification | null>(null)
  const [certificate, setCertificate] = useState<Certificate | null>(null)
  const [audit, setAudit] = useState<AuditLedger | null>(null)
  const [destruction, setDestruction] = useState<Destruction | null>(null)
  const [busy, setBusy] = useState<BusyStep>(null)
  const [error, setError] = useState<string | null>(null)
  const [currentPage, setCurrentPage] = useState(0)
  const originalCompareRef = useRef<HTMLDivElement | null>(null)
  const protectedCompareRef = useRef<HTMLDivElement | null>(null)
  const comparisonSyncingRef = useRef(false)
  const [showEntityInventory, setShowEntityInventory] = useState(false)
  const [showPolicyDetails, setShowPolicyDetails] = useState(false)
  const [confirmBulkProtect, setConfirmBulkProtect] = useState(false)
  const [hoverRiskPath, setHoverRiskPath] = useState<{ nodeIds: string[]; label: string } | null>(null)
  const [pinnedRiskPath, setPinnedRiskPath] = useState<{ nodeIds: string[]; label: string } | null>(null)
  const [comparisonZoom, setComparisonZoom] = useState(100)
  const [protectZoom, setProtectZoom] = useState(100)
  const [sourcePreviewLoaded, setSourcePreviewLoaded] = useState(false)
  const [verificationRevealPhase, setVerificationRevealPhase] = useState<'idle' | 'resolving' | 'complete'>('idle')
  const verificationRevealTimerRef = useRef<number | null>(null)
  const [receiptCopied, setReceiptCopied] = useState(false)
  const [workspaceStep, setWorkspaceStep] = useState<WorkspaceStep>('understand')
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const saved = window.localStorage.getItem('veilgraph-theme')
    if (saved === 'light' || saved === 'dark') return saved
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('veilgraph-theme', theme)
    const themeColor = document.querySelector('meta[name=\"theme-color\"]')
    themeColor?.setAttribute('content', theme === 'dark' ? '#09090b' : '#f5f5f7')
  }, [theme])

  useEffect(() => {
    api.status().then(setStatus).catch((reason: Error) => setError(reason.message))
  }, [])

  useEffect(() => {
    if (!job || !fileRecord || !analysis) return
    // Warm the first evidence preview while the analyst is still in Understand.
    // Protect can then open from cache instead of waiting on an image decode.
    const preview = new Image()
    preview.decoding = 'async'
    preview.src = api.originalPreviewUrl(job.id, fileRecord.id, 0)
  }, [job?.id, fileRecord?.id, analysis?.file_type])

  useEffect(() => () => {
    if (verificationRevealTimerRef.current !== null) window.clearTimeout(verificationRevealTimerRef.current)
  }, [])

  useEffect(() => {
    if (!analysis) return
    window.requestAnimationFrame(() => {
      window.scrollTo({ top: 0, behavior: 'auto' })
    })
  }, [workspaceStep])

  useLayoutEffect(() => {
    if (workspaceStep === 'protect') setSourcePreviewLoaded(false)
  }, [workspaceStep, currentPage, fileRecord?.id])

  useEffect(() => {
    if (!job || destruction) return
    let cancelled = false
    const pollLifecycle = async () => {
      try {
        const current = await api.job(job.id)
        if (cancelled) return
        setJob(current)
        if (current.status === 'DESTROYED') {
          const receipt = await api.destructionReceipt(job.id)
          if (!cancelled) setDestruction(receipt)
        }
      } catch (reason) {
        if (!cancelled) setError(reason instanceof Error ? reason.message : 'Retention lifecycle check failed')
      }
    }
    const lifecycleTimer = window.setInterval(pollLifecycle, 5000)
    const clockTimer = window.setInterval(() => setRetentionClock(Date.now()), 1000)
    return () => {
      cancelled = true
      window.clearInterval(lifecycleTimer)
      window.clearInterval(clockTimer)
    }
  }, [job?.id, destruction])

  const retentionRemainingSeconds = useMemo(() => {
    if (!job) return null
    return Math.max(0, Math.ceil((new Date(job.expires_at).getTime() - retentionClock) / 1000))
  }, [job, retentionClock])

  const retentionLabel = useMemo(() => {
    if (retentionRemainingSeconds === null) return ''
    const hours = Math.floor(retentionRemainingSeconds / 3600)
    const minutes = Math.floor((retentionRemainingSeconds % 3600) / 60)
    const seconds = retentionRemainingSeconds % 60
    if (hours > 0) return `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
  }, [retentionRemainingSeconds])

  const totalMentions = useMemo(
    () => entities.reduce((sum, item) => sum + item.entity.mention_count, 0),
    [entities],
  )
  const pendingMentions = useMemo(
    () => entities.flatMap((item) => item.mentions).filter((mention) => mention.review_status === 'PENDING'),
    [entities],
  )
  const reviewEntities = useMemo(
    () => entities
      .map((item) => ({ ...item, mentions: item.mentions.filter((mention) => mention.review_status === 'PENDING') }))
      .filter((item) => item.mentions.length > 0),
    [entities],
  )
  const highConfidencePending = useMemo(
    () => pendingMentions.filter((mention) => mention.confidence >= 0.95),
    [pendingMentions],
  )
  const videoSecurityUnits = useMemo(
    () => analysis?.file_type === 'VIDEO'
      ? (analysis.video_units ?? []).filter((unit) => unit.full_ocr_selected)
      : [],
    [analysis],
  )
  const videoSecurityPageIndexes = useMemo(
    () => videoSecurityUnits.map((unit) => unit.page_index),
    [videoSecurityUnits],
  )
  const currentVideoEvidencePosition = useMemo(
    () => Math.max(0, videoSecurityPageIndexes.indexOf(currentPage)),
    [videoSecurityPageIndexes, currentPage],
  )
  const currentVideoUnit = useMemo(
    () => analysis?.file_type === 'VIDEO'
      ? (analysis.video_units ?? []).find((unit) => unit.page_index === currentPage) ?? null
      : null,
    [analysis, currentPage],
  )
  const currentVideoUnitPromoted = Boolean(
    currentVideoUnit?.security_promoted
      ?? (currentVideoUnit?.full_ocr_selected && !currentVideoUnit?.is_evidence),
  )
  const policySummary = useMemo(() => {
    const counts: Record<string, number> = {}
    graph?.policy.rules.forEach((rule) => { counts[rule.action] = (counts[rule.action] ?? 0) + 1 })
    return counts
  }, [graph])

  const evidenceUnitLabel = (pageIndex: number) => {
    if (!analysis) return `Page ${pageIndex + 1}`
    if (analysis.file_type === 'DATASET') return `Record ${pageIndex + 1}`
    if (analysis.file_type === 'DOCX') {
      const unit = analysis.docx_units?.find((item) => item.page_index === pageIndex)
      return unit?.label?.replace(/^Body\b/i, 'Section') ?? `Section ${pageIndex + 1}`
    }
    if (analysis.file_type === 'VIDEO') {
      const unit = analysis.video_units?.find((item) => item.page_index === pageIndex)
      return unit?.label ? `Frame · ${unit.label}` : `Video frame ${pageIndex + 1}`
    }
    return `Page ${pageIndex + 1}`
  }

  const videoTimelineLabel = (unit: NonNullable<Analysis['video_units']>[number]) => {
    const promoted = unit.security_promoted ?? (unit.full_ocr_selected && !unit.is_evidence)
    return `${promoted ? '◆' : '●'} ${unit.label}${promoted ? ' · PROMOTED' : ''}`
  }

  const highRiskSummary = useMemo(() => {
    if (!graph) return []
    const grouped = new Map<string, { reason: string; score: number; count: number; nodeIds: string[] }>()
    graph.high_risk_paths.forEach((path) => {
      const current = grouped.get(path.reason)
      if (current) {
        current.count += 1
        if (path.score > current.score) {
          current.score = path.score
          current.nodeIds = path.node_ids
        }
      } else {
        grouped.set(path.reason, { reason: path.reason, score: path.score, count: 1, nodeIds: path.node_ids })
      }
    })
    return Array.from(grouped.values()).sort((a, b) => b.score - a.score || b.count - a.count).slice(0, 4)
  }, [graph])

  const activeRiskPath = hoverRiskPath ?? pinnedRiskPath

  const syntheticEvidence = useMemo(() => {
    const raw = transformed?.synthetic_twin
    return raw && typeof raw === 'object' ? raw as Record<string, unknown> : null
  }, [transformed])

  const syntheticNumber = (key: string) => {
    const value = syntheticEvidence?.[key]
    return typeof value === 'number' ? value : null
  }

  function syncComparisonScroll(source: HTMLDivElement, target: HTMLDivElement | null) {
    if (!target || comparisonSyncingRef.current) return
    comparisonSyncingRef.current = true
    const sourceY = source.scrollHeight > source.clientHeight ? source.scrollTop / (source.scrollHeight - source.clientHeight) : 0
    const sourceX = source.scrollWidth > source.clientWidth ? source.scrollLeft / (source.scrollWidth - source.clientWidth) : 0
    target.scrollTop = sourceY * Math.max(0, target.scrollHeight - target.clientHeight)
    target.scrollLeft = sourceX * Math.max(0, target.scrollWidth - target.clientWidth)
    window.requestAnimationFrame(() => { comparisonSyncingRef.current = false })
  }

  async function execute(step: BusyStep, action: () => Promise<void>) {
    setBusy(step)
    setError(null)
    try {
      await action()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unexpected error')
    } finally {
      setBusy(null)
    }
  }

  function runVisualTransition(update: () => void) {
    // Keep state changes synchronous and cheap. Full-document View Transitions snapshot
    // the graph/document canvas and caused visible main-thread stalls on target hardware.
    update()
  }

  function transitionToWorkspace(next: WorkspaceStep) {
    if (next === workspaceStep) return
    setWorkspaceStep(next)
  }

  function toggleTheme() {
    const root = document.documentElement
    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
    root.style.setProperty('--theme-transition-wash', theme === 'dark' ? '#09090b' : '#f5f5f7')
    if (!reducedMotion) {
      // One compositor-friendly wash is dramatically cheaper than animating every surface,
      // border, SVG node and backdrop independently.
      root.classList.add('theme-transitioning')
      window.setTimeout(() => root.classList.remove('theme-transitioning'), 190)
    }
    setTheme((current) => current === 'dark' ? 'light' : 'dark')
  }

  const createUploadAnalyse = () => execute('create', async () => {
    if (!selectedFile) throw new Error('Choose a PDF, image, native text/DOCX file, CSV/JSON/XLSX dataset or MP4/MOV video first')
    const created = await api.createJob(purpose, recipient, audience, privacyLevel, retentionSeconds)
    setBusy('upload')
    const uploaded = await api.upload(created.id, selectedFile)
    setBusy('analyse')
    const result = await api.analyse(created.id, uploaded.id)
    setBusy('graph')
    const [loadedEntities, recommended] = await Promise.all([
      api.entities(created.id, uploaded.id),
      api.privacyRecommendation(created.id, uploaded.id),
    ])
    const compiledGraph = await api.graph(created.id, uploaded.id, recommended.recommended_level)
    // Commit the complete first workspace atomically. The landing surface stays present while
    // analysis/graph work happens, so judges never see a half-built Understand screen.
    runVisualTransition(() => {
      setJob(created)
      setFileRecord(uploaded)
      setAnalysis(result)
      setCurrentPage(0)
      setEntities(loadedEntities)
      setRecommendation(recommended)
      setPrivacyLevel(recommended.recommended_level)
      setGraph(compiledGraph)
      setWorkspaceStep('understand')
    })
  })

  const selectLevel = (level: PrivacyLevel) => execute('graph', async () => {
    const preview = recommendation?.previews.find((item) => item.privacy_level === level)
    if (preview && !preview.supported) throw new Error(preview.limitation ?? 'This privacy level is not supported for the uploaded format')
    const compiledGraph = job && fileRecord ? await api.graph(job.id, fileRecord.id, level) : null
    runVisualTransition(() => {
      setPrivacyLevel(level)
      setTransformed(null)
      setVerification(null)
      setVerificationRevealPhase('idle')
      setCertificate(null)
      setAudit(null)
      if (compiledGraph) setGraph(compiledGraph)
    })
  })

  const reviewMention = (mentionId: string, action: 'PROTECT' | 'IGNORE') => execute('review', async () => {
    if (!job || !fileRecord || !analysis) return
    const result = await api.review(job.id, mentionId, action)
    setEntities(await api.entities(job.id, fileRecord.id))
    setAnalysis({ ...analysis, pending_reviews: result.pending_reviews, status: result.job_status })
    setGraph(await api.graph(job.id, fileRecord.id, privacyLevel))
    setRecommendation(await api.privacyRecommendation(job.id, fileRecord.id))
    setConfirmBulkProtect(false)
  })

  const protectHighConfidencePending = () => execute('review', async () => {
    if (!job || !fileRecord || !analysis || highConfidencePending.length === 0) return
    let pendingReviews = analysis.pending_reviews
    let jobStatus = analysis.status
    for (const mention of highConfidencePending) {
      const result = await api.review(job.id, mention.id, 'PROTECT')
      pendingReviews = result.pending_reviews
      jobStatus = result.job_status
    }
    setEntities(await api.entities(job.id, fileRecord.id))
    setAnalysis({ ...analysis, pending_reviews: pendingReviews, status: jobStatus })
    setGraph(await api.graph(job.id, fileRecord.id, privacyLevel))
    setConfirmBulkProtect(false)
  })

  const transform = () => execute('transform', async () => {
    if (!job || !fileRecord) return
    const result = await api.transform(job.id, fileRecord.id, privacyLevel)
    runVisualTransition(() => {
      setTransformed(result)
      setVerification(null)
      setVerificationRevealPhase('idle')
      setCertificate(null)
      setAudit(null)
      setWorkspaceStep('verify')
    })
  })

  const verify = () => execute('verify', async () => {
    if (!job || !transformed) return
    if (verificationRevealTimerRef.current !== null) window.clearTimeout(verificationRevealTimerRef.current)
    setVerificationRevealPhase('idle')
    const result = await api.verify(job.id, transformed.output_id)
    let signedCertificate: Certificate | null = null
    let ledger: AuditLedger | null = null
    if (result.status === 'VERIFIED_SAFE') {
      ;[signedCertificate, ledger] = await Promise.all([
        api.certificate(job.id, transformed.output_id),
        api.audit(job.id),
      ])
    }
    setVerification(result)
    setCertificate(signedCertificate)
    setAudit(ledger)
    setVerificationRevealPhase('resolving')
    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
    verificationRevealTimerRef.current = window.setTimeout(() => {
      setVerificationRevealPhase('complete')
      verificationRevealTimerRef.current = null
    }, reducedMotion ? 0 : 620)
  })

  const destroy = () => execute('destroy', async () => {
    if (!job) return
    const result = await api.destroy(job.id)
    runVisualTransition(() => setDestruction(result))
  })


  const startNewRelease = () => {
    runVisualTransition(() => {
      setDestruction(null)
      setJob(null)
      setFileRecord(null)
      setAnalysis(null)
      setEntities([])
      setGraph(null)
      setRecommendation(null)
      setTransformed(null)
      setVerification(null)
      setVerificationRevealPhase('idle')
      setCertificate(null)
      setAudit(null)
      setSelectedFile(null)
      setCurrentPage(0)
      setShowEntityInventory(false)
      setShowPolicyDetails(false)
      setHoverRiskPath(null)
      setPinnedRiskPath(null)
      setComparisonZoom(100)
      setProtectZoom(100)
      setSourcePreviewLoaded(false)
      setReceiptCopied(false)
      setWorkspaceStep('understand')
    })
    window.scrollTo({ top: 0, behavior: 'auto' })
  }

  const copyDestructionReceipt = async () => {
    if (!destruction) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(destruction.destruction_receipt, null, 2))
      setReceiptCopied(true)
      window.setTimeout(() => setReceiptCopied(false), 1800)
    } catch {
      setReceiptCopied(false)
    }
  }

  if (destruction) {
    const receipt = destruction.destruction_receipt
    return (
      <div className="app-root destruction-root">
        <header className="app-chrome minimal-chrome">
          <BrandLockup />
          <div className="chrome-actions">
            <div className="local-status erased"><i /><span>Workspace erased</span></div>
            <button className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`} aria-pressed={theme === 'dark'}><span>{theme === 'dark' ? '☼' : '◐'}</span></button>
          </div>
        </header>
        <main className="destruction-stage page-enter">
          <section className="destruction-card">
            <div className="destruction-symbol"><span>✓</span></div>
            <span className="overline">{destruction.trigger === 'RETENTION_EXPIRED' ? 'AUTOMATIC RETENTION ERASURE' : destruction.trigger === 'PROCESS_RESTART_KEY_LOSS' ? 'RAM-KEY LOSS ERASURE' : 'CRYPTOGRAPHIC ERASURE'}</span>
            <h1>Workspace destroyed.</h1>
            <p>Encrypted workspace data, ephemeral plaintext and active outputs have been cleared. The signed destruction receipt remains independently verifiable.</p>
            <details className="security-boundary-disclosure"><summary>Security boundary</summary><p>{destruction.note}</p></details>
            <div className="destruction-metrics">
              <div><strong>{destruction.deleted_workspace_files}</strong><span>Encrypted files deleted</span></div>
              <div><strong>{destruction.cleared_plaintext_entities}</strong><span>Plaintext entities cleared</span></div>
              <div><strong>{destruction.destroyed_outputs}</strong><span>Outputs invalidated</span></div>
            </div>
            <details className="proof-disclosure receipt-disclosure">
              <summary><span>Signed destruction receipt</span><b>{receipt.signature_valid ? 'VALID' : 'INVALID'}</b></summary>
              <div className="receipt-detail-grid">
                <div><span>Trigger</span><strong>{receipt.payload.trigger.replaceAll('_', ' ')}</strong></div>
                <div><span>Audit integrity</span><strong>{receipt.payload.audit_integrity_valid ? 'VALID' : 'INVALID · ERASURE EXECUTED'}</strong></div>
                <div><span>Retention deadline</span><strong>{new Date(receipt.payload.retention_deadline).toLocaleString()}</strong></div>
                <div><span>Final audit events</span><strong>{receipt.payload.final_audit_event_count}</strong></div>
                <div className="wide"><span>Final audit head</span><code>{receipt.payload.final_audit_head}</code></div>
                <div className="wide"><span>Ed25519 signer</span><code>{receipt.payload.signer.public_key_sha256}</code></div>
              </div>
            </details>
            <div className="destruction-actions"><button className="receipt-copy" onClick={copyDestructionReceipt}>{receiptCopied ? 'Receipt copied' : 'Copy signed receipt'}</button><button className="new-release-button" onClick={startNewRelease}>Start new release <span>→</span></button></div>
          </section>
        </main>
      </div>
    )
  }

  const stepAvailability: Record<WorkspaceStep, boolean> = {
    understand: Boolean(analysis && graph),
    protect: Boolean(analysis && graph),
    verify: Boolean(transformed),
    release: Boolean(certificate && transformed && verification?.status === 'VERIFIED_SAFE'),
  }

  const workflowSteps: { key: WorkspaceStep; label: string; detail: string }[] = [
    { key: 'understand', label: 'Understand', detail: 'Identity exposure' },
    { key: 'protect', label: 'Protect', detail: 'Privacy policy' },
    { key: 'verify', label: 'Verify', detail: 'Adversarial proof' },
    { key: 'release', label: 'Release', detail: 'Signed evidence' },
  ]

  const attackCount = privacyLevel === 5 ? 15 : analysis?.file_type === 'VIDEO' ? 13 : 12

  const evidenceNavigation = analysis && (
    <div className="evidence-navigation">
      {analysis.file_type === 'VIDEO' ? (
        <>
          <button disabled={currentVideoEvidencePosition <= 0} onClick={() => setCurrentPage(videoSecurityPageIndexes[Math.max(0, currentVideoEvidencePosition - 1)] ?? currentPage)}>‹</button>
          <input type="range" min={0} max={Math.max(0, videoSecurityPageIndexes.length - 1)} value={currentVideoEvidencePosition} onChange={(event: { target: { value: string } }) => setCurrentPage(videoSecurityPageIndexes[Number(event.target.value)] ?? currentPage)} />
          <button disabled={currentVideoEvidencePosition >= videoSecurityPageIndexes.length - 1} onClick={() => setCurrentPage(videoSecurityPageIndexes[Math.min(videoSecurityPageIndexes.length - 1, currentVideoEvidencePosition + 1)] ?? currentPage)}>›</button>
          <select aria-label="Jump to video security evidence frame" value={currentPage} onChange={(event: { target: { value: string } }) => setCurrentPage(Number(event.target.value))}>
            {videoSecurityUnits.map((unit) => <option value={unit.page_index} key={unit.page_index}>{videoTimelineLabel(unit)}</option>)}
          </select>
        </>
      ) : (
        <>
          <button aria-label="Previous evidence unit" disabled={currentPage <= 0} onClick={() => setCurrentPage(Math.max(0, currentPage - 1))}>‹</button>
          <span>{evidenceUnitLabel(currentPage)} <i>of {analysis.page_count}</i></span>
          <button aria-label="Next evidence unit" disabled={currentPage >= analysis.page_count - 1} onClick={() => setCurrentPage(Math.min(analysis.page_count - 1, currentPage + 1))}>›</button>
        </>
      )}
    </div>
  )

  return (
    <div className="app-root">
      <header className="app-chrome">
        <BrandLockup />
        <div className="chrome-actions">
          <div className={`local-status ${status?.offline_mode ? 'online' : ''}`}><i /><span>{status?.offline_mode ? 'Local · Private' : 'Local status unavailable'}</span></div>
          <button className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} appearance`} aria-pressed={theme === 'dark'}><span>{theme === 'dark' ? '☼' : '◐'}</span></button>
        </div>
      </header>

      {error && <div className="system-alert"><strong>VeilGraph could not complete that action.</strong><span>{error}</span><button onClick={() => setError(null)}>Dismiss</button></div>}
      {busy && <div className="busy-float"><i /><span>{busy === 'create' ? 'Creating secure workspace' : busy === 'upload' ? 'Encrypting upload' : busy === 'analyse' ? 'Mapping identity exposure' : busy === 'graph' ? 'Compiling privacy graph' : busy === 'review' ? 'Recording review decision' : busy === 'transform' ? 'Applying privacy transformation' : busy === 'verify' ? 'Running Privacy Red Team' : 'Destroying workspace'}</span></div>}

      {!analysis || !fileRecord ? (
        <main className="landing-shell page-enter">
          <section className="landing-hero">
            <span className="overline">LOCAL-FIRST PRIVACY INTELLIGENCE</span>
            <h1>Release data.<br/><em>Not identity.</em></h1>
            <div className="landing-trust-row">
              <span><i />No external model calls</span>
              <span>Local ML + graph reasoning</span>
              <span>L1–L5 privacy gradation</span>
              <span>Fail-closed release proof</span>
            </div>
          </section>

          <section className="intake-surface">
            <div className="surface-heading">
              <div><span className="overline">NEW RELEASE</span><h2>Set the release intent</h2><p>Define who receives the data. VeilGraph will recommend and enforce the minimum safe policy.</p></div>
              <div className="security-note"><i /><span><strong>Processed on this device</strong>Input is encrypted before workspace persistence.</span></div>
            </div>

            <div className="intake-layout">
              <div className="intent-form">
                <label><span>Purpose</span><input value={purpose} onChange={(event: { target: { value: string } }) => setPurpose(event.target.value)} /></label>
                <label><span>Recipient</span><input value={recipient} onChange={(event: { target: { value: string } }) => setRecipient(event.target.value)} /></label>
                <div className="form-row">
                  <label><span>Audience</span>
                    <select value={audience} onChange={(event: { target: { value: string } }) => setAudience(event.target.value as AudienceProfile)}>
                      {Object.entries(audienceLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
                    </select>
                  </label>
                  <label><span>Retention</span>
                    <select value={retentionSeconds} onChange={(event: { target: { value: string } }) => setRetentionSeconds(Number(event.target.value))}>
                      <option value={60}>1 minute · judge demo</option><option value={900}>15 minutes</option><option value={3600}>1 hour · default</option><option value={14400}>4 hours</option><option value={86400}>24 hours · maximum</option>
                    </select>
                  </label>
                </div>
                <label><span>Starting privacy level</span>
                  <select value={privacyLevel} onChange={(event: { target: { value: string } }) => setPrivacyLevel(Number(event.target.value) as PrivacyLevel)}>
                    <option value={1}>L1 · Direct masking</option><option value={2}>L2 · Opaque pseudonymization</option><option value={3}>L3 · Context generalization</option><option value={4}>L4 · Relationship-safe pseudonymization</option><option value={5}>L5 · Synthetic Twin</option>
                  </select>
                </label>
                <div className="privacy-preview"><span>L{privacyLevel}</span><div><strong>{levelDetails[privacyLevel].title.replace(/^Level \d · /, '')}</strong><p>{levelDetails[privacyLevel].description}</p></div></div>
              </div>

              <div className="upload-column">
                <label className={`file-drop ${selectedFile ? 'has-file' : ''}`}>
                  <input type="file" accept="application/pdf,image/png,image/jpeg,text/plain,text/markdown,application/rtf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/csv,application/json,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,video/mp4,video/quicktime,.pdf,.png,.jpg,.jpeg,.txt,.md,.rtf,.docx,.csv,.json,.xlsx,.mp4,.mov" onChange={(event: { target: { files?: FileList | null } }) => setSelectedFile(event.target.files?.[0] ?? null)} />
                  <div className="file-drop-icon"><ImportMark ready={Boolean(selectedFile)} /></div>
                  <strong>{selectedFile ? selectedFile.name : 'Choose a file to protect'}</strong>
                  <p>{selectedFile ? 'Ready for encrypted local analysis.' : 'PDF, image, text, DOCX, CSV, JSON, XLSX, MP4 or MOV'}</p>
                  <small>{selectedFile ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB · stays inside this workspace` : 'Drag and drop or click to browse'}</small>
                </label>
                <button className="action-button primary-action" onClick={createUploadAnalyse} disabled={busy !== null || !selectedFile}><span>{busy ? 'Working…' : 'Analyse identity exposure'}</span><i>→</i></button>
                <p className="microcopy">VeilGraph does not send operational content to external AI services.</p>
              </div>
            </div>
          </section>
        </main>
      ) : job && analysis && fileRecord ? (
        <main className="workspace-shell page-enter">
          <section className="case-bar">
            <div className="case-identity"><span className="overline">ACTIVE RELEASE</span><strong>{fileRecord.original_filename}</strong><small>{audienceLabels[job.audience_profile]} · {analysis.file_type}</small></div>
            <nav className="workspace-nav" aria-label="VeilGraph privacy workflow">
              {workflowSteps.map((step, index) => {
                const available = stepAvailability[step.key]
                const completed = step.key === 'understand' ? Boolean(graph) : step.key === 'protect' ? Boolean(transformed) : step.key === 'verify' ? verification?.status === 'VERIFIED_SAFE' : Boolean(certificate)
                return (
                  <button key={step.key} className={`${workspaceStep === step.key ? 'active' : ''} ${completed ? 'complete' : ''}`} disabled={!available} onClick={() => available && transitionToWorkspace(step.key)}>
                    <i>{completed ? '✓' : index + 1}</i><span><b>{step.label}</b><small>{step.detail}</small></span>
                  </button>
                )
              })}
            </nav>
            <div className="case-controls"><div className="case-retention" title={`Scheduled erasure · ${new Date(job.expires_at).toLocaleString()}`}><span>Auto-erasure</span><strong>{retentionLabel || '—'}</strong></div><button className="case-destroy" disabled={busy !== null} onClick={destroy} title="Destroy encrypted workspace and invalidate active outputs">Destroy workspace</button></div>
          </section>

          {workspaceStep === 'understand' && graph && (
            <section className="workspace-stage understand-stage stage-enter">
              <div className="exposure-summary">
                <div><span>Direct</span><strong>{analysis.direct_identifier_mentions}</strong><small>identifier mentions</small></div>
                <div><span>Quasi</span><strong>{analysis.quasi_identifier_mentions}</strong><small>context clues</small></div>
                <div><span>Visual</span><strong>{analysis.visual_mentions}</strong><small>visual regions</small></div>
                <div><span>Evidence</span><strong>{totalMentions}</strong><small>security mentions</small></div>
                <div className="utility-metric"><span>Projected utility</span><strong>{graph.risk.utility_score}%</strong><small>at Level {privacyLevel}</small></div>
              </div>

              <div className="graph-workbench">
                <div className="workbench-title"><div><span className="overline">IDENTITY EXPOSURE GRAPH</span><h2>Reconstruction map</h2></div><div className="graph-key"><span><i className="key-direct"/>Direct</span><span><i className="key-quasi"/>Quasi</span><span><i className="key-link"/>Relationship</span></div></div>
                <div className="graph-main"><GraphCanvas graph={graph} compact={analysis.file_type === 'DATASET' && graph.nodes.length > 24} focusNodeIds={activeRiskPath?.nodeIds ?? null} focusLabel={activeRiskPath?.label ?? null} /></div>
                <aside className="graph-insight-panel">
                  <span className="overline">HIGHEST-RISK PATHS</span>
                  <h3>What still identifies this subject?</h3>
                  <div className="risk-path-list">
                    {highRiskSummary.length ? highRiskSummary.map((path, index) => { const pinned = pinnedRiskPath?.label === path.reason; return <button key={path.reason} className={pinned ? 'active' : ''} onMouseEnter={() => setHoverRiskPath({ nodeIds: path.nodeIds, label: path.reason })} onMouseLeave={() => setHoverRiskPath(null)} onFocus={() => setHoverRiskPath({ nodeIds: path.nodeIds, label: path.reason })} onBlur={() => setHoverRiskPath(null)} onClick={() => setPinnedRiskPath(pinned ? null : { nodeIds: path.nodeIds, label: path.reason })}><b>{String(index + 1).padStart(2, '0')}</b><span><strong>{path.reason}</strong><small>Exposure contribution · {path.score}{path.count > 1 ? ` · ${path.count} linked paths` : ''}</small></span><i>↗</i></button> }) : <p>No high-risk combination paths remain at this level.</p>}
                  </div>
                  <details className="proof-disclosure"><summary><span>Why this score?</span><b>Details</b></summary><div className="risk-detail"><RiskPanel graph={graph} /></div></details>
                </aside>
              </div>
              <div className="stage-footer"><div><span>Recommended</span><strong>{recommendation ? `Level ${recommendation.recommended_level}` : `Level ${privacyLevel}`}</strong><small>{recommendation?.reasons?.[0] ?? 'Audience-aware privacy policy compiled locally.'}</small></div><button className="action-button stage-advance-action" onClick={() => transitionToWorkspace('protect')}><span>Configure protection</span><i>→</i></button></div>
            </section>
          )}

          {workspaceStep === 'protect' && graph && (
            <section className="workspace-stage protect-stage stage-enter">
              <div className="document-workbench">
                <div className="document-toolbar"><div><span className="overline">SOURCE EVIDENCE</span><strong>{evidenceUnitLabel(currentPage)}</strong><small>{currentVideoUnitPromoted ? 'Promoted by full-frame change guard' : 'Review overlay · technical provenance available below'}</small></div><div className="toolbar-actions">{evidenceNavigation}<div className="zoom-control compact-zoom" aria-label="Source evidence zoom"><button aria-label="Zoom source evidence out" onClick={() => setProtectZoom((value) => Math.max(60, value - 10))}>−</button><span>{protectZoom}%</span><button aria-label="Zoom source evidence in" onClick={() => setProtectZoom((value) => Math.min(160, value + 10))}>+</button><button className="fit-button" onClick={() => setProtectZoom(100)}>Fit</button></div></div></div>
                <div className={`document-canvas evidence-canvas ${sourcePreviewLoaded ? 'preview-ready' : 'preview-loading'}`}><figure>{!sourcePreviewLoaded && <div className="document-skeleton" aria-hidden="true"><i/><i/><i/><i/><i/></div>}<img key={`${fileRecord.id}:${currentPage}`} style={{ width: `${protectZoom}%`, maxWidth: 'none' }} onLoad={() => setSourcePreviewLoaded(true)} src={api.originalPreviewUrl(job.id, fileRecord.id, currentPage)} alt={`Annotated original ${evidenceUnitLabel(currentPage)}`} /></figure></div>
                <div className="document-footer"><div><i className="privacy-dot"/><span>Detected regions are local review overlays. The source artifact remains encrypted.</span></div><button className="text-button" onClick={() => setShowEntityInventory((value) => !value)}>{showEntityInventory ? 'Hide detection inventory' : `Inspect ${entities.length} entities`}</button></div>
                {showEntityInventory && (
                  <div className="inventory-drawer stage-enter">
                    <div className="inventory-heading"><span className="overline">DETECTION INVENTORY</span><strong>{entities.length} canonical entities · {totalMentions} mentions</strong></div>
                    <div className="inventory-grid">{entities.map(({ entity, mentions }) => <article key={entity.id} className={`${quasiTypes.has(entity.entity_type) ? 'quasi' : visualTypes.has(entity.entity_type) ? 'visual' : 'direct'}`}><div><strong>{entity.placeholder}</strong><span>{humanizeToken(entity.entity_type)}</span></div><small>{entity.mention_count} mention{entity.mention_count === 1 ? '' : 's'} · {entity.sensitivity}</small><em>{mentions[0] ? `${evidenceUnitLabel(mentions[0].page_index)} · ${Math.round(mentions[0].confidence * 100)}%` : 'Policy queued'}</em></article>)}</div>
                  </div>
                )}
              </div>

              <aside className="privacy-inspector">
                <div className="inspector-section privacy-strength">
                  <div className="inspector-heading"><span className="overline">PRIVACY STRENGTH</span><strong>Level {privacyLevel}</strong><small>{recommendation?.recommended_level === privacyLevel ? 'Recommended for this audience' : recommendation ? `Recommended: Level ${recommendation.recommended_level}` : ''}</small></div>
                  <div className="level-track">
                    {([1,2,3,4,5] as PrivacyLevel[]).map((level) => {
                      const preview = recommendation?.previews.find((item) => item.privacy_level === level)
                      const disabled = busy !== null || Boolean(transformed) || preview?.supported === false
                      return <button key={level} className={`${privacyLevel === level ? 'active' : ''} ${recommendation?.recommended_level === level ? 'recommended' : ''}`} disabled={disabled} onClick={() => selectLevel(level)} title={preview?.limitation ?? undefined}><i>{level}</i><span>L{level}</span></button>
                    })}
                  </div>
                  <div key={privacyLevel} className="level-description level-live"><strong>{levelDetails[privacyLevel].title}</strong><p>{levelDetails[privacyLevel].description}</p>{recommendation?.policy_floor_enforced && <small className="policy-floor-note">Release floor · Level {recommendation.minimum_level} minimum for {audienceLabels[job.audience_profile]}</small>}</div>
                  {recommendation?.previews.find((item) => item.privacy_level === 5)?.supported === false && <p className="l5-format-note"><strong>L5 Synthetic Twin</strong><span>Available for structured CSV, JSON and XLSX datasets. This {analysis.file_type.toLowerCase()} release uses L1–L4 transformation.</span></p>}
                  <div className="risk-shift"><div><span>Original</span><strong>{graph.risk.before}</strong></div><i>→</i><div><span>Residual</span><strong>{graph.risk.after}</strong></div><div className="utility"><span>Utility</span><strong>{graph.risk.utility_score}%</strong></div></div>
                </div>

                <div className={`inspector-section review-gate ${pendingMentions.length === 0 ? 'complete' : ''}`}>
                  <div className="inspector-heading"><span className="overline">HUMAN REVIEW</span><strong>{pendingMentions.length ? `${pendingMentions.length} decision${pendingMentions.length === 1 ? '' : 's'} required` : 'Review complete'}</strong><small>{pendingMentions.length ? `${highConfidencePending.length} recommended · ${Math.max(0, pendingMentions.length - highConfidencePending.length)} require manual judgment. Unresolved findings stay fail-closed.` : 'All uncertain findings are resolved.'}</small></div>
                  {highConfidencePending.length > 1 && !confirmBulkProtect && <button className="quiet-action" disabled={busy !== null} onClick={() => setConfirmBulkProtect(true)}>Protect all {highConfidencePending.length} high-confidence findings</button>}
                  {confirmBulkProtect && <div className="confirm-row"><span>Protect all high-confidence findings?</span><button onClick={protectHighConfidencePending}>Confirm</button><button onClick={() => setConfirmBulkProtect(false)}>Cancel</button></div>}
                  <div className="review-list">
                    {reviewEntities.map(({ entity, mentions }) => (
                      <article key={entity.id} className="review-entity">
                        <div className="review-entity-heading"><span><strong>{humanizeToken(entity.entity_type)}</strong><small>{entity.placeholder}</small></span><b>{mentions.length} occurrence{mentions.length === 1 ? '' : 's'}</b></div>
                        {mentions.length === 1 ? (
                          <div className="review-occurrence"><span>{evidenceUnitLabel(mentions[0].page_index)}{mentions[0].context_label ? ` · ${mentions[0].context_label}` : ''}<small>{Math.round(mentions[0].confidence * 100)}% confidence</small></span><div><button className="protect-action" disabled={busy !== null} onClick={() => reviewMention(mentions[0].id,'PROTECT')}>Protect</button><button className="retain-action" disabled={busy !== null} onClick={() => reviewMention(mentions[0].id,'IGNORE')}>False positive</button></div></div>
                        ) : (
                          <details className="occurrence-disclosure"><summary>Review {mentions.length} occurrences <b>⌄</b></summary><div>{mentions.map((mention) => <div className="review-occurrence" key={mention.id}><span>{evidenceUnitLabel(mention.page_index)}{mention.context_label ? ` · ${mention.context_label}` : ''}<small>{Math.round(mention.confidence * 100)}% confidence</small></span><div><button className="protect-action" disabled={busy !== null} onClick={() => reviewMention(mention.id,'PROTECT')}>Protect</button><button className="retain-action" disabled={busy !== null} onClick={() => reviewMention(mention.id,'IGNORE')}>False positive</button></div></div>)}</div></details>
                        )}
                      </article>
                    ))}
                  </div>
                </div>

                <div className="inspector-section policy-brief">
                  <button className="disclosure-button" onClick={() => setShowPolicyDetails((value) => !value)}><span><small>COMPILED POLICY</small><strong>{graph.policy.name}</strong></span><b>{showPolicyDetails ? '−' : '+'}</b></button>
                  <div className="policy-counts"><span><b>{policySummary.PROTECT ?? 0}</b> protect</span><span><b>{policySummary.PSEUDONYMIZE ?? 0}</b> pseudonymize</span><span><b>{policySummary.GENERALIZE ?? 0}</b> generalize</span><span><b>{policySummary.REMOVE ?? 0}</b> remove</span>{(policySummary.SYNTHESIZE ?? 0) > 0 && <span><b>{policySummary.SYNTHESIZE}</b> synthesize</span>}</div>
                  {showPolicyDetails && <div className="policy-rule-list stage-enter">{graph.policy.rules.map((rule) => <div key={rule.entity_type}><span><strong>{humanizeToken(rule.entity_type)}</strong><small>{rule.rationale}</small></span><b>{rule.action}</b></div>)}</div>}
                </div>

                <button className="action-button primary-action inspector-cta" disabled={busy !== null || pendingMentions.length > 0 || Boolean(recommendation?.policy_floor_enforced && privacyLevel < recommendation.minimum_level)} onClick={transform}><span>{pendingMentions.length ? 'Complete human review first' : `Apply Level ${privacyLevel} protection`}</span><i>→</i></button>
              </aside>
            </section>
          )}

          {workspaceStep === 'verify' && transformed && (
            <section className="workspace-stage verify-stage stage-enter">
              <div className="comparison-workbench">
                <div className="document-toolbar"><div><span className="overline">TRANSFORMED ARTIFACT</span><strong>{evidenceUnitLabel(currentPage)}</strong><small>Original and protected panes scroll in lockstep</small></div><div className="toolbar-actions">{evidenceNavigation}<div className="zoom-control" aria-label="Comparison zoom"><button aria-label="Zoom out" onClick={() => setComparisonZoom((value) => Math.max(60, value - 10))}>−</button><span>{comparisonZoom}%</span><button aria-label="Zoom in" onClick={() => setComparisonZoom((value) => Math.min(160, value + 10))}>+</button><button className="fit-button" onClick={() => setComparisonZoom(100)}>Fit</button></div></div></div>
                <div className="comparison-grid">
                  <figure><figcaption><span>Original</span><small>Detected evidence</small></figcaption><div ref={originalCompareRef} onScroll={(event) => syncComparisonScroll(event.currentTarget, protectedCompareRef.current)}><img style={{ width: `${comparisonZoom}%`, maxWidth: 'none' }} src={api.originalPreviewUrl(job.id, fileRecord.id, currentPage)} alt={`Original ${evidenceUnitLabel(currentPage)}`} /></div></figure>
                  <figure className="protected"><figcaption><span>Protected</span><small>{verification?.status === 'VERIFIED_SAFE' ? 'Verified for release' : 'Release locked'}</small></figcaption><div ref={protectedCompareRef} onScroll={(event) => syncComparisonScroll(event.currentTarget, originalCompareRef.current)}><img style={{ width: `${comparisonZoom}%`, maxWidth: 'none' }} src={api.protectedPreviewUrl(job.id, transformed.output_id, currentPage)} alt={`Protected ${evidenceUnitLabel(currentPage)}`} /></div></figure>
                </div>
              </div>

              <aside className="verification-inspector">
                {!verification ? (
                  <div className="verification-pending">
                    <div className={`attack-matrix ${busy === 'verify' ? 'running' : ''}`} aria-label={`${attackCount} mandatory privacy attacks`}><div className="attack-matrix-grid">{Array.from({ length: attackCount }, (_, index) => <i key={index}><span>{String(index + 1).padStart(2,'0')}</span></i>)}</div><strong>{attackCount}</strong><span>fail-closed adversarial gates</span><small>Signed gate names bind when the result returns.</small></div>
                    <span className="overline">PRIVACY RED TEAM</span>
                    <h2>Release is locked.</h2>
                    <p>{transformed.transformations_applied} exposure regions changed. VeilGraph will now attack the protected artifact through {attackCount} mandatory fail-closed checks.</p>
                    <div className="transformation-summary"><div><span>Exposure</span><strong>{transformed.risk_before}<i>→</i>{transformed.residual_risk}</strong></div><div><span>Utility retained</span><strong>{transformed.utility_score}%</strong></div></div>
                    {syntheticEvidence && <div className="synthetic-compact"><span>L5 Synthetic Twin</span><strong>{syntheticNumber('privacy_score') ?? '—'}/100 privacy · {syntheticNumber('exact_row_copies') ?? '—'} exact copies</strong></div>}
                    <button className="action-button primary-action" disabled={busy !== null} onClick={verify}><span>{busy === 'verify' ? 'Attacking artifact…' : `Run ${attackCount}-attack verification`}</span><i>→</i></button>
                    <small className="fail-closed-note">Any FAIL or INCONCLUSIVE result keeps download blocked.</small>
                  </div>
                ) : verificationRevealPhase === 'resolving' ? (
                  <div className={`verification-result verification-resolving ${verification.status === 'VERIFIED_SAFE' ? 'safe' : 'blocked'}`}>
                    <div className="resolved-gate-grid">{verification.tests.map((test, index) => <i key={test.name} className={test.status.toLowerCase()} title={`${humanizeGate(test.name)} · ${test.status}`}><span>{String(index + 1).padStart(2,'0')}</span><small>{humanizeGate(test.name)}</small></i>)}</div>
                    <span className="overline">RESULT RECEIVED</span><h2>Resolving signed gates.</h2><p>The returned adversarial results are being composed into the release decision and proof state.</p>
                  </div>
                ) : (
                  <div className={`verification-result verification-complete ${verification.status === 'VERIFIED_SAFE' ? 'safe' : 'blocked'}`}>
                    <div className="verification-symbol"><span>{verification.status === 'VERIFIED_SAFE' ? '✓' : '×'}</span></div>
                    <span className="overline">{verification.status === 'VERIFIED_SAFE' ? 'RELEASE VERIFIED' : 'RELEASE BLOCKED'}</span>
                    <h2>{verification.status === 'VERIFIED_SAFE' ? 'Verified Safe' : 'Verification blocked'}</h2>
                    <div className="proof-number"><strong>{verification.proof_score}</strong><span>/100 proof score</span></div>
                    <p>{verification.passed} of {verification.attack_coverage} attacks passed · {verification.critical_failures} critical blockers.</p>
                    <div className="attack-result-strip" aria-label="Adversarial gate results">{verification.tests.map((test, index) => <i key={test.name} className={test.status.toLowerCase()} title={`${humanizeGate(test.name)} · ${test.status}`}><span>{String(index + 1).padStart(2,'0')}</span><small>{humanizeGate(test.name)}</small></i>)}</div>
                    <div className="verification-metrics"><div><span>Exposure</span><strong>{verification.risk_before} → {verification.residual_risk}</strong></div><div><span>Utility</span><strong>{verification.utility_score}%</strong></div><div><span>Failed</span><strong>{verification.failed}</strong></div><div><span>Inconclusive</span><strong>{verification.inconclusive}</strong></div></div>
                    <details className="proof-disclosure checks-disclosure"><summary><span>Inspect all adversarial checks</span><b>{verification.passed}/{verification.attack_coverage}</b></summary><div className="check-list">{verification.tests.map((test) => <div key={test.name} className={test.status.toLowerCase()}><i>{test.status === 'PASS' ? '✓' : '!'}</i><span><strong>{test.name.replaceAll('_',' ')}</strong><small>{test.attack_class.replaceAll('_',' ')} · {test.detail}</small></span><b>{test.status}</b></div>)}</div></details>
                    {verification.status === 'VERIFIED_SAFE' && certificate && <button className="action-button stage-advance-action" onClick={() => transitionToWorkspace('release')}><span>Open release package</span><i>→</i></button>}
                  </div>
                )}
              </aside>
            </section>
          )}

          {workspaceStep === 'release' && certificate && transformed && verification && (
            <section className="workspace-stage release-stage stage-enter">
              <div className="release-hero">
                <div className="release-hero-main"><div className="release-check"><span>✓</span></div><div><span className="overline">VERIFIED RELEASE</span><h1>Ready to release.</h1><p>Every mandatory adversarial gate passed. The artifact and its evidence are cryptographically bound.</p></div></div>
                <div className="release-score-row"><div><strong>{verification.proof_score}</strong><span>Proof score</span></div><div><strong>{verification.passed}/{verification.attack_coverage}</strong><span>Attacks passed</span></div><div><strong>{verification.residual_risk}</strong><span>Residual exposure</span></div><div><strong>{verification.utility_score}%</strong><span>Utility retained</span></div></div>
              </div>

              <div className="release-layout">
                <section className="proof-package-card">
                  <div className="proof-package-heading"><div><span className="overline">CRYPTOGRAPHIC PROOF</span><h2>Release certificate</h2><p><span>Certificate ID</span><code>{certificate.payload.certificate_id}</code></p></div><span className={`signature-state ${certificate.signature_valid ? 'valid' : 'invalid'}`}><i />{certificate.signature_valid ? 'Ed25519 signature valid' : 'Signature invalid'}</span></div>
                  <div className="trust-grid"><div><span>Artifact</span><strong>SHA-256 bound</strong></div><div><span>Identity graph</span><strong>SHA-256 bound</strong></div><div><span>Audit ledger</span><strong>{audit?.valid ? 'Chain intact' : 'Inspect ledger'}</strong></div><div><span>Red Team</span><strong>{verification.passed}/{verification.attack_coverage} PASS</strong></div></div>
                  <details className="proof-disclosure"><summary><span>Inspect cryptographic bindings</span><b>Technical</b></summary><div className="crypto-grid"><div><span>Output SHA-256</span><code>{certificate.payload.output_sha256}</code></div><div><span>Graph SHA-256</span><code>{certificate.payload.graph_sha256}</code></div><div><span>Signer fingerprint</span><code>{certificate.payload.signer.public_key_sha256}</code></div><div><span>Audit chain head</span><code>{certificate.payload.audit_head_at_certification}</code></div></div></details>
                  {audit && <p className="proof-note">Audit ledger · {audit.event_count} chained events · {audit.valid ? 'integrity valid' : 'integrity requires inspection'}.</p>}<p className="proof-note">The clean protected artifact stays separate from annotated review evidence. The signed proof package binds the artifact, verification results, Identity Exposure Graph, certificate and audit evidence.</p><p className="proof-note">{certificate.payload.disclaimer}</p>
                </section>

                <aside className="release-actions-card">
                  <span className="overline">ARTIFACTS</span><h2>Download release package</h2><p>Choose the clean artifact or independently verifiable evidence.</p>
                  <div className="release-downloads"><a className="primary-download" href={api.downloadUrl(job.id, transformed.output_id)}><i className="artifact-kind">OUT</i><span><strong>Protected output</strong><small>Clean release artifact</small></span><em>Verified ↓</em></a><a href={api.proofPackageUrl(job.id, transformed.output_id)}><i className="artifact-kind">ZIP</i><span><strong>Complete signed proof package</strong><small>Portable independent verification</small></span><em>Signed ↓</em></a><a href={api.certificatePdfUrl(job.id, transformed.output_id)}><i className="artifact-kind">PDF</i><span><strong>Certificate</strong><small>Human-readable release proof</small></span><em>Signed ↓</em></a><a href={api.annotatedExportUrl(job.id, transformed.output_id)}><i className="artifact-kind">EVD</i><span><strong>Annotated evidence</strong><small>Review evidence, separate from clean output</small></span><em>Evidence ↓</em></a></div>
                  {transformed.synthetic_twin && <div className="synthetic-export-section"><span>Verified Synthetic Twin formats</span><div>{(['csv','json','xlsx','docx','pdf'] as const).map(format => <a key={format} href={api.syntheticExportUrl(job.id, transformed.output_id, format)}>{format.toUpperCase()}</a>)}<a href={api.syntheticExportReceiptUrl(job.id, transformed.output_id, 'pdf')}>SIGNED RECEIPT</a></div><details className="proof-disclosure synthetic-proof"><summary><span>Inspect Synthetic Twin evidence</span><b>L5</b></summary><div className="synthetic-proof-grid"><div><span>Privacy score</span><strong>{syntheticNumber('privacy_score') ?? '—'}/100</strong></div><div><span>Utility score</span><strong>{syntheticNumber('utility_score') ?? '—'}/100</strong></div><div><span>Exact row copies</span><strong>{syntheticNumber('exact_row_copies') ?? '—'}</strong></div><div><span>Correlation fidelity</span><strong>{syntheticNumber('numeric_correlation_fidelity') !== null ? `${Math.round((syntheticNumber('numeric_correlation_fidelity') ?? 0) * 100)}%` : '—'}</strong></div><div><span>Category fidelity</span><strong>{syntheticNumber('categorical_distribution_fidelity') !== null ? `${Math.round((syntheticNumber('categorical_distribution_fidelity') ?? 0) * 100)}%` : '—'}</strong></div><div><span>Synthetic records</span><strong>{syntheticNumber('record_count_synthetic') ?? '—'}</strong></div></div></details></div>}
                </aside>
              </div>

              <section className="destruction-action-bar"><div><span className="overline">END OF WORKSPACE</span><strong>Destroy sensitive workspace when the release is complete.</strong><small>Encrypted blobs, ephemeral plaintext and active outputs are invalidated; a signed destruction receipt remains.</small></div><button className="destroy-button" disabled={busy !== null} onClick={destroy}>Destroy workspace</button></section>
            </section>
          )}
        </main>
      ) : null}
    </div>
  )
}
