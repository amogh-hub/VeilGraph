import type {
  Analysis,
  AuditLedger,
  AudienceProfile,
  Certificate,
  Destruction,
  EntityWithMentions,
  ExposureGraph,
  FileRecord,
  Job,
  OfflineStatus,
  PrivacyLevel,
  PrivacyRecommendation,
  ReviewResult,
  TransformResult,
  Verification,
} from './types'

const API = '/api/v1'

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${url}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new Error(body.detail ?? `Request failed: ${response.status}`)
  }
  return response.json() as Promise<T>
}

export const api = {
  status: () => request<OfflineStatus>('/status'),
  createJob: (
    purpose: string,
    recipient: string,
    audienceProfile: AudienceProfile,
    privacyLevel: PrivacyLevel,
    retentionSeconds: number,
  ) => request<Job>('/jobs', {
    method: 'POST',
    body: JSON.stringify({
      purpose,
      recipient,
      audience_profile: audienceProfile,
      privacy_level: privacyLevel,
      retention_seconds: retentionSeconds,
    }),
  }),
  job: (jobId: string) => request<Job>(`/jobs/${jobId}`),
  destructionReceipt: (jobId: string) => request<Destruction>(`/jobs/${jobId}/destruction-receipt`),
  upload: (jobId: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<FileRecord>(`/jobs/${jobId}/files`, { method: 'POST', body: form })
  },
  analyse: (jobId: string, fileId: string) =>
    request<Analysis>(`/jobs/${jobId}/files/${fileId}/analyse`, { method: 'POST' }),
  entities: (jobId: string, fileId: string) =>
    request<EntityWithMentions[]>(`/jobs/${jobId}/files/${fileId}/entities`),
  graph: (jobId: string, fileId: string, privacyLevel: PrivacyLevel) =>
    request<ExposureGraph>(`/jobs/${jobId}/files/${fileId}/graph?privacy_level=${privacyLevel}`),
  privacyRecommendation: (jobId: string, fileId: string) =>
    request<PrivacyRecommendation>(`/jobs/${jobId}/files/${fileId}/privacy-recommendation`),
  originalPreviewUrl: (jobId: string, fileId: string, page: number) =>
    `${API}/jobs/${jobId}/files/${fileId}/preview?page=${page}`,
  protectedPreviewUrl: (jobId: string, outputId: string, page: number) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/preview?page=${page}`,
  review: (jobId: string, mentionId: string, action: 'PROTECT' | 'IGNORE') =>
    request<ReviewResult>(`/jobs/${jobId}/mentions/${mentionId}/review`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),
  transform: (jobId: string, fileId: string, privacyLevel: PrivacyLevel) =>
    request<TransformResult>(`/jobs/${jobId}/files/${fileId}/transform`, {
      method: 'POST',
      body: JSON.stringify({ privacy_level: privacyLevel }),
    }),
  verify: (jobId: string, outputId: string) =>
    request<Verification>(`/jobs/${jobId}/outputs/${outputId}/verify`, { method: 'POST' }),
  certificate: (jobId: string, outputId: string) =>
    request<Certificate>(`/jobs/${jobId}/outputs/${outputId}/certificate`),
  audit: (jobId: string) => request<AuditLedger>(`/jobs/${jobId}/audit`),
  downloadUrl: (jobId: string, outputId: string) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/download`,
  certificatePdfUrl: (jobId: string, outputId: string) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/certificate.pdf`,
  proofBundleUrl: (jobId: string, outputId: string) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/proof-bundle`,
  proofPackageUrl: (jobId: string, outputId: string) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/proof-package`,
  annotatedExportUrl: (jobId: string, outputId: string) =>
    `${API}/jobs/${jobId}/outputs/${outputId}/annotated-export`,
  syntheticExportUrl: (jobId: string, outputId: string, format: 'csv' | 'json' | 'xlsx' | 'docx' | 'pdf') =>
    `${API}/jobs/${jobId}/outputs/${outputId}/synthetic-export?format=${format}`,
  syntheticExportReceiptUrl: (jobId: string, outputId: string, format: 'csv' | 'json' | 'xlsx' | 'docx' | 'pdf') =>
    `${API}/jobs/${jobId}/outputs/${outputId}/synthetic-export-receipt?format=${format}`,
  destroy: (jobId: string) =>
    request<Destruction>(`/jobs/${jobId}/destroy`, { method: 'DELETE' }),
}
