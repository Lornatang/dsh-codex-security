/** Shared types for the codex-security host plugin. */
import type { SkillRegistration } from '@deepseek-ai/dsh-skill'

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type Confidence = 'high' | 'medium' | 'low'
export type ScanMode = 'standard' | 'prompt-only' | 'deep'
export type ScanStatus = 'starting' | 'running' | 'completed' | 'failed' | 'canceled'
export type TargetKind = 'git_revision' | 'git_worktree' | 'git_diff' | 'directory_snapshot'
export type Disposition = 'reported' | 'no_issue_found' | 'rejected' | 'not_applicable' | 'needs_follow_up'
export type FindingStatus = 'open' | 'triaged' | 'fixed' | 'false_positive' | 'accepted_risk' | 'wont_fix'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
export const SEVERITY_SCORE: Record<Severity, number> = { critical: 9.5, high: 8.0, medium: 5.0, low: 2.0, informational: 0.0 }
export const FINDING_STATUSES: FindingStatus[] = ['open', 'triaged', 'fixed', 'false_positive', 'accepted_risk', 'wont_fix']
export const DISPOSITIONS: Disposition[] = ['reported', 'no_issue_found', 'rejected', 'not_applicable', 'needs_follow_up']

export interface FindingLocation { path: string; startLine: number; endLine?: number; role?: string; [key: string]: unknown }

export interface FindingValidation {
  status?: string
  method?: string
  summary?: string
  assertions?: unknown[]
  counterEvidence?: unknown[]
  evidence?: unknown[]
  limitations?: string[]
  [key: string]: unknown
}

export interface FindingAttackPath {
  summary?: string
  steps?: string[]
  preconditions?: string[]
  impact?: string
  likelihood?: string
  controls?: string[]
  assumptions?: string[]
  blindspots?: string[]
  limitations?: string[]
  [key: string]: unknown
}

export interface Finding {
  findingId: string
  occurrenceId: string
  ruleId: string
  identity: { anchor: string; instance?: string }
  fingerprints: { algorithm: 'codex-security/v1'; primary: string }
  title: string
  summary: string
  severity: { level: Severity; score: number; scoringSystem?: string; vector?: string; rationale?: string; changeConditions?: string }
  confidence: { level: Confidence; rationale: string }
  taxonomy: { category: string; cwe: string[] }
  locations: FindingLocation[]
  remediation: string
  rootCause?: string | Record<string, unknown>
  root_cause?: string | Record<string, unknown> | null
  codeEvidence?: unknown[]
  code_evidence?: unknown[] | null
  validation?: FindingValidation
  attackPath?: FindingAttackPath
  remediationTests?: unknown[]
  preventiveControls?: unknown[]
  writeup?: { reportPath: string }
  provenance?: { source?: string; [key: string]: unknown }
  extensions?: Record<string, unknown>
  [key: string]: unknown
}

export interface SourceReference { path: string; startLine: number; endLine: number }
export interface DraftSurface { id?: string; label: string; disposition: Disposition; receiptRefs?: string[]; riskArea?: string; notes?: string; invariant?: string; sourceEvidence?: (SourceReference & { excerpt: string })[]; [key: string]: unknown }
export interface DraftExclusion { pattern: string; reason: string; [key: string]: unknown }
export interface DraftDeferred { id: string; reason: string; paths?: string[]; surfaceIds?: string[]; [key: string]: unknown }
export interface DraftReviewState {
  completeness?: 'complete' | 'partial' | 'unknown'
  surfaces: DraftSurface[]
  explicitExclusions?: DraftExclusion[]
  deferred?: DraftDeferred[]
  resolvedDeferred?: { id: string; reason: string }[]
  openQuestions?: { question: string; followUpPrompt?: string }[]
  [key: string]: unknown
}

export interface DraftFinding {
  ruleId: string
  title: string
  summary: string
  severity: { level: Severity; score?: number; rationale?: string; scoringSystem?: string; vector?: string; changeConditions?: string }
  confidence: { level: Confidence; rationale: string }
  taxonomy?: { category: string; cwe?: string | string[] }
  locations: FindingLocation[]
  remediation: string
  anchor?: string
  instance?: string
  identity?: { anchor: string; instance?: string }
  rootCause?: string | Record<string, unknown>
  root_cause?: string | Record<string, unknown> | null
  codeEvidence?: unknown[]
  code_evidence?: unknown[] | null
  validation?: FindingValidation
  attackPath?: FindingAttackPath
  remediationTests?: unknown[]
  preventiveControls?: unknown[]
  writeup?: { reportPath?: string }
  provenance?: { source?: string; [key: string]: unknown }
  extensions?: Record<string, unknown>
  [key: string]: unknown
}

export interface ScanDraftInput {
  scanId?: string
  complete?: boolean
  scope?: { includePaths?: string[]; excludePaths?: string[]; summary?: string; runtimeStatus?: string; validationMode?: string; context?: string; limitations?: string[]; [key: string]: unknown }
  threatModel?: Record<string, unknown> | string
  findings: DraftFinding[]
  reviewState: DraftReviewState
}

export interface TargetInfo {
  kind: TargetKind
  targetId: string
  displayName: string
  rootPath: string
  remote?: string
  revision?: string
  branch?: string
  baseRevision?: string
  headRevision?: string
  snapshotDigest: string
  diffTarget?: string
  workingTree?: boolean
  dirty: boolean
}

export interface InventoryInfo {
  totalFiles: number
  inspectedFiles: number
  totalBytes: number
  languages: Record<string, number>
  sample: string[]
  excluded: string[]
  truncated: boolean
}

export interface ScopeInfo { includePaths: string[]; excludePaths: string[]; summary?: string }

export interface ProgressInfo {
  phase: string
  notes: string[]
  discoveryRuns: number
  startedAt: string
  updatedAt: string
}

export interface DeepBudget { workers: number; maxDiscoveryRuns: number; stopAfterNoNew: number; maxTimeMinutes: number }

export interface ScanRecord {
  scanId: string
  /** A managed Deep campaign owns mutations of this scan while it runs. */
  managedParent?: string
  managedRootIdentity?: { dev: string; ino: string }
  repoKey: string
  mode: ScanMode
  status: ScanStatus
  promptOnly: boolean
  createdAt: string
  updatedAt: string
  completedAt?: string
  target: TargetInfo
  scope: ScopeInfo
  inventory: InventoryInfo
  /** Changed files captured when a diff scan was bound. */
  diffFiles?: { status: string; path: string; oldPath?: string }[]
  progress: ProgressInfo
  budget?: DeepBudget
  notes?: string
  threatModel?: Record<string, unknown> | string
  artifacts: { path: string; bytes: number; sha256?: string; mediaType?: string; createdAt: string }[]
  findingsCount: number
  severityCounts: Record<Severity, number>
  previousScanId?: string
  error?: string
  cancelReason?: string
  warnings: string[]
  policy?: { threshold: string; status: 'pass' | 'fail'; failing: number }
}

export interface ScanSummary {
  scanId: string
  mode: ScanMode
  status: ScanStatus
  repoKey: string
  target: { displayName: string; kind: TargetKind; revision?: string; baseRevision?: string; headRevision?: string }
  createdAt: string
  updatedAt: string
  findingsCount: number
  severityCounts: Record<Severity, number>
  progress: { phase: string; discoveryRuns: number; updatedAt: string }
  policy?: { threshold: string; status: 'pass' | 'fail'; failing: number }
}

export interface Candidate {
  candidateId: string
  ruleId?: string
  title: string
  severity?: Severity
  path: string
  startLine?: number
  anchor: string
  instance?: string
  summary?: string
  status: 'discovered' | 'validating' | 'validated' | 'rejected' | 'reported'
  createdAt: string
  discovery?: Record<string, unknown>
  validation?: Record<string, unknown>
  attackPath?: Record<string, unknown>
}

export interface CandidateValidation {
  candidateId: string
  status: string
  summary: string
  method?: string
  evidence?: unknown[]
  limitations?: string[]
  recordedAt: string
  validation?: Record<string, unknown>
}

export interface CandidateAttackPath {
  candidateId: string
  summary: string
  steps?: string[]
  impact?: string
  likelihood?: string
  preconditions?: string[]
  controls?: string[]
  recordedAt: string
  attackPath?: Record<string, unknown>
}

export interface ReviewItem {
  reviewId: string
  path: string
  changeType: string
  status: 'pending' | 'reviewed' | 'no_issue_found' | 'rejected' | 'not_applicable' | 'needs_follow_up'
  note?: string
  updatedAt: string
}

export interface TriageEntry { findingId: string; status: FindingStatus; note?: string; remediation?: string; updatedAt: string }

export interface SourceDelivery { deliveredFiles: number; eligibleFiles: number }
export interface CoverageSurface { id: string; label: string; disposition: Disposition; receiptRefs: string[]; riskArea?: string; notes?: string; invariant?: string; sourceEvidence?: (SourceReference & { excerptSha256: string })[] }
export interface CoverageDocument {
  documentType: 'codex-security.coverage'
  schemaVersion: '1.0'
  scanId: string
  mode: string
  completeness?: 'complete' | 'partial' | 'unknown'
  inventoryStrategy: string
  sourceDelivery?: SourceDelivery
  sourceCoverageVersion?: 1
  includePaths: string[]
  excludePaths: string[]
  surfaces: CoverageSurface[]
  explicitExclusions: DraftExclusion[]
  deferred: DraftDeferred[]
  resolvedDeferred?: { id: string; reason: string }[]
  openQuestions?: { question: string; followUpPrompt?: string }[]
}

export interface FindingsDocument {
  documentType: 'codex-security.findings'
  schemaVersion: '1.0'
  scanId: string
  generatedAt: string
  findings: Finding[]
}

export interface ToolResultBlock { type: 'text'; text: string }
export interface ToolDefinition {
  name: string
  description: string
  parameters: Record<string, unknown>
  output: { schema: Record<string, unknown>; render(args: unknown, value: unknown): ToolResultBlock[] }
  execute(args: Record<string, unknown>, exec: unknown): Promise<unknown>
  timeoutMs?: number
}

export interface PluginContext {
  tools: { register(definition: ToolDefinition, options?: { when?: unknown }): () => void }
  skills: { register(skill: SkillRegistration): () => void }
  logger: { info(...args: unknown[]): void; warn(...args: unknown[]): void; error(...args: unknown[]): void }
  effect(callback: () => void | (() => void | Promise<void>), label?: string): () => void
  inject?(services: string[], callback: (ctx: PluginContext) => void): unknown
  on?(event: string, callback: (name?: string) => void): (() => void) | undefined
  get?(name: string): unknown
  profileContext?: { patchPath?: string }
  [key: string]: unknown
}
