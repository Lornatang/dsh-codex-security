import type {
  CoverageDocument, CoverageSurface, DraftFinding, DraftReviewState, DraftSurface, Finding, FindingsDocument, ScanDraftInput,
  ScanRecord, Severity, Confidence, Disposition, FindingStatus,
} from './types.js'
import { DISPOSITIONS, SEVERITIES, SEVERITY_SCORE } from './types.js'
import { compareSeverity, normalizeLine, sanitizeRelative, sha256, slugify } from './util.js'
import { VERSION } from './constants.js'

const SEVERITY_SET = new Set<string>(SEVERITIES)
const CONFIDENCE_SET = new Set<string>(['high','medium','low'])
const DISPOSITION_SET = new Set<string>(DISPOSITIONS)
const CATEGORY_SET = new Set<string>(['injection','authentication','authorization','cryptography','secrets','injection-deserialization','path-traversal','ssrf','memory-safety','race-condition','dependency','configuration','information-disclosure','business-logic','other'])

export function normalizeRuleId(value: string): string {
  const normalized = String(value ?? '').toLowerCase().replace(/[^a-z0-9._/-]+/g, '-').replace(/^[^a-z0-9]+/, '').replace(/\/+$/, '')
  return normalized.length > 0 ? normalized.slice(0, 96) : 'code-security.finding'
}

export function normalizeAnchor(ruleId: string, path: string, lineText?: string, instance?: string): string {
  const rulePart = normalizeRuleId(ruleId).replace(/[^a-z0-9._-]/g, '-')
  const pathPart = slugify(path, 40).toLowerCase().replace(/[^a-z0-9._-]/g, '-')
  const evidence = normalizeLine(lineText ?? '')
  const evidencePart = evidence.length > 0 ? sha256(evidence).slice(0, 12) : (instance ? sha256(instance).slice(0, 12) : 'anchor')
  const compactRule = rulePart.length > 0 ? rulePart : 'rule'
  const value = compactRule + '/' + (pathPart.length > 0 ? pathPart : 'file') + '/' + evidencePart
  return value.slice(0, 200)
}

export function fingerprintFor(ruleId: string, path: string, anchor: string, instance?: string): string {
  return 'codex-security/v1:sha256:' + sha256(['codex-security/v1', ruleId, path, anchor, instance ?? ''].join('\u0000'))
}

export function idsFor(ruleId: string, path: string, anchor: string, instance?: string, startLine = 1): { findingId: string; occurrenceId: string; primary: string } {
  const primary = fingerprintFor(ruleId, path, anchor, instance)
  return {
    primary,
    findingId: 'csf_' + sha256('finding\u0000' + primary).slice(0, 24),
    occurrenceId: 'occ_' + sha256('occ\u0000' + primary + '\u0000' + path + '\u0000' + startLine).slice(0, 24),
  }
}

export function normalizeSeverity(input: DraftFinding['severity']): Finding['severity'] {
  const level = String(input?.level ?? '').toLowerCase() as Severity
  if (!SEVERITY_SET.has(level)) throw new Error('codex-security: severity.level must be one of ' + SEVERITIES.join(', '))
  const score = typeof input?.score === 'number' && Number.isFinite(input.score) ? Math.min(10, Math.max(0, input.score)) : SEVERITY_SCORE[level]
  return {
    level,
    score,
    ...(input.rationale ? { rationale: String(input.rationale) } : {}),
    ...(input.scoringSystem ? { scoringSystem: String(input.scoringSystem) } : {}),
    ...(input.changeConditions ? { changeConditions: String(input.changeConditions) } : {}),
  }
}

export function normalizeConfidence(input: DraftFinding['confidence']): Finding['confidence'] {
  const level = String(input?.level ?? '').toLowerCase() as Confidence
  if (!CONFIDENCE_SET.has(level)) throw new Error('codex-security: confidence.level must be high, medium or low')
  const rationale = String(input.rationale ?? '').trim().slice(0, 4000)
  if (!rationale) throw new Error('codex-security: confidence.rationale is required')
  return { level, rationale }
}

export function normalizeLocation(input: { path: string; startLine: number; endLine?: number; role?: string }): { path: string; startLine: number; endLine?: number; role?: string } {
  const path = sanitizeRelative(input.path)
  const startLine = Number(input.startLine)
  if (!Number.isInteger(startLine) || startLine < 1) throw new Error('codex-security: locations[].startLine must be a positive integer')
  const endLine = input.endLine === undefined ? undefined : Number(input.endLine)
  if (endLine !== undefined && (!Number.isInteger(endLine) || endLine < startLine)) throw new Error('codex-security: locations[].endLine must be >= startLine')
  return { path, startLine, ...(endLine === undefined ? {} : { endLine }), ...(input.role ? { role: String(input.role) } : {}) }
}

export interface NormalizeFindingOptions { rootPath: string; evidenceLines?: Map<string, string> }

export function normalizeFinding(scanId: string, input: DraftFinding, options: NormalizeFindingOptions): Finding {
  if (!input || typeof input !== 'object') throw new Error('codex-security: each finding must be an object')
  const ruleId = normalizeRuleId(input.ruleId ?? '')
  const title = String(input.title ?? '').trim()
  const summary = String(input.summary ?? '').trim()
  if (title.length === 0) throw new Error('codex-security: finding.title is required')
  if (summary.length === 0) throw new Error('codex-security: finding.summary is required')
  if (!Array.isArray(input.locations) || input.locations.length === 0) throw new Error('codex-security: finding.locations must contain at least one location for ' + title)
  const locations = input.locations.map((location) => normalizeLocation(location))
  const remediation = String(input.remediation ?? '').trim()
  if (remediation.length === 0) throw new Error('codex-security: finding.remediation is required for ' + title)
  const first = locations[0] as { path: string; startLine: number }
  const evidenceKey = first.path + ':' + first.startLine
  const lineText = options.evidenceLines?.get(evidenceKey)
  const anchor = input.anchor && /^[a-z0-9][a-z0-9._/-]*$/.test(String(input.anchor)) ? String(input.anchor) : normalizeAnchor(ruleId, first.path, lineText, input.instance)
  const ids = idsFor(ruleId, first.path, anchor, input.instance, first.startLine)
  const severity = normalizeSeverity(input.severity)
  const confidence = normalizeConfidence(input.confidence)
  const taxonomy = input.taxonomy ?? { category: 'other' }
  const category = CATEGORY_SET.has(String(taxonomy.category)) ? String(taxonomy.category) : 'other'
  const cwe = taxonomy.cwe === undefined ? [] : (Array.isArray(taxonomy.cwe) ? taxonomy.cwe : [taxonomy.cwe]).map(String).filter(Boolean)
  const finding: Finding = {
    findingId: ids.findingId,
    occurrenceId: ids.occurrenceId,
    ruleId,
    identity: { anchor, ...(input.instance ? { instance: String(input.instance) } : {}) },
    fingerprints: { algorithm: 'codex-security/v1', primary: ids.primary },
    title: title.slice(0, 300),
    summary: summary.slice(0, 8000),
    severity,
    confidence,
    taxonomy: { category, cwe },
    locations,
    remediation: remediation.slice(0, 8000),
    ...(input.rootCause ? { rootCause: String(input.rootCause) } : {}),
    ...(input.codeEvidence ? { codeEvidence: input.codeEvidence } : {}),
    ...(input.validation ? { validation: input.validation } : {}),
    ...(input.attackPath ? { attackPath: input.attackPath } : {}),
    ...(input.remediationTests ? { remediationTests: input.remediationTests } : {}),
    ...(input.preventiveControls ? { preventiveControls: input.preventiveControls } : {}),
    ...(input.writeup?.reportPath ? { writeup: { reportPath: sanitizeRelative(input.writeup.reportPath) } } : {}),
    ...(input.provenance ? { provenance: { source: String(input.provenance.source ?? 'agent-review') } } : { provenance: { source: 'agent-review' } }),
    ...(input.extensions ? { extensions: input.extensions } : {}),
    scanId,
  }
  return finding
}

export function validateDraft(input: unknown): ScanDraftInput {
  if (!input || typeof input !== 'object') throw new Error('codex-security: draft must be an object')
  const draft = input as ScanDraftInput
  if (!Array.isArray(draft.findings)) throw new Error('codex-security: draft.findings must be an array')
  const reviewState = (draft.reviewState ?? {}) as DraftReviewState
  if (!Array.isArray(reviewState.surfaces)) throw new Error('codex-security: draft.reviewState.surfaces must be an array')
  for (const surface of reviewState.surfaces) {
    if (!surface || typeof surface.label !== 'string' || surface.label.trim().length === 0) throw new Error('codex-security: each coverage surface needs a non-empty label')
    if (!DISPOSITION_SET.has(String(surface.disposition))) throw new Error('codex-security: surface disposition must be one of ' + DISPOSITIONS.join(', '))
    if (surface.receiptRefs !== undefined) {
      if (!Array.isArray(surface.receiptRefs)) throw new Error('codex-security: surface.receiptRefs must be an array')
      for (const ref of surface.receiptRefs) {
        const value = String(ref)
        if (!value.startsWith('artifacts/') || value.split('/').includes('..')) throw new Error('codex-security: surface receiptRefs must point under artifacts/: ' + value)
      }
    }
  }
  if (reviewState.explicitExclusions !== undefined && !Array.isArray(reviewState.explicitExclusions)) throw new Error('codex-security: reviewState.explicitExclusions must be an array')
  if (reviewState.deferred !== undefined && !Array.isArray(reviewState.deferred)) throw new Error('codex-security: reviewState.deferred must be an array')
  return draft
}

export function buildFindingsDocument(scanId: string, findings: Finding[]): FindingsDocument {
  return { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId, generatedAt: new Date().toISOString(), findings }
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  for (const finding of findings) counts[finding.severity.level] = (counts[finding.severity.level] ?? 0) + 1
  return counts
}

export function sortedFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => compareSeverity(left.severity.level, right.severity.level) || left.title.localeCompare(right.title))
}

export function buildCoverage(scan: ScanRecord, reviewState: DraftReviewState, modeOverride?: string): CoverageDocument {
  const mode = modeOverride ?? coverageMode(scan)
  const surfaces: CoverageSurface[] = sanitizeSurfaces(reviewState.surfaces)
  return {
    documentType: 'codex-security.coverage',
    schemaVersion: '1.0',
    scanId: scan.scanId,
    mode,
    inventoryStrategy: scan.target.kind === 'git_diff' ? 'diff' : scan.target.kind === 'directory_snapshot' ? 'directory' : 'repository',
    includePaths: scan.scope.includePaths,
    excludePaths: scan.scope.excludePaths,
    surfaces,
    explicitExclusions: (reviewState.explicitExclusions ?? []).map((entry) => ({ pattern: String(entry.pattern), reason: String(entry.reason) })),
    deferred: (reviewState.deferred ?? []).map((entry) => ({ id: String(entry.id), reason: String(entry.reason), ...(entry.paths ? { paths: entry.paths } : {}), ...(entry.surfaceIds ? { surfaceIds: entry.surfaceIds } : {}) })),
    ...(reviewState.resolvedDeferred ? { resolvedDeferred: reviewState.resolvedDeferred } : {}),
    ...(reviewState.openQuestions ? { openQuestions: reviewState.openQuestions } : {}),
  }
}

function sanitizeSurfaces(surfaces: DraftSurface[]): CoverageSurface[] {
  return surfaces.map((surface, index) => {
    const disposition = String(surface.disposition) as Disposition
    if (!DISPOSITION_SET.has(disposition)) throw new Error('codex-security: invalid surface disposition ' + disposition)
    return {
      id: String(surface.id ?? 'surface-' + (index + 1)),
      label: String(surface.label),
      disposition,
      receiptRefs: Array.isArray(surface.receiptRefs) ? surface.receiptRefs.map(String) : [],
      ...(surface.riskArea ? { riskArea: String(surface.riskArea) } : {}),
      ...(surface.notes ? { notes: String(surface.notes) } : {}),
    }
  })
}

function coverageMode(scan: ScanRecord): string {
  if (scan.mode === 'deep') return 'deep_repository'
  const kind = scan.target.kind
  if (kind === 'git_diff') return scan.target.baseRevision ? 'branch_diff' : 'diff'
  if (kind === 'directory_snapshot') return scan.scope.includePaths.includes('.') ? 'repository' : 'scoped_path'
  if (kind === 'git_worktree') return scan.target.dirty ? 'working_tree' : 'repository'
  return 'repository'
}

export function policyGate(findings: Finding[], threshold: string): { threshold: string; status: 'pass' | 'fail'; failing: number } {
  if (threshold === 'off') return { threshold, status: 'pass', failing: 0 }
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }
  const limit = rank[threshold]
  if (limit === undefined) return { threshold, status: 'pass', failing: 0 }
  const failing = findings.filter((finding) => (rank[finding.severity.level] ?? 9) <= limit).length
  return { threshold, status: failing > 0 ? 'fail' : 'pass', failing }
}

export function renderReport(scan: ScanRecord, findings: Finding[], coverage: CoverageDocument, options: { sealedAt: string; threatModel?: Record<string, unknown> | string }): string {
  const counts = severityCounts(findings)
  const lines: string[] = []
  const push = (value = ''): void => { lines.push(value) }
  push('# Security review: ' + scan.target.displayName)
  push()
  push('| Field | Value |')
  push('| --- | --- |')
  push('| Scan | ' + scan.scanId + ' |')
  push('| Mode | ' + scan.mode + ' |')
  push('| Status | completed |')
  push('| Sealed | ' + options.sealedAt + ' |')
  push('| Target | ' + scan.target.kind + ' |')
  push('| Revision | ' + (scan.target.revision ?? '(no git revision)') + ' |')
  if (scan.target.baseRevision) push('| Base revision | ' + scan.target.baseRevision + ' |')
  if (scan.target.remote) push('| Remote | ' + scan.target.remote + ' |')
  push('| Snapshot | ' + scan.target.snapshotDigest + ' |')
  push('| Scope | ' + scan.scope.includePaths.join(', ') + ' |')
  push('| Excluded | ' + (scan.scope.excludePaths.length > 0 ? scan.scope.excludePaths.join(', ') : '(none beyond defaults)') + ' |')
  push('| Files reviewed | ' + scan.inventory.inspectedFiles + ' |')
  push()
  push('## Executive summary')
  push()
  push('| Severity | Count |')
  push('| --- | --- |')
  for (const level of SEVERITIES) push('| ' + level + ' | ' + counts[level] + ' |')
  push('| **Total** | **' + findings.length + '** |')
  push()
  push('| Coverage disposition | Surfaces |')
  push('| --- | --- |')
  const dispositionCounts = new Map<string, number>()
  for (const surface of coverage.surfaces) dispositionCounts.set(surface.disposition, (dispositionCounts.get(surface.disposition) ?? 0) + 1)
  for (const [disposition, count] of dispositionCounts) push('| ' + disposition + ' | ' + count + ' |')
  push()
  push('## Findings')
  push()
  if (findings.length === 0) {
    push('No reportable findings. Static review cannot prove the absence of vulnerabilities; see coverage and limitations.')
    push()
  }
  const ordered = sortedFindings(findings)
  ordered.forEach((finding, index) => {
    push('### ' + (index + 1) + '. [' + finding.severity.level.toUpperCase() + '] ' + finding.title)
    push()
    push('- Finding: ' + finding.findingId + ' (occurrence ' + finding.occurrenceId + ')')
    push('- Rule: ' + finding.ruleId + ' | Category: ' + finding.taxonomy.category + (finding.taxonomy.cwe ? ' | CWE: ' + String(finding.taxonomy.cwe) : ''))
    push('- Severity: ' + finding.severity.level + ' (' + finding.severity.score + '/10)' + (finding.severity.rationale ? ' - ' + finding.severity.rationale : ''))
    push('- Confidence: ' + finding.confidence.level + (finding.confidence.rationale ? ' - ' + finding.confidence.rationale : ''))
    for (const location of finding.locations) {
      push('- Location: ' + location.path + ':' + location.startLine + (location.endLine ? '-' + location.endLine : '') + (location.role ? ' (' + location.role + ')' : ''))
    }
    push()
    push(finding.summary)
    push()
    if (finding.rootCause) { push('**Root cause:** ' + finding.rootCause); push() }
    if (finding.validation) {
      const validation = finding.validation
      push('**Validation:** ' + (validation.status ?? validation.method ?? 'recorded') + (validation.summary ? ' - ' + validation.summary : ''))
      push()
    }
    if (finding.attackPath) {
      const attackPath = finding.attackPath
      push('**Attack path:** ' + (attackPath.summary ?? 'See validation evidence'))
      if (Array.isArray(attackPath.steps) && attackPath.steps.length > 0) {
        for (const step of attackPath.steps) push('1. ' + String(step))
      }
      push()
    }
    push('**Remediation:** ' + finding.remediation)
    push()
    if (finding.writeup?.reportPath) { push('Writeup: ' + finding.writeup.reportPath); push() }
  })
  push('## Coverage')
  push()
  if (coverage.surfaces.length === 0) push('No coverage surfaces were recorded.')
  else {
    push('| Surface | Disposition | Risk area | Receipts |')
    push('| --- | --- | --- | --- |')
    for (const surface of coverage.surfaces) push('| ' + surface.label + ' | ' + surface.disposition + ' | ' + (surface.riskArea ?? '') + ' | ' + surface.receiptRefs.join(', ') + ' |')
  }
  push()
  if (coverage.explicitExclusions.length > 0) {
    push('## Explicit exclusions')
    push()
    for (const exclusion of coverage.explicitExclusions) push('- ' + exclusion.pattern + ': ' + exclusion.reason)
    push()
  }
  if (coverage.deferred.length > 0) {
    push('## Deferred work')
    push()
    for (const deferred of coverage.deferred) push('- ' + deferred.id + ': ' + deferred.reason)
    push()
  }
  if (coverage.openQuestions && coverage.openQuestions.length > 0) {
    push('## Open questions')
    push()
    for (const question of coverage.openQuestions) push('- ' + question.question)
    push()
  }
  if (options.threatModel) {
    push('## Threat model')
    push()
    const model = options.threatModel
    push(typeof model === 'string' ? model : JSON.stringify(model, null, 2))
    push()
  }
  push('## Limitations')
  push()
  push('- This review is a static source review. It does not execute the target, build it, or run dynamic analysis.')
  push('- Findings without validation evidence remain candidate risk, not confirmed exploitable behavior.')
  push('- Review depth is bounded by the recorded coverage surfaces, exclusions and deferred items.')
  push('- Target repository content must be treated as untrusted data; this report does not independently verify agent behavior.')
  push()
  return lines.join('\n')
}

export function toSarif(scan: ScanRecord, findings: Finding[]): Record<string, unknown> {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; properties: Record<string, unknown> }>()
  for (const finding of findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.taxonomy.category },
        properties: { category: finding.taxonomy.category, ...(finding.taxonomy.cwe ? { cwe: finding.taxonomy.cwe } : {}) },
      })
    }
  }
  const ruleList = [...rules.values()]
  const ruleIndex = new Map(ruleList.map((rule, index) => [rule.id, index]))
  const results = sortedFindings(findings).map((finding) => {
    const location = finding.locations[0] as { path: string; startLine: number; endLine?: number }
    return {
      ruleId: finding.ruleId,
      ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
      level: sarifLevel(finding.severity.level),
      message: { text: finding.title + ': ' + finding.summary },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: location.path, uriBaseId: '%SRCROOT%' },
          region: { startLine: location.startLine, ...(location.endLine ? { endLine: location.endLine } : {}) },
        },
      }],
      fingerprints: { 'codex-security/v1': finding.fingerprints.primary, findingId: finding.findingId },
      properties: { 'security-severity': finding.severity.score.toFixed(1), confidence: finding.confidence.level, category: finding.taxonomy.category, ...(finding.taxonomy.cwe ? { cwe: finding.taxonomy.cwe } : {}) },
    }
  })
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'codex-security',
          semanticVersion: VERSION,
          informationUri: 'https://github.com/Lornatang/dsh-codex-security',
          rules: ruleList,
        },
      },
      originalUriBaseIds: { '%SRCROOT%': { uri: pathToUri(scan.target.rootPath) } },
      results,
    }],
  }
}

function sarifLevel(level: Severity): string {
  if (level === 'critical' || level === 'high') return 'error'
  if (level === 'medium') return 'warning'
  return 'note'
}

function pathToUri(path: string): string {
  const normalized = path.split('\\').join('/')
  if (/^[A-Za-z]:\//.test(normalized)) return 'file:///' + normalized
  return 'file://' + normalized
}

export function toCsv(findings: Finding[]): string {
  const header = ['finding_id','occurrence_id','severity','confidence','rule_id','title','path','start_line','end_line','category','cwe','remediation']
  const rows = sortedFindings(findings).map((finding) => {
    const location = finding.locations[0] as { path: string; startLine: number; endLine?: number }
    return [finding.findingId, finding.occurrenceId, finding.severity.level, finding.confidence.level, finding.ruleId, finding.title, location.path, String(location.startLine), location.endLine ? String(location.endLine) : '', finding.taxonomy.category, finding.taxonomy.cwe ? String(finding.taxonomy.cwe) : '', finding.remediation]
  })
  const escape = (value: string): string => /[",\n\r]/.test(value) ? '"' + value.split('"').join('""') + '"' : value
  return [header, ...rows].map((row) => row.map((value) => escape(String(value))).join(',')).join('\n') + '\n'
}

export function findingStatusOf(entry?: { status?: FindingStatus }): FindingStatus {
  return entry?.status ?? 'open'
}
