/*
 * Codex Security workbench — browser half of dsh-codex-security. Registers one settings.section that
 * renders scans, findings, coverage, and artifacts from /plugins/codex-security. HTTP failures and
 * non-JSON bodies surface in an inline error banner; effects own AbortControllers and never set state
 * after unmount. Only React is imported (the DSH web client module loader maps 'react').
 */
import * as React from 'react'

export const name = 'dsh-codex-security'
export const inject = ['slots']

const API_BASE = '/plugins/codex-security'
const STYLE_ATTR = 'data-dsh-codex-security'
const SCAN_LIMIT = 50

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
type FindingStatus = 'open' | 'triaged' | 'fixed' | 'false_positive' | 'accepted_risk' | 'wont_fix'
type ExportFormat = 'sarif' | 'json' | 'csv' | 'markdown'
type Tone = 'critical' | 'error' | 'warn' | 'success' | 'info' | 'muted'
type SeverityCounts = Partial<Record<Severity, number>>

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
const FINDING_STATUSES: FindingStatus[] = ['open', 'triaged', 'fixed', 'false_positive', 'accepted_risk', 'wont_fix']
const EXPORT_FORMATS: { format: ExportFormat; label: string }[] = [{ format: 'sarif', label: 'SARIF' }, { format: 'json', label: 'JSON' }, { format: 'csv', label: 'CSV' }, { format: 'markdown', label: 'Markdown' }]
const SEVERITY_TONE: Record<Severity, Tone> = { critical: 'critical', high: 'error', medium: 'warn', low: 'info', informational: 'muted' }
const SEVERITY_SHORT: Record<Severity, string> = { critical: 'crit', high: 'high', medium: 'med', low: 'low', informational: 'info' }
const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 }
const STATUS_TONE: Record<string, Tone> = { completed: 'success', running: 'info', starting: 'info', failed: 'error', canceled: 'warn' }
const MODE_TONE: Record<string, Tone> = { deep: 'info', 'prompt-only': 'warn' }
const DISPOSITION_TONE: Record<string, Tone> = { reported: 'info', no_issue_found: 'success', needs_follow_up: 'warn', rejected: 'muted', not_applicable: 'muted' }
const CONFIDENCE_TONE: Record<string, Tone> = { high: 'success', medium: 'info', low: 'warn' }
function toneOf(map: Record<string, Tone>, value: string | undefined): Tone { return (value !== undefined && map[value]) || 'muted' }

interface ScanTarget { displayName?: string; kind?: string; revision?: string; baseRevision?: string; headRevision?: string; rootPath?: string; remote?: string }
interface ScanProgress { phase?: string; discoveryRuns?: number }
interface ScanScope { includePaths?: string[]; excludePaths?: string[]; summary?: string }
interface ArtifactInfo { path?: string; size?: number; bytes?: number }
interface ScanSummary {
  scanId: string; mode?: string; status?: string; target?: ScanTarget; updatedAt?: string
  findingsCount?: number; severityCounts?: SeverityCounts; progress?: ScanProgress
}
interface ScanRecord extends ScanSummary {
  scope?: ScanScope; inventory?: { totalFiles?: number; inspectedFiles?: number; truncated?: boolean }
  warnings?: string[]; notes?: string; error?: string; artifacts?: ArtifactInfo[]
  policy?: { threshold?: string; status?: string; failing?: number }
}
interface Finding {
  findingId?: string; ruleId?: string; title?: string; summary?: string
  severity?: { level?: string; score?: number }; confidence?: { level?: string }
  taxonomy?: { category?: string; cwe?: string | string[] }
  locations?: { path?: string; startLine?: number }[]
  remediation?: string; status?: string; triage?: { status?: string; note?: string; remediation?: string }
}
interface CoverageSurface { id?: string; label?: string; disposition?: string; receiptRefs?: string[]; riskArea?: string; notes?: string }
interface CoverageDocument {
  mode?: string; inventoryStrategy?: string; surfaces?: CoverageSurface[]
  explicitExclusions?: { pattern?: string; reason?: string }[]
  deferred?: { id?: string; reason?: string }[]
  openQuestions?: { question?: string }[]
}
interface StatusResponse { version?: string; stateDir?: string; scans?: number; findings?: number }
interface ScansResponse { scans?: ScanSummary[]; total?: number }
interface ScanDetailResponse { scan?: ScanRecord; findings?: Finding[]; coverage?: CoverageDocument | null; artifacts?: ArtifactInfo[] }
interface FindingsResponse { total?: number }

/* ---------------------------------------------------------------- HTTP */

function clip(text: string, limit: number): string {
  const value = text.replace(/\s+/g, ' ').trim()
  return value.length <= limit ? value : value.slice(0, limit - 1) + '…'
}

function errorMessageOf(value: unknown): string | undefined {
  if (!value || typeof value !== 'object') return undefined
  const record = value as Record<string, unknown>
  const message = record.error && typeof record.error === 'object' ? (record.error as Record<string, unknown>).message : record.error
  if (typeof message === 'string' && message.trim()) return message.trim()
  return typeof record.message === 'string' && record.message.trim() ? record.message.trim() : undefined
}

function describeError(error: unknown): string {
  return error instanceof Error && error.message ? error.message : typeof error === 'string' && error.trim() ? error : 'Unexpected error while talking to the Codex Security plugin.'
}

async function requestJson<T>(url: string, init: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, init)
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    throw new Error('Could not reach the Codex Security plugin. ' + describeError(error))
  }
  const text = await response.text().catch(() => '')
  let parsed: unknown
  let parseFailed = false
  if (text.length > 0) {
    try { parsed = JSON.parse(text) } catch { parseFailed = true }
  }
  if (!response.ok) {
    const detail = parseFailed ? undefined : errorMessageOf(parsed)
    throw new Error('HTTP ' + response.status + ' ' + response.statusText + ' from ' + url + ': ' + (detail ?? clip(text, 200) ?? 'no response body'))
  }
  if (parseFailed) {
    throw new Error('Expected JSON from ' + url + ' but the server returned ' + (response.headers.get('content-type') ?? 'an unknown content type') + '.')
  }
  if (parsed && typeof parsed === 'object' && (parsed as { ok?: unknown }).ok === false) {
    throw new Error(errorMessageOf(parsed) ?? 'The Codex Security server rejected the request.')
  }
  return parsed as T
}

function fetchJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  return requestJson<T>(API_BASE + path, { method: 'GET', headers: { accept: 'application/json' }, credentials: 'same-origin', signal })
}

function postJson<T>(path: string, body: unknown): Promise<T> {
  return requestJson<T>(API_BASE + path, {
    method: 'POST', credentials: 'same-origin', body: JSON.stringify(body),
    headers: { accept: 'application/json', 'content-type': 'application/json' },
  })
}

/* ---------------------------------------------------------- formatting */

function relativeTime(value: string | undefined, now: number): string {
  if (!value) return '—'
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp)) return '—'
  const seconds = Math.round(Math.max(0, now - timestamp) / 1000)
  if (seconds < 45) return 'just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return minutes + 'm ago'
  const hours = Math.round(minutes / 60)
  if (hours < 24) return hours + 'h ago'
  const days = Math.round(hours / 24)
  return days < 30 ? days + 'd ago' : new Date(timestamp).toLocaleDateString()
}

function absoluteTime(value: string | undefined): string | undefined {
  const timestamp = value ? Date.parse(value) : NaN
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString() : value
}

function shortRevision(value: string | undefined): string {
  const trimmed = typeof value === 'string' ? value.trim() : ''
  return trimmed.length <= 8 ? trimmed || '—' : trimmed.slice(0, 8)
}

function formatBytes(value: number | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return ''
  if (value < 1024) return value + ' B'
  return value < 1048576 ? (value / 1024).toFixed(1) + ' KB' : (value / 1048576).toFixed(1) + ' MB'
}

function severityOf(finding: Finding): Severity {
  const raw = finding.severity?.level
  return typeof raw === 'string' && (SEVERITIES as string[]).includes(raw) ? (raw as Severity) : 'informational'
}

function findingStatusOf(finding: Finding): FindingStatus {
  const raw = finding.triage?.status ?? finding.status
  return typeof raw === 'string' && (FINDING_STATUSES as string[]).includes(raw) ? (raw as FindingStatus) : 'open'
}

function pathLine(finding: Finding): string {
  const location = finding.locations?.[0]
  return location && typeof location.path === 'string' && location.path ? location.path + (typeof location.startLine === 'number' ? ':' + location.startLine : '') : '—'
}

function taxonomyText(finding: Finding): string {
  const parts: string[] = []
  const category = finding.taxonomy?.category
  const cwe = finding.taxonomy?.cwe
  if (typeof category === 'string' && category) parts.push(category)
  if (typeof cwe === 'string' && cwe) parts.push(cwe)
  if (Array.isArray(cwe)) parts.push(...cwe.filter((entry): entry is string => typeof entry === 'string'))
  return parts.join(' · ')
}

function countSeverities(findings: Finding[], fallback?: SeverityCounts): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  if (findings.length > 0) { for (const finding of findings) counts[severityOf(finding)] += 1; return counts }
  for (const level of SEVERITIES) { const value = fallback?.[level]; if (typeof value === 'number' && Number.isFinite(value)) counts[level] = value }
  return counts
}

function exportUrl(scanId: string, format: ExportFormat): string {
  return API_BASE + '/export/' + encodeURIComponent(scanId) + '?format=' + format
}

/* ------------------------------------------------------- presentation */

function Chip({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return <span className="dcs-chip" data-tone={tone}>{children}</span>
}

function SeverityChips({ counts }: { counts: Record<Severity, number> }) {
  const present = SEVERITIES.filter(level => counts[level] > 0)
  if (present.length === 0) return <span className="dcs-muted">no findings</span>
  return <span className="dcs-chips">{present.map(level => <Chip key={level} tone={SEVERITY_TONE[level]}>{SEVERITY_SHORT[level]} {counts[level]}</Chip>)}</span>
}

function Spinner({ label }: { label: string }) {
  return <div className="dcs-loading" role="status" aria-live="polite"><span className="dcs-spinner" aria-hidden="true" /><span>{label}…</span></div>
}

function Panel({ title, meta, children }: { title: string; meta?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="dcs-panel" aria-label={title}>
      <div className="dcs-panelHead"><h3 className="dcs-panelTitle">{title}</h3>{meta ? <div className="dcs-panelMeta">{meta}</div> : null}</div>{children}
    </section>
  )
}

/* ----------------------------------------------------------- scan list */

function ScanList(props: { scans: ScanSummary[]; total: number; selectedId: string | null; loading: boolean; now: number; onSelect: (id: string) => void }) {
  const { scans, total, selectedId, loading, now, onSelect } = props
  const meta = total > scans.length ? 'showing ' + scans.length + ' of ' + total : scans.length + ' total'
  return (
    <Panel title="Scans" meta={meta}>
      {loading && scans.length === 0 ? <Spinner label="Loading scans" /> : scans.length === 0 ? (
        <p className="dcs-empty">No scans recorded yet. Start one with the codex_security_start_standard_scan, codex_security_start_prompt_only_scan, or codex_security_start_deep_scan tool.</p>
      ) : (
        <div className="dcs-tableWrap">
          <table className="dcs-table">
            <thead><tr><th scope="col">Mode</th><th scope="col">Status</th><th scope="col">Target</th><th scope="col">Revision</th><th scope="col">Findings</th><th scope="col">Updated</th></tr></thead>
            <tbody>
              {scans.map(scan => {
                const selected = scan.scanId === selectedId
                const select = () => onSelect(scan.scanId)
                return (
                  <tr key={scan.scanId} className={selected ? 'dcs-row dcs-rowSelected' : 'dcs-row'} tabIndex={0} aria-selected={selected} onClick={select}
                    onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select() } }}>
                    <td><Chip tone={toneOf(MODE_TONE, scan.mode)}>{scan.mode ?? 'standard'}</Chip></td>
                    <td><Chip tone={toneOf(STATUS_TONE, scan.status)}>{scan.status ?? 'unknown'}</Chip></td>
                    <td title={(scan.target?.displayName ?? '') + (scan.target?.rootPath ? '\n' + scan.target.rootPath : '')}><span className="dcs-targetCell">
                      <span className="dcs-targetName">{scan.target?.displayName ?? 'unknown target'}</span><span className="dcs-targetKind">{scan.target?.kind ?? ''}</span></span></td>
                    <td><code className="dcs-code">{shortRevision(scan.target?.revision)}</code></td>
                    <td><span className="dcs-findingCount">{scan.findingsCount ?? 0}</span><SeverityChips counts={countSeverities([], scan.severityCounts)} /></td>
                    <td><time dateTime={scan.updatedAt} title={absoluteTime(scan.updatedAt)}>{relativeTime(scan.updatedAt, now)}</time></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

/* -------------------------------------------------------- findings list */

function FindingsTable(props: { scanId: string; findings: Finding[]; busyFindingId: string | null; onTriage: (scanId: string, findingId: string, status: FindingStatus) => void }) {
  const { scanId, findings, busyFindingId, onTriage } = props
  const [expandedId, setExpandedId] = React.useState<string | null>(null)
  const ordered = React.useMemo(() => findings
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => SEVERITY_RANK[severityOf(right.finding)] - SEVERITY_RANK[severityOf(left.finding)] || left.index - right.index), [findings])
  if (ordered.length === 0) return <p className="dcs-empty">No findings recorded for this scan.</p>
  return (
    <div className="dcs-tableWrap">
      <table className="dcs-table">
        <thead><tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Rule</th><th scope="col">Location</th><th scope="col">Confidence</th><th scope="col">Triage</th><th scope="col"><span className="dcs-srOnly">Remediation details</span></th></tr></thead>
        <tbody>
          {ordered.map(({ finding, index }) => {
            const findingId = typeof finding.findingId === 'string' && finding.findingId ? finding.findingId : 'finding-' + index
            const title = finding.title ?? 'Untitled finding'
            const expanded = expandedId === findingId
            const detailId = 'dcs-finding-detail-' + index
            const taxonomy = taxonomyText(finding)
            return (
              <React.Fragment key={findingId}>
                <tr>
                  <td><Chip tone={SEVERITY_TONE[severityOf(finding)]}>{severityOf(finding)}</Chip></td>
                  <td><span className="dcs-findingTitle">{title}</span>{taxonomy ? <span className="dcs-findingMeta">{taxonomy}</span> : null}</td>
                  <td><code className="dcs-code">{finding.ruleId ?? '—'}</code></td>
                  <td><code className="dcs-code dcs-location" title={pathLine(finding)}>{pathLine(finding)}</code></td>
                  <td><Chip tone={toneOf(CONFIDENCE_TONE, finding.confidence?.level)}>{finding.confidence?.level ?? 'unknown'}</Chip></td>
                  <td><select className="dcs-select" value={findingStatusOf(finding)} disabled={busyFindingId === findingId || !finding.findingId} aria-label={'Triage status for ' + title}
                    onChange={event => { if (finding.findingId) onTriage(scanId, finding.findingId, event.target.value as FindingStatus) }}>
                    {FINDING_STATUSES.map(option => <option key={option} value={option}>{option.replace(/_/g, ' ')}</option>)}</select></td>
                  <td><button type="button" className="dcs-button dcs-buttonGhost" aria-expanded={expanded} aria-controls={detailId} onClick={() => setExpandedId(expanded ? null : findingId)}>{expanded ? 'Hide' : 'Details'}</button></td>
                </tr>
                {expanded ? (
                  <tr id={detailId} className="dcs-detailRow">
                    <td colSpan={7}>
                      {finding.summary ? <p className="dcs-summary">{finding.summary}</p> : null}
                      <h4 className="dcs-subhead">Remediation</h4>
                      <p className="dcs-remediation">{finding.remediation ?? finding.triage?.remediation ?? 'No remediation recorded.'}</p>
                      <p className="dcs-hint"><code className="dcs-code">{findingId}</code>{finding.triage?.note ? ' · triage note: ' + finding.triage.note : ''}</p>
                    </td>
                  </tr>
                ) : null}
              </React.Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/* --------------------------------------------------------- scan detail */

function ScanDetailPanel(props: {
  detail: ScanDetailResponse | null; selectedId: string | null; loading: boolean; error: string | null
  busyFindingId: string | null; now: number; onTriage: (scanId: string, findingId: string, status: FindingStatus) => void
}) {
  const { detail, selectedId, loading, error, busyFindingId, now, onTriage } = props
  if (!selectedId) return <Panel title="Scan detail"><p className="dcs-empty">Select a scan above to inspect its findings, coverage, and artifacts.</p></Panel>
  if (!detail) return <Panel title="Scan detail">{loading ? <Spinner label="Loading scan details" /> : <p className="dcs-empty">{error ?? 'Scan details are unavailable.'} Use Retry to try again.</p>}</Panel>
  const scan = detail.scan ?? { scanId: selectedId }
  const findings = Array.isArray(detail.findings) ? detail.findings : []
  const artifacts = Array.isArray(detail.artifacts) && detail.artifacts.length > 0 ? detail.artifacts : (scan.artifacts ?? [])
  const counts = countSeverities(findings, scan.severityCounts)
  const coverage = detail.coverage ?? null
  const surfaces = coverage?.surfaces ?? []
  const exclusions = coverage?.explicitExclusions ?? []
  const deferred = coverage?.deferred ?? []
  const warnings = scan.warnings ?? []
  const target = scan.target
  const progress = scan.progress
  const scope = scan.scope
  const inventory = scan.inventory
  const revision = target?.revision ?? target?.headRevision
  const scopeText = scope?.summary ?? ((scope?.includePaths?.length ?? 0) + ' include / ' + (scope?.excludePaths?.length ?? 0) + ' exclude paths')
  const inventoryText = typeof inventory?.totalFiles === 'number'
    ? (inventory.inspectedFiles ?? 0) + ' of ' + inventory.totalFiles + ' files inspected' + (inventory.truncated ? ' · truncated' : '') : '—'
  const overview: { term: string; value: React.ReactNode }[] = [
    { term: 'Target', value: (target?.displayName ?? '—') + (target?.kind ? ' · ' + target.kind : '') + (target?.remote ? ' · ' + target.remote : '') },
    { term: 'Revision', value: <code className="dcs-code">{shortRevision(revision)}</code> },
    { term: 'Scope', value: scopeText },
    { term: 'Inventory', value: inventoryText },
    { term: 'Severity', value: <SeverityChips counts={counts} /> },
  ]
  if (scan.policy) overview.push({ term: 'Policy', value: (scan.policy.threshold ?? '—') + ' · ' + (scan.policy.status ?? 'unknown') + (typeof scan.policy.failing === 'number' ? ' · ' + scan.policy.failing + ' failing' : '') })
  if (scan.notes) overview.push({ term: 'Notes', value: scan.notes })
  if (scan.error) overview.push({ term: 'Error', value: scan.error })
  return (
    <>
      <section className="dcs-panel dcs-detailHead" aria-label="Selected scan">
        <div className="dcs-detailHeading">
          <h3 className="dcs-detailTitle" title={target?.rootPath}>{target?.displayName ?? 'Unknown target'}</h3>
          <span className="dcs-detailMeta">
            <Chip tone={toneOf(MODE_TONE, scan.mode)}>{scan.mode ?? 'standard'}</Chip>
            <Chip tone={toneOf(STATUS_TONE, scan.status)}>{scan.status ?? 'unknown'}</Chip>
            <code className="dcs-code">{scan.scanId}</code>
          </span>
        </div>
        <div className="dcs-detailStatus">
          <span className="dcs-phase">phase: <strong>{progress?.phase ?? 'unknown'}</strong></span>
          {typeof progress?.discoveryRuns === 'number' ? <span>discovery runs: {progress.discoveryRuns}</span> : null}
          <time dateTime={scan.updatedAt} title={absoluteTime(scan.updatedAt)}>updated {relativeTime(scan.updatedAt, now)}</time>
          {loading ? <span className="dcs-loadingInline" role="status">Refreshing…</span> : null}
        </div>
      </section>
      <Panel title="Overview">
        <dl className="dcs-meta">{overview.map(entry => <div key={entry.term}><dt>{entry.term}</dt><dd>{entry.value}</dd></div>)}</dl>
        <h4 className="dcs-subhead">Limitations</h4>
        {warnings.length === 0 && exclusions.length === 0 && deferred.length === 0 ? (
          <p className="dcs-muted">No warnings, explicit exclusions, or deferred surfaces recorded.</p>
        ) : (
          <ul className="dcs-limits">
            {warnings.map((warning, index) => <li key={'warning-' + index}>{warning}</li>)}
            {exclusions.map((entry, index) => <li key={'exclusion-' + index}>Excluded <code className="dcs-code">{entry.pattern ?? 'pattern'}</code>{entry.reason ? ': ' + entry.reason : ''}</li>)}
            {deferred.map((entry, index) => <li key={'deferred-' + index}>Deferred <code className="dcs-code">{entry.id ?? 'surface'}</code>{entry.reason ? ': ' + entry.reason : ''}</li>)}
          </ul>
        )}
      </Panel>
      <Panel title="Findings" meta={<SeverityChips counts={counts} />}>
        <FindingsTable scanId={scan.scanId} findings={findings} busyFindingId={busyFindingId} onTriage={onTriage} />
      </Panel>
      <Panel title="Coverage" meta={coverage?.mode ? 'mode: ' + coverage.mode : undefined}>
        {surfaces.length === 0 ? (
          <p className="dcs-empty">No coverage surfaces recorded for this scan.</p>
        ) : (
          <div className="dcs-tableWrap">
            <table className="dcs-table">
              <thead><tr><th scope="col">Surface</th><th scope="col">Disposition</th><th scope="col">Risk area</th><th scope="col">Notes</th></tr></thead>
              <tbody>
                {surfaces.map((surface, index) => (
                  <tr key={surface.id ?? 'surface-' + index}>
                    <td><span className="dcs-surfaceLabel">{surface.label ?? surface.id ?? 'unnamed surface'}</span><code className="dcs-code dcs-surfaceId">{surface.id ?? ''}</code></td>
                    <td><Chip tone={toneOf(DISPOSITION_TONE, surface.disposition)}>{(surface.disposition ?? 'unknown').replace(/_/g, ' ')}</Chip></td>
                    <td>{surface.riskArea ?? '—'}</td>
                    <td>{surface.notes ?? '—'}{Array.isArray(surface.receiptRefs) && surface.receiptRefs.length > 0 ? ' · ' + surface.receiptRefs.length + ' receipt(s)' : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {coverage?.inventoryStrategy ? <p className="dcs-hint">Inventory strategy: {coverage.inventoryStrategy}</p> : null}
      </Panel>
      <Panel title="Artifacts & exports">
        {artifacts.length === 0 ? (
          <p className="dcs-empty">No artifacts saved for this scan.</p>
        ) : (
          <ul className="dcs-artifacts">
            {artifacts.map((artifact, index) => (
              <li key={(artifact.path ?? 'artifact') + '-' + index}><code className="dcs-code">{artifact.path ?? 'artifact-' + index}</code><span className="dcs-artifactSize">{formatBytes(artifact.size ?? artifact.bytes)}</span></li>
            ))}
          </ul>
        )}
        <div className="dcs-exportRow" role="group" aria-label="Download scan exports">
          <span className="dcs-exportLabel">Download:</span>
          {EXPORT_FORMATS.map(entry => (
            <a key={entry.format} className="dcs-linkButton" href={exportUrl(scan.scanId, entry.format)} download={'codex-security-' + scan.scanId + '.' + (entry.format === 'markdown' ? 'md' : entry.format)}
              aria-label={'Download ' + entry.label + ' export for scan ' + scan.scanId}>{entry.label}</a>
          ))}
        </div>
        <p className="dcs-hint">Exports are generated from the sealed findings document.</p>
      </Panel>
    </>
  )
}

/* ------------------------------------------------------------ workbench */

function Workbench() {
  const [status, setStatus] = React.useState<StatusResponse | null>(null)
  const [openFindings, setOpenFindings] = React.useState<number | null>(null)
  const [scans, setScans] = React.useState<ScanSummary[]>([])
  const [scansTotal, setScansTotal] = React.useState(0)
  const [selectedId, setSelectedId] = React.useState<string | null>(null)
  const [detail, setDetail] = React.useState<ScanDetailResponse | null>(null)
  const [listLoading, setListLoading] = React.useState(true)
  const [detailLoading, setDetailLoading] = React.useState(false)
  const [loadError, setLoadError] = React.useState<string | null>(null)
  const [actionError, setActionError] = React.useState<string | null>(null)
  const [reloadToken, setReloadToken] = React.useState(0)
  const [busyFindingId, setBusyFindingId] = React.useState<string | null>(null)
  const [now, setNow] = React.useState(() => Date.now())
  const mountedRef = React.useRef(true)
  React.useEffect(() => {
    mountedRef.current = true
    ensureStyles()
    const timer = window.setInterval(() => setNow(Date.now()), 30000)
    return () => { mountedRef.current = false; window.clearInterval(timer) }
  }, [])
  React.useEffect(() => {
    const controller = new AbortController()
    let active = true
    fetchJson<StatusResponse>('/status', controller.signal).then(value => { if (active && mountedRef.current) setStatus(value) }).catch(() => undefined)
    fetchJson<FindingsResponse>('/findings?status=open&limit=1', controller.signal)
      .then(value => { if (active && mountedRef.current && typeof value.total === 'number') setOpenFindings(value.total) }).catch(() => undefined)
    return () => { active = false; controller.abort() }
  }, [reloadToken])
  React.useEffect(() => {
    const controller = new AbortController()
    let active = true
    setListLoading(true)
    fetchJson<ScansResponse>('/scans?limit=' + SCAN_LIMIT, controller.signal)
      .then(value => {
        if (!active || !mountedRef.current) return
        const next = Array.isArray(value.scans) ? value.scans.filter(scan => scan && typeof scan.scanId === 'string') : []
        setScans(next)
        setScansTotal(typeof value.total === 'number' ? value.total : next.length)
        setSelectedId(current => next.some(scan => scan.scanId === current) ? current : (next[0]?.scanId ?? null))
        setLoadError(null)
      })
      .catch((error: unknown) => {
        if (!active || !mountedRef.current || (error instanceof Error && error.name === 'AbortError')) return
        setLoadError(describeError(error))
      })
      .finally(() => { if (active && mountedRef.current) setListLoading(false) })
    return () => { active = false; controller.abort() }
  }, [reloadToken])
  React.useEffect(() => {
    if (!selectedId) { setDetail(null); return }
    const controller = new AbortController()
    let active = true
    setDetailLoading(true)
    fetchJson<ScanDetailResponse>('/scans/' + encodeURIComponent(selectedId), controller.signal)
      .then(value => {
        if (!active || !mountedRef.current) return
        setDetail(value)
        setLoadError(null)
      })
      .catch((error: unknown) => {
        if (!active || !mountedRef.current || (error instanceof Error && error.name === 'AbortError')) return
        setDetail(null)
        setLoadError(describeError(error))
      })
      .finally(() => { if (active && mountedRef.current) setDetailLoading(false) })
    return () => { active = false; controller.abort() }
  }, [selectedId, reloadToken])
  const refresh = React.useCallback(() => { setActionError(null); setReloadToken(token => token + 1) }, [])
  const selectScan = React.useCallback((scanId: string) => { setDetail(null); setSelectedId(scanId) }, [])
  const handleTriage = React.useCallback((scanId: string, findingId: string, nextStatus: FindingStatus) => {
    setBusyFindingId(findingId)
    setActionError(null)
    postJson<unknown>('/scans/' + encodeURIComponent(scanId) + '/triage', { findingId, status: nextStatus })
      .then(() => { if (mountedRef.current) setReloadToken(token => token + 1) })
      .catch((error: unknown) => { if (mountedRef.current) setActionError(describeError(error)) })
      .finally(() => { if (mountedRef.current) setBusyFindingId(null) })
  }, [])
  const errorText = actionError ?? loadError
  const scanCount = typeof status?.scans === 'number' ? status.scans : scansTotal
  const findingCount = typeof status?.findings === 'number' ? status.findings : null
  return (
    <section className="dcs-root" aria-label="Codex Security workbench">
      <header className="dcs-header">
        <div className="dcs-heading">
          <h2 className="dcs-title">Codex Security</h2>
          <span className="dcs-subtitle">Sealed security scans, findings, and exports</span>
        </div>
        <div className="dcs-actions">
          <div className="dcs-headerMeta">
            <span className="dcs-stat"><span className="dcs-statValue">{scanCount}</span> scans</span>
            <span className="dcs-stat"><span className="dcs-statValue">{findingCount ?? '—'}</span> findings</span>
            <span className="dcs-stat"><span className="dcs-statValue">{openFindings ?? '—'}</span> open</span>
          </div>
          <button type="button" className="dcs-button" onClick={refresh} aria-label="Refresh Codex Security data">{listLoading ? 'Refreshing…' : 'Refresh'}</button>
        </div>
      </header>
      <div className="dcs-stateDir">State dir: <code>{status?.stateDir ?? 'unknown'}</code>{typeof status?.version === 'string' ? <span className="dcs-version"> · v{status.version}</span> : null}</div>
      {errorText ? (
        <div className="dcs-errorBanner" role="alert" aria-live="assertive">
          <span className="dcs-errorMark" aria-hidden="true">!</span>
          <span className="dcs-errorText">{errorText}</span>
          <button type="button" className="dcs-button dcs-buttonSmall" onClick={refresh} aria-label="Retry loading Codex Security data">Retry</button>
        </div>
      ) : null}
      <ScanList scans={scans} total={scansTotal} selectedId={selectedId} loading={listLoading} now={now} onSelect={selectScan} />
      <ScanDetailPanel detail={detail} selectedId={selectedId} loading={detailLoading} error={actionError ?? loadError} busyFindingId={busyFindingId} now={now} onTriage={handleTriage} />
    </section>
  )
}

/* ----------------------------------------------------- style injection */

const DEFAULT_STYLE = `
.dcs-root{display:flex;flex-direction:column;gap:14px;width:100%;max-width:1040px;color:var(--dsw-alias-label-primary,#e7e8ea);font-size:13px;line-height:20px}.dcs-root *,.dcs-root *::before,.dcs-root *::after{box-sizing:border-box}
.dcs-root :focus-visible{outline:2px solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary,#4c8dff));outline-offset:2px}.dcs-header{display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;gap:12px}
.dcs-heading{display:flex;flex-direction:column;gap:2px;min-width:0}.dcs-title{margin:0;font-size:16px;line-height:24px;font-weight:600}
.dcs-subtitle{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}.dcs-actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.dcs-headerMeta{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.dcs-stat{display:inline-flex;align-items:baseline;gap:4px;padding:1px 8px;border:0.5px solid var(--dsw-alias-border-l2,rgba(255,255,255,.1));border-radius:999px;color:var(--dsw-alias-label-secondary,#b4b6bd);font-size:11px;line-height:18px;white-space:nowrap}
.dcs-statValue{color:var(--dsw-alias-label-primary,#e7e8ea);font-weight:600;font-variant-numeric:tabular-nums}.dcs-stateDir{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px;overflow-wrap:anywhere}
.dcs-stateDir code,.dcs-code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;color:var(--dsw-alias-label-secondary,#b4b6bd)}.dcs-version{color:var(--dsw-alias-label-caption,#6f727b)}
.dcs-button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:28px;padding:3px 12px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-md,8px);background:var(--dsw-alias-bg-layer-1,#1c1d21);color:var(--dsw-alias-label-primary,#e7e8ea);font:inherit;font-size:12px;cursor:pointer}.dcs-button:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}
.dcs-button:disabled{opacity:.55;cursor:default}.dcs-buttonGhost{padding:2px 8px;min-height:24px;background:transparent;color:var(--dsw-alias-label-secondary,#b4b6bd)}
.dcs-buttonSmall{min-height:24px;padding:1px 10px}.dcs-linkButton{display:inline-flex;align-items:center;min-height:24px;padding:1px 10px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-md,8px);color:var(--dsw-alias-link,var(--dsw-alias-state-business-primary,#6b9fff));font-size:12px;text-decoration:none}
.dcs-linkButton:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}.dcs-errorBanner{display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border:0.5px solid var(--dsw-alias-state-error-primary,#ff6b6b);border-radius:var(--dsw-radius-lg,12px);background:color-mix(in srgb,var(--dsw-alias-state-error-primary,#ff6b6b) 10%,transparent)}
.dcs-errorMark{flex:none;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;margin-top:2px;border-radius:50%;background:var(--dsw-alias-state-error-primary,#ff6b6b);color:var(--dsw-alias-label-on-color,#fff);font-size:11px;font-weight:700}.dcs-errorText{flex:1 1 auto;min-width:0;overflow-wrap:anywhere;color:var(--dsw-alias-state-error-primary,#ff6b6b)}
.dcs-panel{display:flex;flex-direction:column;gap:10px;min-width:0;padding:12px 14px;border:0.5px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l2,rgba(255,255,255,.1)));border-radius:var(--dsw-radius-lg,12px);background:var(--dsw-alias-settings-card-fill,var(--dsw-alias-bg-layer-1,#1c1d21))}.dcs-panelHead{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px}
.dcs-panelTitle{margin:0;font-size:13px;line-height:20px;font-weight:600}.dcs-panelMeta{display:flex;flex-wrap:wrap;align-items:center;gap:6px;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-loading{display:flex;align-items:center;gap:8px;padding:6px 0;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}.dcs-spinner{flex:none;width:12px;height:12px;border-radius:50%;border:2px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-top-color:var(--dsw-alias-state-business-primary,#6b9fff);animation:dcs-spin .8s linear infinite}
@keyframes dcs-spin{to{transform:rotate(360deg)}}.dcs-loadingInline{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-empty{margin:0;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:12px}.dcs-muted{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-hint{margin:0;color:var(--dsw-alias-label-caption,#6f727b);font-size:11px}.dcs-subhead{margin:4px 0 0;font-size:11px;line-height:16px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--dsw-alias-label-tertiary,#8a8d95)}
.dcs-tableWrap{width:100%;overflow-x:auto;border-radius:var(--dsw-radius-sm,6px)}.dcs-table{width:100%;border-collapse:collapse;font-size:12px;line-height:18px}
.dcs-table th{padding:6px 10px;text-align:left;white-space:nowrap;font-size:11px;font-weight:500;color:var(--dsw-alias-label-tertiary,#8a8d95);border-bottom:0.5px solid var(--dsw-alias-border-l2,rgba(255,255,255,.1))}.dcs-table td{padding:7px 10px;vertical-align:top;border-bottom:0.5px solid var(--dsw-alias-border-l1,rgba(255,255,255,.06))}
.dcs-table tbody tr:last-child td{border-bottom:0}.dcs-row{cursor:pointer}
.dcs-row:hover td{background:var(--dsw-alias-interactive-bg-hover,rgba(255,255,255,.06))}.dcs-rowSelected td{background:var(--dsw-alias-interactive-bg-active,rgba(255,255,255,.1))}
.dcs-rowSelected td:first-child{box-shadow:inset 2px 0 0 var(--dsw-alias-state-business-primary,#6b9fff)}.dcs-targetCell{display:flex;flex-direction:column;min-width:0;max-width:240px}
.dcs-targetName{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}.dcs-targetKind{color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}
.dcs-findingCount{margin-right:8px;font-weight:600;font-variant-numeric:tabular-nums}.dcs-chips{display:inline-flex;flex-wrap:wrap;align-items:center;gap:4px;vertical-align:middle}
.dcs-chip{display:inline-flex;align-items:center;gap:4px;padding:0 7px;border:0.5px solid currentColor;border-radius:999px;font-size:10px;line-height:16px;white-space:nowrap;font-variant-numeric:tabular-nums}.dcs-chip[data-tone=critical]{color:var(--dsw-alias-state-error-primary,#ff6b6b);background:color-mix(in srgb,currentColor 18%,transparent);font-weight:600}
.dcs-chip[data-tone=error]{color:var(--dsw-alias-state-error-primary,#ff6b6b);background:color-mix(in srgb,currentColor 10%,transparent)}.dcs-chip[data-tone=warn]{color:var(--dsw-alias-state-warn-primary,#f0b429);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=success]{color:var(--dsw-alias-state-success-primary,#4ec97a);background:color-mix(in srgb,currentColor 10%,transparent)}.dcs-chip[data-tone=info]{color:var(--dsw-alias-state-business-primary,#6b9fff);background:color-mix(in srgb,currentColor 10%,transparent)}
.dcs-chip[data-tone=muted]{color:var(--dsw-alias-label-tertiary,#8a8d95)}.dcs-select{max-width:130px;padding:2px 6px;border:0.5px solid var(--dsw-alias-border-l3,rgba(255,255,255,.16));border-radius:var(--dsw-radius-sm,6px);background:var(--dsw-alias-bg-layer-2,#232429);color:var(--dsw-alias-label-primary,#e7e8ea);font:inherit;font-size:11px}
.dcs-select:disabled{opacity:.55}.dcs-findingTitle{display:block;font-weight:500}
.dcs-findingMeta{display:block;color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}.dcs-location{display:inline-block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.dcs-detailRow td{background:var(--dsw-alias-bg-layer-2,#232429)}.dcs-summary{margin:0 0 8px;color:var(--dsw-alias-label-secondary,#b4b6bd)}
.dcs-remediation{margin:0 0 8px;white-space:pre-wrap;overflow-wrap:anywhere}.dcs-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 18px;margin:0}
.dcs-meta>div{display:flex;flex-direction:column;gap:1px;min-width:0}.dcs-meta dt{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:10px;text-transform:uppercase;letter-spacing:.04em}
.dcs-meta dd{margin:0;overflow-wrap:anywhere}.dcs-limits{margin:0;padding-left:18px;color:var(--dsw-alias-label-secondary,#b4b6bd);font-size:12px}
.dcs-limits li{margin:2px 0;overflow-wrap:anywhere}.dcs-detailHead{gap:6px}
.dcs-detailHeading{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}.dcs-detailTitle{margin:0;font-size:14px;line-height:22px;font-weight:600;overflow-wrap:anywhere}
.dcs-detailMeta{display:inline-flex;flex-wrap:wrap;align-items:center;gap:6px}.dcs-detailStatus{display:flex;flex-wrap:wrap;align-items:center;gap:12px;color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-phase strong{color:var(--dsw-alias-label-primary,#e7e8ea);font-weight:600}.dcs-surfaceLabel{display:block}
.dcs-surfaceId{display:block;color:var(--dsw-alias-label-caption,#6f727b)}.dcs-artifacts{display:flex;flex-direction:column;gap:4px;margin:0;padding:0;list-style:none}
.dcs-artifacts li{display:flex;align-items:baseline;justify-content:space-between;gap:12px}.dcs-artifactSize{flex:none;color:var(--dsw-alias-label-caption,#6f727b);font-size:10px}
.dcs-exportRow{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.dcs-exportLabel{color:var(--dsw-alias-label-tertiary,#8a8d95);font-size:11px}
.dcs-srOnly{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
`

function ensureStyles(): void {
  if (typeof document === 'undefined' || document.querySelector('style[' + STYLE_ATTR + ']')) return
  const element = document.createElement('style')
  element.setAttribute(STYLE_ATTR, '')
  element.textContent = DEFAULT_STYLE
  document.head.appendChild(element)
}

interface SlotsApi {
  inject(name: string, callback: () => () => void): void
  register(options: { name: string; id: string; order: number; label: string }, component: React.ComponentType): () => void
}

export function apply(ctx: { slots: SlotsApi }): void {
  ensureStyles()
  ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'codex-security', order: 41, label: 'Codex Security' }, Workbench))
}
