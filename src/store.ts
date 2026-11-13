import { readdir } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import type { Config } from './config.js'
import type { Finding, ScanRecord, ScanStatus, ScanSummary, Severity, TriageEntry, FindingStatus } from './types.js'
import { SEVERITIES } from './types.js'
import { ensureDir, joinWithin, nowIso, readJson, readText, sanitizeRelative, writeFileAtomic, writeJsonAtomic, sha256 } from './util.js'

export interface ScanIndex { version: 1; scans: Record<string, ScanSummary & { repoKey: string }> }

export interface CreateScanInput {
  scanId: string
  mode: ScanRecord['mode']
  promptOnly: boolean
  target: ScanRecord['target']
  scope: ScanRecord['scope']
  inventory: ScanRecord['inventory']
  budget?: ScanRecord['budget']
  notes?: string
  threatModel?: ScanRecord['threatModel']
  previousScanId?: string
  warnings: string[]
}

export function defaultStateDir(patchPath: string | undefined, configured: string): string {
  if (configured.length > 0) return configured
  if (patchPath && patchPath.length > 0) return join(dirname(patchPath), 'data', 'codex-security')
  const home = process.env['DSH_HOME'] || join(process.env['HOME'] ?? process.cwd(), '.dsh')
  return join(home, 'profiles', 'web', 'data', 'codex-security')
}

export function repoKeyFor(rootPath: string): string {
  return sha256(rootPath).slice(0, 16)
}

function emptySeverityCounts(): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  return counts
}

export function summarize(record: ScanRecord): ScanSummary {
  return {
    scanId: record.scanId,
    mode: record.mode,
    status: record.status,
    repoKey: record.repoKey,
    target: {
      displayName: record.target.displayName,
      kind: record.target.kind,
      ...(record.target.revision ? { revision: record.target.revision } : {}),
      ...(record.target.baseRevision ? { baseRevision: record.target.baseRevision } : {}),
      ...(record.target.headRevision ? { headRevision: record.target.headRevision } : {}),
    },
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    findingsCount: record.findingsCount,
    severityCounts: record.severityCounts,
    progress: { phase: record.progress.phase, discoveryRuns: record.progress.discoveryRuns, updatedAt: record.progress.updatedAt },
    ...(record.policy ? { policy: record.policy } : {}),
  }
}

export class ScanStore {
  private indexCache: ScanIndex | undefined
  private queue: Promise<unknown> = Promise.resolve()

  constructor(public readonly stateDir: string) {}

  private get indexPath(): string { return join(this.stateDir, 'index.json') }

  scanDir(record: Pick<ScanRecord, 'repoKey' | 'scanId'>): string {
    return join(this.stateDir, 'repositories', record.repoKey, 'scans', record.scanId)
  }

  async init(): Promise<void> {
    await ensureDir(this.stateDir)
    await ensureDir(join(this.stateDir, 'repositories'))
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.queue.then(operation, operation)
    this.queue = next.catch(() => undefined)
    return next
  }

  async loadIndex(): Promise<ScanIndex> {
    if (this.indexCache) return this.indexCache
    const stored = await readJson<ScanIndex>(this.indexPath)
    this.indexCache = stored && stored.version === 1 ? stored : { version: 1, scans: {} }
    return this.indexCache
  }

  async saveIndex(index: ScanIndex): Promise<void> {
    this.indexCache = index
    await writeJsonAtomic(this.indexPath, index)
  }

  async create(input: CreateScanInput): Promise<ScanRecord> {
    return this.serialize(async () => {
      const timestamp = nowIso()
      const record: ScanRecord = {
        scanId: input.scanId,
        repoKey: repoKeyFor(input.target.rootPath),
        mode: input.mode,
        status: 'running',
        promptOnly: input.promptOnly,
        createdAt: timestamp,
        updatedAt: timestamp,
        target: input.target,
        scope: input.scope,
        inventory: input.inventory,
        progress: { phase: 'target-bound', notes: [], discoveryRuns: 0, startedAt: timestamp, updatedAt: timestamp },
        ...(input.budget ? { budget: input.budget } : {}),
        ...(input.notes ? { notes: input.notes } : {}),
        ...(input.threatModel ? { threatModel: input.threatModel } : {}),
        ...(input.previousScanId ? { previousScanId: input.previousScanId } : {}),
        artifacts: [],
        findingsCount: 0,
        severityCounts: emptySeverityCounts(),
        warnings: input.warnings,
      }
      await this.writeRecord(record)
      const dir = this.scanDir(record)
      await ensureDir(join(dir, 'checkpoints'))
      await ensureDir(join(dir, 'artifacts'))
      const index = await this.loadIndex()
      index.scans[record.scanId] = { ...summarize(record), repoKey: record.repoKey }
      await this.saveIndex(index)
      return record
    })
  }

  private async writeRecord(record: ScanRecord): Promise<void> {
    await writeJsonAtomic(join(this.scanDir(record), 'scan.json'), record)
  }

  async get(scanId: string): Promise<{ record: ScanRecord; dir: string } | undefined> {
    if (!/^cs_[a-f0-9]{24}$/.test(scanId)) return undefined
    const index = await this.loadIndex()
    const entry = index.scans[scanId]
    if (entry) {
      const dir = join(this.stateDir, 'repositories', entry.repoKey, 'scans', scanId)
      const record = await readJson<ScanRecord>(join(dir, 'scan.json'))
      if (record) return { record, dir }
    }
    // Fallback: index may be stale or missing; scan the repository directories.
    const reposDir = join(this.stateDir, 'repositories')
    let repos: string[] = []
    try { repos = await readdir(reposDir) } catch { return undefined }
    for (const repoKey of repos) {
      const dir = join(reposDir, repoKey, 'scans', scanId)
      const record = await readJson<ScanRecord>(join(dir, 'scan.json'))
      if (record) {
        index.scans[scanId] = { ...summarize(record), repoKey }
        await this.saveIndex(index)
        return { record, dir }
      }
    }
    return undefined
  }

  async update(scanId: string, mutate: (record: ScanRecord) => void): Promise<ScanRecord> {
    return this.serialize(async () => {
      const found = await this.get(scanId)
      if (!found) throw new Error('codex-security: scan not found: ' + scanId)
      const record = found.record
      mutate(record)
      record.updatedAt = nowIso()
      record.progress.updatedAt = record.updatedAt
      await this.writeRecord(record)
      const index = await this.loadIndex()
      index.scans[record.scanId] = { ...summarize(record), repoKey: record.repoKey }
      await this.saveIndex(index)
      return record
    })
  }

  async writeScanFile(scanId: string, name: string, value: unknown): Promise<string> {
    const found = await this.get(scanId)
    if (!found) throw new Error('codex-security: scan not found: ' + scanId)
    const target = joinWithin(found.dir, name)
    await writeJsonAtomic(target, value)
    return target
  }

  async readScanFile<T>(scanId: string, name: string): Promise<T | undefined> {
    const found = await this.get(scanId)
    if (!found) throw new Error('codex-security: scan not found: ' + scanId)
    return readJson<T>(joinWithin(found.dir, name))
  }

  async list(): Promise<ScanSummary[]> {
    const index = await this.loadIndex()
    return Object.values(index.scans).sort((left, right) => right.createdAt.localeCompare(left.createdAt))
  }

  async saveArtifact(scanId: string, relativePath: string, content: string, mediaType: string): Promise<{ path: string; bytes: number; sha256: string; mediaType: string }> {
    const found = await this.get(scanId)
    if (!found) throw new Error('codex-security: scan not found: ' + scanId)
    const clean = sanitizeRelative(relativePath)
    const target = joinWithin(join(found.dir, 'artifacts'), clean)
    const data = Buffer.from(content, 'utf8')
    await ensureDir(dirname(target))
    await writeFileAtomic(target, data)
    const digest = sha256(data)
    return { path: 'artifacts/' + clean, bytes: data.byteLength, sha256: digest, mediaType }
  }

  async readArtifact(scanId: string, relativePath: string, limit: number): Promise<{ path: string; content: string; bytes: number; truncated: boolean }> {
    const found = await this.get(scanId)
    if (!found) throw new Error('codex-security: scan not found: ' + scanId)
    const clean = relativePath.startsWith('artifacts/') ? sanitizeRelative(relativePath.slice('artifacts/'.length)) : sanitizeRelative(relativePath)
    const target = joinWithin(join(found.dir, 'artifacts'), clean)
    const content = await readText(target, limit)
    if (content === undefined) throw new Error('codex-security: artifact not found: ' + relativePath)
    const { stat } = await import('node:fs/promises')
    const info = await stat(target)
    return { path: 'artifacts/' + clean, content, bytes: info.size, truncated: info.size > limit }
  }

  async listArtifacts(scanId: string): Promise<{ path: string; bytes: number }[]> {
    const found = await this.get(scanId)
    if (!found) return []
    const results: { path: string; bytes: number }[] = []
    const walk = async (dir: string, relBase: string): Promise<void> => {
      let entries
      try { entries = await readdir(dir, { withFileTypes: true }) } catch { return }
      for (const entry of entries) {
        const rel = relBase.length > 0 ? relBase + '/' + entry.name : entry.name
        if (entry.isDirectory()) { await walk(join(dir, entry.name), rel); continue }
        if (!entry.isFile()) continue
        const { stat } = await import('node:fs/promises')
        const info = await stat(join(dir, entry.name))
        results.push({ path: 'artifacts/' + rel, bytes: info.size })
      }
    }
    await walk(join(found.dir, 'artifacts'), '')
    return results.sort((left, right) => left.path.localeCompare(right.path))
  }

  async readTriage(scanId: string): Promise<Record<string, TriageEntry>> {
    return (await this.readScanFile<Record<string, TriageEntry>>(scanId, 'triage.json')) ?? {}
  }

  async setTriage(scanId: string, entry: TriageEntry): Promise<TriageEntry> {
    return this.serialize(async () => {
      const found = await this.get(scanId)
      if (!found) throw new Error('codex-security: scan not found: ' + scanId)
      const triage = (await readJson<Record<string, TriageEntry>>(join(found.dir, 'triage.json'))) ?? {}
      triage[entry.findingId] = entry
      await writeJsonAtomic(join(found.dir, 'triage.json'), triage)
      return entry
    })
  }

  async readFindings(scanId: string): Promise<Finding[]> {
    const document = await this.readScanFile<{ findings?: Finding[] }>(scanId, 'findings.json')
    return document?.findings ?? []
  }
}
