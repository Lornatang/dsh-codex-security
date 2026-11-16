import { createHash } from 'node:crypto'
import { setImmediate as yieldEventLoop } from 'node:timers/promises'
import { digestWorkerSource, readWorkerSource, sourceRootIdentity, workerSourcePath } from './secure-read.js'
import type { TargetInfo } from './types.js'

export interface WorkerSnapshot {
  rootPath: string
  maxFileBytes: number
  files: Record<string, { sha256: string }>
  rootIdentity?: { dev: string; ino: string }
  unavailable?: { path: string; reason: string }[]
  observedDigests?: Record<string, string>
}

interface Binding extends WorkerSnapshot {
  rootNode: { dev: bigint; ino: bigint }
  receipts: Set<string>
  ranges: Map<string, ReceiptRange[]>
  finalStep?: StepPosition
  allowUnpositioned: boolean
}
export interface StepPosition { turn: number; step: number }
export interface ReceiptRange { start: number; end: number; total: number; position?: StepPosition }

/** Compact adjacent chunks conservatively using their latest model step. */
export function mergeReceiptRanges(ranges: ReceiptRange[], next: ReceiptRange): ReceiptRange[] {
  const compare = (a?: StepPosition, b?: StepPosition): number => (a?.turn ?? -1) - (b?.turn ?? -1) || (a?.step ?? -1) - (b?.step ?? -1)
  const sorted = [...ranges, next].sort((a, b) => a.start - b.start || b.end - a.end)
  const merged: ReceiptRange[] = []
  for (const range of sorted) {
    const previous = merged[merged.length - 1]
    if (!previous || previous.total !== range.total || range.start > previous.end) { merged.push({ ...range }); continue }
    if (range.end <= previous.end && compare(previous.position, range.position) <= 0) continue
    if (range.start <= previous.start && range.end >= previous.end && compare(range.position, previous.position) <= 0) { merged[merged.length - 1] = { ...range }; continue }
    previous.end = Math.max(previous.end, range.end)
    if (compare(previous.position, range.position) < 0) previous.position = range.position
  }
  return merged
}

/** Capture exact source bytes without allowing links or paths outside the target. */
export async function captureWorkerSnapshot(rootPath: string, paths: string[], maxFileBytes: number, signal?: AbortSignal): Promise<WorkerSnapshot> {
  signal?.throwIfAborted()
  const root = sourceRootIdentity(rootPath)
  const files = Object.create(null) as WorkerSnapshot['files']
  const observedDigests = Object.create(null) as Record<string, string>
  const unavailable: { path: string; reason: string }[] = []
  let visited = 0
  for (const path of [...new Set(paths)].sort()) {
    if (++visited % 32 === 0) await yieldEventLoop()
    signal?.throwIfAborted()
    try {
      const content = readWorkerSource(root.path, path, maxFileBytes, root.identity)
      const digest = createHash('sha256').update(content).digest('hex')
      observedDigests[path] = digest
      const text = content.toString('utf8')
      if (!Buffer.from(text, 'utf8').equals(content)) throw new Error('worker source is not valid UTF-8')
      files[path] = { sha256: digest }
    } catch (error) {
      signal?.throwIfAborted()
      if (!Object.hasOwn(observedDigests, path)) {
        try { observedDigests[path] = await digestWorkerSource(root.path, path, root.identity, signal) } catch { signal?.throwIfAborted() }
      }
      unavailable.push({ path, reason: error instanceof Error ? error.message.slice(0, 1000) : 'worker source is unavailable' })
    }
  }
  return {
    rootPath: root.path, rootIdentity: { dev: String(root.identity.dev), ino: String(root.identity.ino) },
    maxFileBytes, files, unavailable, observedDigests,
  }
}

/** Verify that the secure per-file capture is exactly the target originally bound. */
export function assertWorkerSnapshotMatches(target: TargetInfo, paths: string[], snapshot: WorkerSnapshot): void {
  if (target.kind === 'git_diff') throw new Error('codex-security: Deep worker snapshots do not support diffs')
  const hash = createHash('sha256')
  hash.update(JSON.stringify({ kind: target.kind, revision: target.revision ?? null, baseRevision: target.baseRevision ?? null, diffFiles: null }))
  for (const path of [...paths].sort()) {
    const digest = snapshot.observedDigests && Object.hasOwn(snapshot.observedDigests, path) ? snapshot.observedDigests[path] : 'unavailable'
    hash.update('\u0000' + path + '\u0000' + digest)
  }
  if ('codex-security-snapshot/v1:sha256:' + hash.digest('hex') !== target.snapshotDigest) {
    throw new Error('codex-security: secure worker snapshot differs from the originally bound target or contains an unverifiable file')
  }
}

/** Bind each worker to a fixed target and exact file digests. */
export class WorkerRegistry {
  private readonly workers = new Map<string, Binding>()

  reserve(childId: string, snapshot: WorkerSnapshot, options: { allowUnpositionedReceipts?: boolean } = {}): void {
    if (!childId || this.workers.has(childId)) throw new Error('codex-security: invalid or duplicate worker binding')
    const root = sourceRootIdentity(snapshot.rootPath)
    if (snapshot.rootIdentity && (String(root.identity.dev) !== snapshot.rootIdentity.dev || String(root.identity.ino) !== snapshot.rootIdentity.ino)) throw new Error('codex-security: worker target directory changed since snapshot')
    const files = Object.create(null) as WorkerSnapshot['files']
    for (const [path, item] of Object.entries(snapshot.files)) {
      if (workerSourcePath(path) !== path || !/^[a-f0-9]{64}$/.test(item.sha256)) throw new Error('codex-security: invalid worker inventory')
      files[path] = { sha256: item.sha256 }
    }
    if (!Number.isSafeInteger(snapshot.maxFileBytes) || snapshot.maxFileBytes < 1) throw new Error('codex-security: invalid worker size limit')
    this.workers.set(childId, { rootPath: root.path, rootNode: root.identity, maxFileBytes: snapshot.maxFileBytes, files, receipts: new Set(), ranges: new Map(), allowUnpositioned: options.allowUnpositionedReceipts === true })
  }

  release(childId: string): void { this.workers.delete(childId) }

  has(childId: string): boolean { return this.workers.has(childId) }

  list(childId: string): string[] { return Object.keys(this.binding(childId).files).sort() }

  receipts(childId: string): string[] {
    const binding = this.binding(childId)
    const complete = new Set(binding.receipts)
    for (const [path, chunks] of binding.ranges) {
      const eligible = chunks.filter((chunk) => chunk.position ? binding.finalStep &&
        (chunk.position.turn < binding.finalStep.turn || (chunk.position.turn === binding.finalStep.turn && chunk.position.step < binding.finalStep.step)) : binding.allowUnpositioned)
      const sorted = eligible.sort((a, b) => a.start - b.start)
      if (!sorted.length) continue
      let covered = 0
      for (const chunk of sorted) {
        if (chunk.start > covered) break
        covered = Math.max(covered, chunk.end)
      }
      if (covered === sorted[0]!.total && sorted[0]!.start === 0) complete.add(path)
    }
    return [...complete].sort()
  }

  acceptFinalStep(childId: string, position: StepPosition): void {
    const binding = this.workers.get(childId)
    if (binding) binding.finalStep = position
  }

  async read(childId: string, path: string): Promise<string> {
    return this.readText(childId, path)
  }

  private readText(childId: string, path: string): string {
    const binding = this.binding(childId)
    const source = workerSourcePath(path)
    if (!Object.hasOwn(binding.files, source)) throw new Error('codex-security: worker source path is outside the bound inventory')
    const file = binding.files[source]!
    const bytes = readWorkerSource(binding.rootPath, source, binding.maxFileBytes, binding.rootNode, file.sha256)
    const text = bytes.toString('utf8')
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error('codex-security: worker source is not valid UTF-8')
    return text
  }

  async readChunk(childId: string, path: string, offset: number): Promise<{ path: string; content: string; offset: number; nextOffset: number | null; totalLength: number }> {
    if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('codex-security: invalid worker source offset')
    const content = this.readText(childId, path)
    if (offset > content.length) throw new Error('codex-security: worker source offset exceeds file length')
    const end = Math.min(offset + 4096, content.length)
    return { path, content: content.slice(offset, end), offset, nextOffset: end === content.length ? null : end, totalLength: content.length }
  }

  /** Verify each delivered chunk against the snapshot before counting its covered range. */
  acceptChunk(childId: string, value: { path: string; content: string; offset: number; nextOffset: number | null; totalLength: number }, position?: StepPosition): void {
    const binding = this.workers.get(childId)
    if (!binding || !Object.hasOwn(binding.files, value.path) || !Number.isSafeInteger(value.offset) || !Number.isSafeInteger(value.totalLength)) return
    if (!position && !binding.allowUnpositioned) return
    const end = value.offset + value.content.length
    if (value.offset < 0 || end > value.totalLength || (value.nextOffset !== null && value.nextOffset !== end) || (value.nextOffset === null && end !== value.totalLength)) return
    const original = this.readText(childId, value.path)
    if (original.length !== value.totalLength || original.slice(value.offset, end) !== value.content) return
    const ranges = mergeReceiptRanges(binding.ranges.get(value.path) ?? [], { start: value.offset, end, total: value.totalLength, ...(position ? { position } : {}) })
    if (ranges.length > 16384) return
    binding.ranges.set(value.path, ranges)
  }

  /** Called only after the host accepts the tool's authoritative result. */
  acceptRead(childId: string, path: string, content: string): void {
    const binding = this.workers.get(childId)
    if (!binding || !Object.hasOwn(binding.files, path)) return
    if (createHash('sha256').update(content, 'utf8').digest('hex') === binding.files[path]!.sha256) binding.receipts.add(path)
  }

  private binding(childId: string): Binding {
    const binding = this.workers.get(childId)
    if (!binding) throw new Error('codex-security: worker has no active binding')
    return binding
  }
}

interface GuardContext {
  tools: { guard(callback: (execution: { name: string }) => string | undefined): () => void }
}

/** Install in the persistent worker preset, so resumed child sessions remain confined. */
export function installWorkerGuard(ctx: GuardContext): () => void {
  const allowed = new Set(['codex_security_worker_read', 'codex_security_worker_list', 'structured_output'])
  return ctx.tools.guard((execution) => allowed.has(execution.name) ? undefined : 'codex-security: tool is not available to a security review worker')
}

interface WorkerExecution {
  name: string
  callId?: string
  agent?: { id?: string; session?: { snapshotEvents?: () => readonly { type: string; data?: Record<string, unknown> }[] } }
  arguments?: unknown
}

interface WorkerToolsContext {
  tools: {
    register(definition: Record<string, unknown>, options: { when: (context: { agent: { id?: string } }) => boolean }): () => void
  }
  on(event: string, listener: (execution: WorkerExecution, result: { isError: boolean; value?: unknown; content?: { type: string; text?: string }[] }) => void): (() => void) | undefined
}

/** Register worker-only tools; ordinary agents never receive them in their tool set. */
export function registerWorkerTools(ctx: WorkerToolsContext, registry: WorkerRegistry): () => void {
  const options = { when: ({ agent }: { agent: { id?: string } }): boolean => typeof agent.id === 'string' && registry.has(agent.id) }
  const output = { schema: { type: 'object', additionalProperties: true }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value) }] }
  const workerId = (exec: WorkerExecution): string => {
    const id = exec.agent?.id
    if (typeof id !== 'string' || !registry.has(id)) throw new Error('codex-security: worker has no active binding')
    return id
  }
  const disposers = [
    ctx.tools.register({
      name: 'codex_security_worker_list', description: 'List files in this worker’s bound review inventory.',
      parameters: { type: 'object', properties: {}, additionalProperties: false }, output, timeoutMs: 60000,
      execute: async (_args: unknown, exec: WorkerExecution) => ({ files: registry.list(workerId(exec)) }),
    }, options),
    ctx.tools.register({
      name: 'codex_security_worker_read', description: 'Read a verified source chunk; repeat with nextOffset until it is null.',
      parameters: { type: 'object', properties: { path: { type: 'string' }, offset: { type: 'integer' } }, required: ['path'], additionalProperties: false }, output, timeoutMs: 60000,
      execute: async (args: unknown, exec: WorkerExecution) => {
        if (!args || typeof args !== 'object' || Array.isArray(args) || typeof (args as { path?: unknown }).path !== 'string') throw new Error('codex-security: worker source path is required')
        const path = (args as { path: string }).path
        const offset = (args as { offset?: unknown }).offset ?? 0
        if (typeof offset !== 'number') throw new Error('codex-security: invalid worker source offset')
        return registry.readChunk(workerId(exec), path, offset)
      },
    }, options),
  ]
  const off = ctx.on('tools/result', (execution, result) => {
    if (result.isError || typeof execution.agent?.id !== 'string' || !registry.has(execution.agent.id)) return
    const events = execution.agent.session?.snapshotEvents?.() ?? []
    const call = [...events].reverse().find((event) => event.type === 'tool/call' && event.data?.['callId'] === execution.callId && event.data?.['name'] === execution.name)
    const turn = call?.data?.['turn']
    const step = call?.data?.['step']
    const position = typeof turn === 'number' && Number.isSafeInteger(turn) && typeof step === 'number' && Number.isSafeInteger(step) ? { turn, step } : undefined
    if (execution.name === 'structured_output') { if (position) registry.acceptFinalStep(execution.agent.id, position); return }
    if (execution.name !== 'codex_security_worker_read') return
    const args = execution.arguments as { path?: unknown } | undefined
    const value = result.value as { path?: unknown; content?: unknown; offset?: unknown; nextOffset?: unknown; totalLength?: unknown } | undefined
    if (typeof args?.path !== 'string' || value?.path !== args.path || typeof value.content !== 'string') return
    // The canonical value can survive while a post-execute policy replaces or
    // truncates the actual model-facing content. Count only the delivered JSON.
    if (result.content?.length !== 1 || result.content[0]?.type !== 'text' || typeof result.content[0].text !== 'string') return
    try {
      const delivered = JSON.parse(result.content[0].text) as typeof value
      if (delivered?.path === value.path && delivered.content === value.content && delivered.offset === value.offset &&
          delivered.nextOffset === value.nextOffset && delivered.totalLength === value.totalLength &&
          typeof value.offset === 'number' && typeof value.totalLength === 'number' && (typeof value.nextOffset === 'number' || value.nextOffset === null)) {
        registry.acceptChunk(execution.agent.id, { path: args.path, content: value.content, offset: value.offset, nextOffset: value.nextOffset, totalLength: value.totalLength }, position)
      }
    } catch { /* A replaced, truncated or non-JSON projection is not a receipt. */ }
  })
  return () => { off?.(); for (const dispose of disposers) dispose() }
}
