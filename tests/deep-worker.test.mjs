import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { createScope } from '@deepseek-ai/dsh-scope'
import { ToolsService } from '@deepseek-ai/dsh-tools'
import { ToolExecutionPipeline, executeToolBatch } from '@deepseek-ai/dsh-tools/pipeline'
import { SecurityService } from '../lib/service.js'

const digest = (value) => createHash('sha256').update(value).digest('hex')

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-worker-')))
  const target = join(root, 'target')
  await mkdir(join(target, 'src'), { recursive: true })
  await writeFile(join(target, 'src', 'app.js'), 'const safe = true\n')
  return { root, target, cleanup: () => rm(root, { recursive: true, force: true }) }
}

test('a worker can read only a bound file at its original digest', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.WorkerRegistry, 'worker registry must be available')
  const f = await fixture()
  try {
    const registry = new api.WorkerRegistry()
    registry.reserve('child-a', { rootPath: f.target, maxFileBytes: 1024, files: { 'src/app.js': { sha256: digest('const safe = true\n') } } })
    assert.deepEqual(registry.list('child-a'), ['src/app.js'])
    assert.equal(await registry.read('child-a', 'src/app.js'), 'const safe = true\n')
    await writeFile(join(f.target, 'toString'), 'not in the inventory\n')
    await assert.rejects(registry.read('child-a', 'toString'), /scope|inventory/i)
    await assert.rejects(registry.read('other-child', 'src/app.js'), /worker|binding/i)
    await assert.rejects(registry.read('child-a', '../outside.txt'), /path|scope|inventory/i)
    await assert.rejects(registry.read('child-a', 'src/../src/app.js'), /path|scope|inventory/i)
    await assert.rejects(registry.read('child-a', join(f.target, 'src', 'app.js')), /path|scope|inventory/i)
    await writeFile(join(f.target, 'src', 'app.js'), 'const safe = false\n')
    await assert.rejects(registry.read('child-a', 'src/app.js'), /changed|digest|snapshot/i)
    registry.release('child-a')
    await assert.rejects(registry.read('child-a', 'src/app.js'), /worker|binding/i)
  } finally { await f.cleanup() }
})

test('worker reads reject a directory link even when its target has the expected bytes', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.WorkerRegistry, 'worker registry must be available')
  const f = await fixture()
  try {
    const outside = join(f.root, 'outside')
    await mkdir(outside)
    await writeFile(join(outside, 'secret.txt'), 'same bytes\n')
    await symlink(outside, join(f.target, 'src', 'link'), process.platform === 'win32' ? 'junction' : 'dir')
    const registry = new api.WorkerRegistry()
    registry.reserve('child-a', { rootPath: f.target, maxFileBytes: 1024, files: { 'src/link/secret.txt': { sha256: digest('same bytes\n') } } })
    await assert.rejects(registry.read('child-a', 'src/link/secret.txt'), /link|reparse|directory|secure/i)
  } finally { await f.cleanup() }
})

test('worker scope guard denies mutation and transport tools including scoped tools', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.installWorkerGuard, 'worker guard must be available')
  const root = new Context()
  let scope
  try {
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    const worker = { id: 'worker-a' }
    await root.plugin({ name: 'worker-guard-test', inject: ['tools'], apply(ctx) {
      scope = createScope(ctx, worker)
      api.installWorkerGuard(scope.ctx)
    } })
    const tools = root.get('tools')
    const check = (name) => tools.checkGuards({ name, agent: worker, callId: 'test', rootCallId: 'test', token: {}, arguments: {}, signal: new AbortController().signal })
    for (const name of ['write', 'edit', 'bash', 'run_code', 'subagent', 'codex_security_complete_scan']) assert.ok(check(name), name)
    for (const name of ['codex_security_worker_read', 'codex_security_worker_list', 'structured_output']) assert.equal(check(name), undefined, name)
    assert.equal(tools.checkGuards({ name: 'write', agent: { id: 'ordinary' }, callId: 'test', rootCallId: 'test', token: {}, arguments: {}, signal: new AbortController().signal }), undefined)
  } finally { await scope?.dispose(); await root.fiber.dispose() }
})

test('a resumed worker inherits the preset guard after the first activation is gone', async () => {
  const preset = await import('../lib/worker-preset.js').catch(() => undefined)
  assert.ok(preset?.apply, 'worker preset must be available')
  const root = new Context()
  let presetScope
  let firstScope
  let resumedScope
  try {
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    const presetKey = {}
    const firstWorker = { id: 'worker-a' }
    const resumedWorker = { id: 'worker-a-resumed' }
    await root.plugin({ name: 'worker-preset-test', inject: ['tools'], apply(ctx) {
      presetScope = createScope(ctx, presetKey)
      preset.apply(presetScope.ctx)
      firstScope = createScope(ctx, firstWorker, { parent: presetKey })
    } })
    const tools = root.get('tools')
    const check = (agent, name) => tools.checkGuards({ name, agent, callId: 'test', rootCallId: 'test', token: {}, arguments: {}, signal: new AbortController().signal })
    assert.ok(check(firstWorker, 'write'))
    await firstScope.dispose()
    resumedScope = createScope(root, resumedWorker, { parent: presetKey })
    assert.ok(check(resumedWorker, 'write'))
    assert.equal(check(resumedWorker, 'structured_output'), undefined)
  } finally { await resumedScope?.dispose(); await firstScope?.dispose(); await presetScope?.dispose(); await root.fiber.dispose() }
})

test('a replaced worker target directory cannot reuse the original binding', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.WorkerRegistry, 'worker registry must be available')
  const f = await fixture()
  try {
    const registry = new api.WorkerRegistry()
    registry.reserve('child-a', { rootPath: f.target, maxFileBytes: 1024, files: { 'src/app.js': { sha256: digest('const safe = true\n') } } })
    await rename(f.target, join(f.root, 'old-target'))
    await mkdir(join(f.target, 'src'), { recursive: true })
    await writeFile(join(f.target, 'src', 'app.js'), 'const safe = true\n')
    await assert.rejects(registry.read('child-a', 'src/app.js'), /changed/i)
  } finally { await f.cleanup() }
})

test('snapshot capture binds all available bytes and preserves unavailable files', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.captureWorkerSnapshot, 'worker snapshot capture must be available')
  const f = await fixture()
  try {
    const snapshot = await api.captureWorkerSnapshot(f.target, ['src/app.js', 'src/missing.js'], 1024)
    assert.equal(snapshot.files['src/app.js'].sha256, digest('const safe = true\n'))
    assert.deepEqual(snapshot.unavailable.map((entry) => entry.path), ['src/missing.js'])
    const registry = new api.WorkerRegistry()
    registry.reserve('child-a', snapshot)
    assert.equal(await registry.read('child-a', 'src/app.js'), 'const safe = true\n')
    await rename(f.target, join(f.root, 'old-target'))
    await mkdir(join(f.target, 'src'), { recursive: true })
    await writeFile(join(f.target, 'src', 'app.js'), 'const safe = true\n')
    assert.throws(() => registry.reserve('child-b', snapshot), /changed/i)
  } finally { await f.cleanup() }
})

test('snapshot capture observes cancellation while walking a large inventory', async () => {
  const { captureWorkerSnapshot } = await import('../lib/deep-worker.js')
  const f = await fixture()
  try {
    const controller = new AbortController()
    setImmediate(() => controller.abort(new Error('snapshot stopped')))
    const paths = Array.from({ length: 500 }, (_, i) => `src/missing-${i}.js`)
    await assert.rejects(captureWorkerSnapshot(f.target, paths, 1024, controller.signal), /snapshot stopped/)
  } finally { await f.cleanup() }
})

test('a file swapped only during secure snapshot capture cannot inherit the original target binding', async () => {
  const { captureWorkerSnapshot, assertWorkerSnapshotMatches } = await import('../lib/deep-worker.js')
  const f = await fixture()
  try {
    const service = new SecurityService({}, { config: { stateDir: join(f.root, 'state') } })
    const initial = await service.startScan({ targetPath: f.target }, 'deep')
    const good = await captureWorkerSnapshot(f.target, ['src/app.js'], 1024)
    assertWorkerSnapshotMatches(initial.scan.target, ['src/app.js'], good)
    await writeFile(join(f.target, 'src', 'app.js'), 'const swapped = true\n')
    const swapped = await captureWorkerSnapshot(f.target, ['src/app.js'], 1024)
    await writeFile(join(f.target, 'src', 'app.js'), 'const safe = true\n')
    assert.throws(() => assertWorkerSnapshotMatches(initial.scan.target, ['src/app.js'], swapped), /snapshot|changed/i)
  } finally { await f.cleanup() }
})

test('managed draft evidence cannot reopen files outside the bound worker snapshot', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.captureWorkerSnapshot)
  const f = await fixture()
  try {
    await writeFile(join(f.target, 'src', 'secret.js'), 'privateData()\n')
    const snapshot = await api.captureWorkerSnapshot(f.target, ['src/app.js'], 1024)
    const service = new SecurityService({}, { config: { stateDir: join(f.root, 'state') } })
    const scan = await service.startScan({ targetPath: f.target }, 'standard')
    const draft = { scanId: scan.scanId, complete: true, findings: [{
      ruleId: 'test/escape', title: 'Candidate', summary: 'A candidate.', severity: { level: 'high' },
      confidence: { level: 'medium', rationale: 'Static evidence.' }, locations: [{ path: 'src/secret.js', startLine: 1 }], remediation: 'Fix the issue.',
    }], reviewState: { surfaces: [{ label: 'source', disposition: 'reported' }] } }
    await assert.rejects(service.recordScanDraft(draft, { workerSnapshot: snapshot }), /inventory|scope/i)
    draft.findings[0].locations = [{ path: 'src/app.js', startLine: 1 }]
    draft.findings[0].code_evidence = [{ id: 'unbound', code: 'privateData()' }]
    await assert.rejects(service.recordScanDraft(draft, { workerSnapshot: snapshot }), /evidence.*path/i)
    delete draft.findings[0].code_evidence
    const accepted = await service.recordScanDraft(draft, { workerSnapshot: snapshot })
    assert.equal(accepted.findingsCount, 1)
  } finally { await f.cleanup() }
})

test('read receipts appear only after an accepted worker tool result', async () => {
  const api = await import('../lib/deep-worker.js').catch(() => undefined)
  assert.ok(api?.registerWorkerTools, 'worker tool registration must be available')
  const f = await fixture()
  const root = new Context()
  let scope
  try {
    const registry = new api.WorkerRegistry()
    const worker = { id: 'worker-a' }
    registry.reserve(worker.id, { rootPath: f.target, maxFileBytes: 1024, files: { 'src/app.js': { sha256: digest('const safe = true\n') } } }, { allowUnpositionedReceipts: true })
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    let pipeline
    let blockFirstRead = true
    let replaceNextRead = true
    await root.plugin({ name: 'worker-tools-test', inject: ['tools'], apply(ctx) {
      api.registerWorkerTools(ctx, registry)
      scope = createScope(ctx, worker)
      api.installWorkerGuard(scope.ctx)
      pipeline = new ToolExecutionPipeline(ctx)
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = await next()
        if (exec.name === 'codex_security_worker_read' && blockFirstRead) {
          blockFirstRead = false
          return { kind: 'block', feedback: [{ type: 'text', text: 'Read rejected by policy.' }] }
        }
        if (exec.name === 'codex_security_worker_read' && replaceNextRead) {
          replaceNextRead = false
          return { kind: 'accept', content: [{ type: 'text', text: 'The file was truncated by policy.' }] }
        }
        return decision
      })
    } })
    const signal = new AbortController().signal
    const tools = root.get('tools')
    const toolSet = await tools.resolve({ agent: worker, modelSelection: { provider: 'test', model: 'test' }, signal })
    assert.deepEqual(registry.receipts(worker.id), [])
    const invoke = async (path) => (await executeToolBatch({ calls: [{ type: 'tool-call', id: 'read-1', name: 'codex_security_worker_read', arguments: JSON.stringify({ path }) }], agent: worker, toolSet, signal }, pipeline, () => 1)).results[0].result
    const blocked = await invoke('src/app.js')
    assert.equal(blocked.isError, true)
    assert.deepEqual(registry.receipts(worker.id), [])
    const truncated = await invoke('src/app.js')
    assert.equal(truncated.isError, false)
    assert.deepEqual(registry.receipts(worker.id), [])
    const accepted = await invoke('src/app.js')
    assert.equal(accepted.isError, false, JSON.stringify(accepted))
    assert.deepEqual(registry.receipts(worker.id), ['src/app.js'])
    const rejected = await invoke('../private.txt')
    assert.equal(rejected.isError, true)
    assert.deepEqual(registry.receipts(worker.id), ['src/app.js'])
    const ordinary = { id: 'ordinary' }
    const ordinarySet = await tools.resolve({ agent: ordinary, modelSelection: { provider: 'test', model: 'test' }, signal })
    assert.equal(tools.get('codex_security_worker_read', ordinary, ordinarySet), undefined)
    ordinarySet.dispose()
    toolSet.dispose()
  } finally { await scope?.dispose(); await root.fiber.dispose(); await f.cleanup() }
})

test('chunked reads count a file only when accepted chunks cover its entire verified content', async () => {
  const { WorkerRegistry, registerWorkerTools } = await import('../lib/deep-worker.js')
  const f = await fixture()
  const root = new Context()
  let scope
  try {
    const text = 'a'.repeat(10000)
    await writeFile(join(f.target, 'src', 'app.js'), text)
    const worker = { id: 'worker-chunks' }
    const registry = new WorkerRegistry()
    registry.reserve(worker.id, { rootPath: f.target, maxFileBytes: 20000, files: { 'src/app.js': { sha256: digest(text) } } }, { allowUnpositionedReceipts: true })
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    let pipeline
    await root.plugin({ name: 'worker-chunks-test', inject: ['tools'], apply(ctx) {
      registerWorkerTools(ctx, registry)
      scope = createScope(ctx, worker)
      pipeline = new ToolExecutionPipeline(ctx)
    } })
    const signal = new AbortController().signal
    const toolSet = await root.get('tools').resolve({ agent: worker, modelSelection: { provider: 'test', model: 'test' }, signal })
    const invoke = async (offset) => (await executeToolBatch({ calls: [{ type: 'tool-call', id: 'chunk-' + offset, name: 'codex_security_worker_read', arguments: JSON.stringify({ path: 'src/app.js', offset }) }], agent: worker, toolSet, signal }, pipeline, () => 1)).results[0].result
    const first = await invoke(0)
    assert.equal(first.value.content.length, 4096)
    assert.equal(first.value.nextOffset, 4096)
    assert.deepEqual(registry.receipts(worker.id), [])
    const last = await invoke(8192)
    assert.equal(last.value.nextOffset, null)
    assert.deepEqual(registry.receipts(worker.id), [])
    await invoke(4096)
    assert.deepEqual(registry.receipts(worker.id), ['src/app.js'])
    toolSet.dispose()
  } finally { await scope?.dispose(); await root.fiber.dispose(); await f.cleanup() }
})

test('reads in the same model step as final output cannot count as prior review', async () => {
  const { WorkerRegistry, registerWorkerTools } = await import('../lib/deep-worker.js')
  const f = await fixture()
  const root = new Context()
  const scopes = []
  try {
    const registry = new WorkerRegistry()
    await root.plugin({ name: 'system-prompt-test', apply(ctx) { ctx.provide('systemPrompt', { tools() { return () => {} } }) } })
    await root.plugin(ToolsService)
    let pipeline
    let pluginCtx
    await root.plugin({ name: 'worker-step-test', inject: ['tools'], apply(ctx) {
      registerWorkerTools(ctx, registry)
      pipeline = new ToolExecutionPipeline(ctx)
      pluginCtx = ctx
    } })
    const run = async (id, sameStep) => {
      const events = []
      const session = { append(type, data) { const event = { type, data, seq: events.length }; events.push(event); return event }, snapshotEvents() { return events } }
      const worker = { id, session }
      registry.reserve(id, { rootPath: f.target, maxFileBytes: 1024, files: { 'src/app.js': { sha256: digest('const safe = true\n') } } })
      const scope = createScope(pluginCtx, worker)
      scopes.push(scope)
      scope.ctx.tools.register({ name: 'structured_output', description: 'Finish', parameters: { type: 'object', properties: {} },
        output: { schema: { type: 'object', additionalProperties: true }, render: () => [{ type: 'text', text: 'done' }] },
        async execute(_args, exec) { exec.concludeTurn(); return { ok: true } } })
      const signal = new AbortController().signal
      const toolSet = await root.get('tools').resolve({ agent: worker, modelSelection: { provider: 'test', model: 'test' }, signal })
      const read = { type: 'tool-call', id: 'read', name: 'codex_security_worker_read', arguments: JSON.stringify({ path: 'src/app.js' }) }
      const final = { type: 'tool-call', id: 'final', name: 'structured_output', arguments: '{}' }
      const batch = (calls, step) => executeToolBatch({ calls, agent: worker, toolSet, signal, log: { turn: 1, step } }, pipeline, () => 1)
      if (sameStep) await batch([read, final], 1)
      else { await batch([read], 1); await batch([final], 2) }
      toolSet.dispose()
      return registry.receipts(id)
    }
    assert.deepEqual(await run('same-step', true), [])
    assert.deepEqual(await run('earlier-step', false), ['src/app.js'])
  } finally { for (const scope of scopes) await scope.dispose(); await root.fiber.dispose(); await f.cleanup() }
})

test('sequential chunks compress without an 8192-chunk coverage ceiling', async () => {
  const { mergeReceiptRanges } = await import('../lib/deep-worker.js')
  let ranges = []
  for (let i = 0; i < 8193; i++) ranges = mergeReceiptRanges(ranges, { start: i, end: i + 1, total: 8193, position: { turn: 1, step: i } })
  assert.equal(ranges.length, 1)
  assert.equal(ranges[0].start, 0)
  assert.equal(ranges[0].end, 8193)
  assert.equal(ranges[0].position.step, 8192)
})

test('POSIX named pipes are rejected without blocking the process', { skip: process.platform === 'win32' }, async () => {
  const f = await fixture()
  try {
    execFileSync('mkfifo', [join(f.target, 'victim.js')])
    const script = fileURLToPath(new URL('./fixtures/deep-fifo-process.mjs', import.meta.url))
    const output = execFileSync(process.execPath, [script, f.target], { encoding: 'utf8', timeout: 3000 })
    assert.match(output, /regular file|secure worker/i)
  } finally { await f.cleanup() }
})
