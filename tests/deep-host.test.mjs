import test from 'node:test'
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { Context } from '@deepseek-ai/cordis'
import { Loader } from '@deepseek-ai/cordis-plugin-loader'
import { createScope } from '@deepseek-ai/dsh-scope'
import { ToolsService } from '@deepseek-ai/dsh-tools'
import { AgentPresetRegistry } from '@deepseek-ai/dsh-agent-preset-registry'
import { SubagentRuntime } from '@deepseek-ai/dsh-subagent'
import * as spawnProvider from '@deepseek-ai/dsh-subagent-spawn-in-process'
import { ToolExecutionPipeline, executeToolBatch } from '@deepseek-ai/dsh-tools/pipeline'
import { apply as applyPlugin } from '../lib/index.js'
import { SecurityService } from '../lib/service.js'
import { DshWorkerHost } from '../lib/deep-host.js'
import { createSecurityTools } from '../lib/tools.js'

function services() {
  const calls = []
  const provider = { inheritsParentContext: false, prepareContinuable() {}, capabilities: { agentPreset: true, outputSchema: true, depthLimit: true } }
  const subagents = {
    getProvider: () => provider,
    async startActivation(spec) { calls.push(spec); return { childId: spec.childId, result: Promise.resolve({ stopReason: 'completed' }), dispose: async () => {} } },
  }
  const presets = {
    async register(definition) { calls.push(definition); return async () => {} },
    async resolve(id) { return { id } },
  }
  return { calls, provider, subagents, presets }
}

test('DSH worker host requires an isolated preset and reserves the local child before activation', async () => {
  const f = services()
  const host = new DshWorkerHost(f.subagents, f.presets)
  await host.ensureReady()
  const parent = { id: 'parent' }
  const signal = new AbortController().signal
  const activation = await host.start({ childId: 'child', agent: parent, signal, prompt: 'review', outputSchema: { type: 'object', properties: {} } })
  const definition = f.calls[0]
  assert.ok(definition.plugins.some((entry) => entry.name.endsWith('/worker-preset')))
  assert.ok(definition.plugins.some((entry) => entry.name === '@deepseek-ai/dsh-tool-executor-native'))
  assert.equal(f.calls[1].parent, parent)
  assert.equal(f.calls[1].childId, 'child')
  assert.equal(f.calls[1].provider, 'spawn')
  assert.equal(f.calls[1].agentPreset, definition.id)
  assert.equal(f.calls[1].delivery, 'caller')
  assert.equal(activation.childId, 'child')
  await host.dispose()
})

test('DSH worker host fails closed for inherited or unavailable worker capability', async () => {
  const f = services()
  f.provider.inheritsParentContext = true
  const host = new DshWorkerHost(f.subagents, f.presets)
  await assert.rejects(host.ensureReady(), /isolat|provider/i)
  assert.equal(f.calls.filter((call) => call.childId).length, 0)
  await host.dispose()
})

test('Deep tool forwards the actual execution identity and requires an available coordinator', async () => {
  const calls = []
  const service = { config: { defaultMode: 'deep' } }
  const coordinator = { async start(args, actor) { calls.push({ args, actor }); return { ok: true, scanId: 'ok' } } }
  const start = createSecurityTools(service, () => coordinator).find((tool) => tool.name === 'codex_security_start_deep_scan')
  const actor = { agent: { id: 'real-session' }, signal: new AbortController().signal }
  await start.execute({ targetPath: '.' }, actor)
  assert.equal(calls[0].actor, actor)
  const absent = createSecurityTools(service).find((tool) => tool.name === 'codex_security_start_deep_scan')
  await assert.rejects(absent.execute({ targetPath: '.' }, actor), /unavailable|subagent/i)
})

test('real DSH preset loader mounts the packaged worker guard and native executor', async () => {
  const root = new Context()
  let host
  let scope
  try {
    await root.plugin({ name: 'test-dependencies', apply(ctx) {
      ctx.provide('systemPrompt', { tools() { return () => {} } })
      ctx.provide('sessionProjections', { async register() { return { stateOf() { return null } } } })
      ctx.provide('agents', {})
    } })
    await root.plugin(Loader, { baseUrl: pathToFileURL(join(process.cwd(), 'package.json')).href })
    await root.plugin(ToolsService)
    await root.plugin(AgentPresetRegistry, { default: 'standard' })
    const f = services()
    host = new DshWorkerHost(f.subagents, root.get('agentPresets'))
    await host.ensureReady()
    const agent = { id: 'actual-preset-worker' }
    scope = createScope(root, agent)
    await root.get('agentPresets').mount(scope.ctx, 'codex-security-deep-worker-v1')
    const tools = root.get('tools')
    const check = (name) => tools.checkGuards({ name, agent, callId: 'test', rootCallId: 'test', token: {}, arguments: {}, signal: new AbortController().signal })
    assert.ok(check('write'))
    assert.ok(check('run_code'))
    assert.equal(check('codex_security_worker_read'), undefined)
    assert.equal(check('structured_output'), undefined)
  } finally { await scope?.dispose(); await host?.dispose(); await root.fiber.dispose() }
})

test('real DSH subagent registry accepts the reserved worker activation contract', async () => {
  const root = new Context()
  let host
  const parent = { id: 'live-parent' }
  try {
    await root.plugin({ name: 'test-subagent-dependencies', apply(ctx) {
      ctx.provide('workingDirectory', {})
      ctx.provide('sessionProjections', { async register() { return { stateOf() { return {} } } } })
      ctx.provide('agents', { get(id) { return id === parent.id ? parent : undefined } })
    } })
    await root.plugin(SubagentRuntime, { maxActiveSubagents: 8, maxDepth: 1 })
    await root.plugin(spawnProvider, { providerName: 'spawn' })
    const runtime = root.get('subagents')
    let received
    runtime.manager = { async startLocal(spec, prepare) {
      received = spec
      await prepare({ sessionId: spec.childId })
      return { childId: spec.childId, result: Promise.resolve({ stopReason: 'completed' }), dispose: async () => {} }
    } }
    const f = services()
    host = new DshWorkerHost(runtime, f.presets)
    const activation = await host.start({ childId: 'reserved-worker', agent: parent, signal: new AbortController().signal,
      prompt: 'review', outputSchema: { type: 'object', properties: { draftJson: { type: 'string' } }, required: ['draftJson'], additionalProperties: false } })
    assert.equal(received.parent, parent)
    assert.equal(received.childId, 'reserved-worker')
    assert.equal(received.agentPreset, 'codex-security-deep-worker-v1')
    assert.equal(activation.childId, 'reserved-worker')
  } finally { await host?.dispose(); await root.fiber.dispose() }
})

test('plugin starts an automatic scan through real DSH tools, preset and subagent registries', async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'dcs-dsh-host-')))
  const target = join(directory, 'target')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const stateDir = join(directory, 'state')
  const root = new Context()
  const parent = { id: 'live-parent' }
  try {
    await root.plugin({ name: 'integration-dependencies', apply(ctx) {
      ctx.provide('systemPrompt', { tools() { return () => {} } })
      ctx.provide('sessionProjections', { async register() { return { stateOf() { return {} } } } })
      ctx.provide('agents', { get(id) { return id === parent.id ? parent : undefined } })
      ctx.provide('workingDirectory', {})
      ctx.provide('skills', { register() { return () => {} } })
    } })
    await root.plugin(Loader, { baseUrl: pathToFileURL(join(process.cwd(), 'package.json')).href })
    await root.plugin(ToolsService)
    await root.plugin(AgentPresetRegistry, { default: 'standard' })
    await root.plugin(SubagentRuntime, { maxActiveSubagents: 8, maxDepth: 1 })
    await root.plugin(spawnProvider, { providerName: 'spawn' })
    let workerCtx
    await root.plugin({ name: 'integration-worker-context', inject: ['tools'], apply(ctx) { workerCtx = ctx } })
    const runtime = root.get('subagents')
    runtime.manager = { async startLocal(spec, prepare) {
      await prepare({ sessionId: spec.childId })
      const events = []
      const session = { append(type, data) { const event = { type, data, seq: events.length }; events.push(event); return event }, snapshotEvents() { return events } }
      const worker = { id: spec.childId, session }
      const scope = createScope(workerCtx, worker)
      await root.get('agentPresets').mount(scope.ctx, spec.agentPreset)
      scope.ctx.tools.register({ name: 'structured_output', description: 'Finish', parameters: { type: 'object', properties: {} },
        output: { schema: { type: 'object', additionalProperties: true }, render: () => [{ type: 'text', text: 'done' }] },
        async execute(_args, exec) { exec.concludeTurn(); return { ok: true } } })
      const tools = root.get('tools')
      const toolSet = await tools.resolve({ agent: worker, modelSelection: { provider: 'test', model: 'test' }, signal: spec.signal })
      const pipeline = new ToolExecutionPipeline(root)
      let step = 0
      const invoke = async (name, args) => (await executeToolBatch({ calls: [{ type: 'tool-call', id: name, name, arguments: JSON.stringify(args) }], agent: worker, toolSet, signal: spec.signal, log: { turn: 1, step: ++step } }, pipeline, () => 1)).results[0].result
      const result = (async () => {
        const list = await invoke('codex_security_worker_list', {})
        assert.equal(list.isError, false)
        for (const path of list.value.files) {
          let offset = 0
          do {
            const read = await invoke('codex_security_worker_read', { path, offset })
            assert.equal(read.isError, false)
            offset = read.value.nextOffset
          } while (offset !== null)
        }
        await invoke('structured_output', {})
        return { stopReason: 'completed', structured: { draftJson: JSON.stringify({ findings: [], reviewState: {
          completeness: 'complete', surfaces: [{ label: 'source', disposition: 'no_issue_found' }],
        } }) } }
      })()
      return { childId: spec.childId, result, dispose: async () => { toolSet.dispose(); await scope.dispose() } }
    } }
    await root.plugin({ name: 'security-integration', inject: ['tools', 'skills'], apply(ctx) { applyPlugin(ctx, { stateDir }) } })
    const tools = root.get('tools')
    const signal = new AbortController().signal
    const parentSet = await tools.resolve({ agent: parent, modelSelection: { provider: 'test', model: 'test' }, signal })
    const start = tools.get('codex_security_start_deep_scan', parent, parentSet)
    const started = await start.execute({ targetPath: target, workers: 1, maxDiscoveryRuns: 1 }, { agent: parent, signal })
    const service = new SecurityService({}, { config: { stateDir } })
    const deadline = Date.now() + 10000
    let record
    do {
      await new Promise((resolve) => setTimeout(resolve, 25))
      const found = await service.store.get(started.scanId)
      record = found?.record
    } while ((!record || record.status === 'running') && Date.now() < deadline)
    assert.ok(record, 'parent scan must be initialized')
    assert.equal(record.status, 'completed', record.error)
    assert.equal(record.findingsCount, 0)
    const status = tools.get('codex_security_get_deep_scan_status', parent, parentSet)
    const progress = await status.execute({ scanId: started.scanId }, { agent: parent, signal })
    assert.equal(progress.attempts, 1)
    assert.equal(progress.status, 'completed')
    assert.equal('claimHash' in progress, false)
    parentSet.dispose()
  } finally { await root.fiber.dispose(); await rm(directory, { recursive: true, force: true }) }
})
