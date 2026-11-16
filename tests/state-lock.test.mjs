import test from 'node:test'
import assert from 'node:assert/strict'
import { fork } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { SecurityService } from '../lib/service.js'

const lockFixture = fileURLToPath(new URL('./fixtures/state-lock-process.mjs', import.meta.url))
const scanFixture = fileURLToPath(new URL('./fixtures/concurrent-scan-process.mjs', import.meta.url))

function childMessage(child, expected) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error(`child timed out waiting for ${expected}`)), 15000)
    function onMessage(message) {
      if (message?.kind === 'error') finish(new Error(message.message))
      else if (message?.kind === expected) finish(undefined, message)
    }
    function onExit(code) { finish(new Error(`child exited before ${expected}: ${code}`)) }
    function finish(error, value) {
      clearTimeout(timer)
      child.off('message', onMessage)
      child.off('exit', onExit)
      if (error) reject(error)
      else resolve(value)
    }
    child.on('message', onMessage)
    child.once('exit', onExit)
  })
}

async function startChildren(args, count) {
  const children = Array.from({ length: count }, (_, index) => fork(scanFixture, [...args, String(index)], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true }))
  await Promise.all(children.map((child) => childMessage(child, 'ready')))
  return children
}

async function runChildren(children) {
  const results = children.map((child) => childMessage(child, 'done'))
  for (const child of children) child.send('go')
  return Promise.all(results)
}

test('a live process owns the lock exclusively and a killed owner releases it', async () => {
  const api = await import('../lib/state-lock.js').catch(() => undefined)
  assert.ok(api?.acquireStateLock, 'cross-process state lock must be available')
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-state-lock-')))
  const path = join(root, 'owner.sqlite')
  let child
  try {
    child = fork(lockFixture, [path], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true })
    await childMessage(child, 'locked')
    await assert.rejects(api.acquireStateLock(path, { timeoutMs: 150 }), /timed out/i)
    const exited = once(child, 'exit')
    child.kill()
    await exited
    child = undefined
    const release = await api.acquireStateLock(path, { timeoutMs: 5000 })
    release()
  } finally {
    if (child) { const exited = once(child, 'exit'); child.kill(); await exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('a waiting lock honors cancellation and unrelated locks remain available', async () => {
  const api = await import('../lib/state-lock.js').catch(() => undefined)
  assert.ok(api?.acquireStateLock, 'cross-process state lock must be available')
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-state-lock-')))
  const path = join(root, 'owner.sqlite')
  let release
  try {
    release = await api.acquireStateLock(path, { timeoutMs: 5000 })
    const independent = await api.acquireStateLock(join(root, 'other.sqlite'), { timeoutMs: 5000 })
    independent()
    const controller = new AbortController()
    const waiting = api.acquireStateLock(path, { timeoutMs: 5000, signal: controller.signal })
    controller.abort()
    await assert.rejects(waiting, (error) => error.name === 'AbortError')
  } finally { release?.(); await rm(root, { recursive: true, force: true }) }
})

test('scan lock waits honor cancellation and release the local queue', async () => {
  const { acquireStateLock } = await import('../lib/state-lock.js')
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-scan-cancel-')))
  const target = join(root, 'target')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'safe()\n')
  const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
  const scan = await service.startScan({ targetPath: target }, 'standard')
  const release = await acquireStateLock(join(service.store.stateDir, '.locks', 'scan-' + scan.scanId + '.sqlite'))
  let waiting
  try {
    const controller = new AbortController()
    waiting = service.completeScan({ scanId: scan.scanId }, { signal: controller.signal })
    void waiting.catch(() => undefined)
    await new Promise((resolve) => setTimeout(resolve, 30))
    controller.abort(new Error('scan canceled'))
    const outcome = await Promise.race([waiting.then(() => 'wrong', () => 'aborted'), new Promise((resolve) => setTimeout(() => resolve('timeout'), 500))])
    assert.equal(outcome, 'aborted')
    release()
    await service.updateScanProgress({ scanId: scan.scanId, phase: 'resumed' })
  } finally { release(); await waiting?.catch(() => undefined); await rm(root, { recursive: true, force: true }) }
})

test('concurrent scan creation preserves every entry in the durable index', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-index-race-')))
  const stateDir = join(root, 'state')
  const target = join(root, 'target')
  let children = []
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), 'unsafe(input)\n')
    children = await startChildren([stateDir, target, 'create'], 5)
    const results = await runChildren(children)
    const index = JSON.parse(await readFile(join(stateDir, 'index.json'), 'utf8'))
    assert.equal(Object.keys(index.scans).length, 5)
    for (const result of results) assert.ok(index.scans[result.scanId], result.scanId)
  } finally { for (const child of children) if (child.exitCode === null) child.kill(); await rm(root, { recursive: true, force: true }) }
})

test('concurrent processes retain all updates to one scan', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-scan-race-')))
  const stateDir = join(root, 'state')
  const target = join(root, 'target')
  let children = []
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), 'unsafe(input)\n')
    const service = new SecurityService({}, { config: { stateDir } })
    const scan = await service.startScan({ targetPath: target }, 'standard')
    children = await startChildren([stateDir, target, scan.scanId], 6)
    await runChildren(children)
    assert.equal((await service.listCandidates({ scanId: scan.scanId })).total, 6)
  } finally { for (const child of children) if (child.exitCode === null) child.kill(); await rm(root, { recursive: true, force: true }) }
})

test('a failed lock release does not strand later mutations in the local queue', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-lock-release-')))
  const target = join(root, 'target')
  const originalExec = DatabaseSync.prototype.exec
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), 'const value = 1\n')
    const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
    const scan = await service.startScan({ targetPath: target }, 'standard')
    let rollbacks = 0
    DatabaseSync.prototype.exec = function (sql) {
      if (sql === 'ROLLBACK' && ++rollbacks === 2) throw new Error('simulated lock release failure')
      return originalExec.call(this, sql)
    }
    await assert.rejects(service.updateScanProgress({ scanId: scan.scanId, note: 'first' }), /simulated lock release failure/)
    DatabaseSync.prototype.exec = originalExec
    const result = await Promise.race([
      service.updateScanProgress({ scanId: scan.scanId, note: 'second' }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('scan queue remained locked')), 1000)),
    ])
    assert.equal(result.ok, true)
  } finally {
    DatabaseSync.prototype.exec = originalExec
    await rm(root, { recursive: true, force: true })
  }
})
