import test from 'node:test'
import assert from 'node:assert/strict'
import { fork } from 'node:child_process'
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SecurityService } from '../lib/service.js'

const fixturePath = fileURLToPath(new URL('./fixtures/deep-coordinator-process.mjs', import.meta.url))

function child(args) {
  const process = fork(fixturePath, args, { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
  const messages = []
  process.on('message', (message) => messages.push(message))
  const exited = new Promise((resolve) => process.once('exit', (code, signal) => resolve({ code, signal })))
  async function message(type) {
    const until = Date.now() + 15000
    while (Date.now() < until) {
      const value = messages.find((item) => item.type === type || item.type === 'error')
      if (value) return value
      await new Promise((resolve) => setTimeout(resolve, 20))
    }
    throw new Error('child did not report ' + type)
  }
  return { process, messages, exited, message }
}

test('one live owner, then authenticated takeover after process death, preserves the attempt budget', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-recovery-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['start', state, target])
  let competing
  let resumed
  try {
    const started = await first.message('started')
    assert.equal(started.type, 'started')
    assert.equal((await first.message('worker')).type, 'worker')
    const journalPath = join(state, 'deep', started.scanId + '.json')
    assert.ok(!(await readFile(journalPath, 'utf8')).includes(started.recoveryClaim))
    competing = child(['resume', state, target, started.scanId, started.recoveryClaim, 'other'])
    const rejection = await competing.message('done')
    assert.equal(rejection.type, 'error')
    assert.match(rejection.error, /state lock/i)
    await competing.exited
    first.process.kill('SIGKILL')
    await first.exited
    resumed = child(['resume', state, target, started.scanId, started.recoveryClaim, 'other'])
    const result = await resumed.message('done')
    assert.equal(result.type, 'done', result.error)
    assert.equal(result.status, 'completed')
    await resumed.exited
    const journal = JSON.parse(await readFile(journalPath, 'utf8'))
    assert.equal(journal.runs.length, 2)
    assert.equal(journal.runs[0].state, 'abandoned')
    assert.equal(journal.runs[1].state, 'processed')
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (competing?.process.exitCode === null && competing?.process.signalCode === null) { competing.process.kill('SIGKILL'); await competing.exited }
    if (resumed?.process.exitCode === null && resumed?.process.signalCode === null) { resumed.process.kill('SIGKILL'); await resumed.exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('an expired persisted deadline prevents new workers after takeover', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-expired-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['start', state, target])
  let resumed
  try {
    const started = await first.message('started')
    await first.message('worker')
    first.process.kill('SIGKILL')
    await first.exited
    const journalPath = join(state, 'deep', started.scanId + '.json')
    const journal = JSON.parse(await readFile(journalPath, 'utf8'))
    journal.deadline = Date.now() - 1
    await writeFile(journalPath, JSON.stringify(journal))
    resumed = child(['resume', state, target, started.scanId, started.recoveryClaim, 'other'])
    const result = await resumed.message('done')
    assert.equal(result.type, 'done', result.error)
    assert.equal(result.status, 'failed')
    await resumed.exited
    assert.equal(resumed.messages.filter((message) => message.type === 'worker').length, 0)
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (resumed?.process.exitCode === null && resumed?.process.signalCode === null) { resumed.process.kill('SIGKILL'); await resumed.exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('a crash before claim delivery can be recovered only by the original session', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-initializing-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['initializing', state, target])
  let unauthorized
  let owner
  try {
    const pending = await first.message('initializing')
    const journal = JSON.parse(await readFile(join(state, 'deep', pending.scanId + '.json'), 'utf8'))
    assert.equal(journal.status, 'initializing')
    first.process.kill('SIGKILL')
    await first.exited
    unauthorized = child(['resume', state, target, pending.scanId, '', 'other'])
    assert.match((await unauthorized.message('done')).error, /recovery claim/i)
    await unauthorized.exited
    owner = child(['resume', state, target, pending.scanId, '', 'owner'])
    const result = await owner.message('done')
    assert.equal(result.type, 'done', result.error)
    assert.equal(result.status, 'completed')
    await owner.exited
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (unauthorized?.process.exitCode === null && unauthorized?.process.signalCode === null) { unauthorized.process.kill('SIGKILL'); await unauthorized.exited }
    if (owner?.process.exitCode === null && owner?.process.signalCode === null) { owner.process.kill('SIGKILL'); await owner.exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('an authenticated process can cancel a worker owned by another live process', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-cancel-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['start', state, target])
  let canceler
  try {
    const started = await first.message('started')
    await first.message('worker')
    canceler = child(['cancel', state, target, started.scanId, started.recoveryClaim, 'other'])
    assert.equal((await canceler.message('done')).status, 'cancel_requested')
    await canceler.exited
    const outcome = await first.message('done')
    assert.equal(outcome.status, 'canceled')
    await first.exited
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (canceler?.process.exitCode === null && canceler?.process.signalCode === null) { canceler.process.kill('SIGKILL'); await canceler.exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('recovery applies the no-new stop threshold before launching another worker', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-no-new-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['start', state, target])
  let resumed
  try {
    const started = await first.message('started')
    await first.message('worker')
    first.process.kill('SIGKILL')
    await first.exited
    const path = join(state, 'deep', started.scanId + '.json')
    const journal = JSON.parse(await readFile(path, 'utf8'))
    journal.budget.stopAfterNoNew = 1
    journal.runs[0].state = 'result'
    journal.runs[0].receipts = ['app.js']
    journal.runs[0].draft = { findings: [], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'no_issue_found' }] } }
    await writeFile(path, JSON.stringify(journal))
    resumed = child(['resume', state, target, started.scanId, started.recoveryClaim, 'other'])
    const result = await resumed.message('done')
    assert.equal(result.status, 'completed', result.error)
    await resumed.exited
    assert.equal(resumed.messages.filter((message) => message.type === 'worker').length, 0)
    assert.equal(JSON.parse(await readFile(path, 'utf8')).runs.length, 1)
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (resumed?.process.exitCode === null && resumed?.process.signalCode === null) { resumed.process.kill('SIGKILL'); await resumed.exited }
    await rm(root, { recursive: true, force: true })
  }
})

test('cancel after a crash also terminates an unfinished managed child scan', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-child-cancel-')))
  const target = join(root, 'target')
  const state = join(root, 'state')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const first = child(['pause-seal', state, target])
  let canceler
  try {
    const started = await first.message('started')
    const childScan = await first.message('child-seal')
    first.process.kill('SIGKILL')
    await first.exited
    canceler = child(['cancel', state, target, started.scanId, started.recoveryClaim, 'other'])
    assert.equal((await canceler.message('done')).status, 'cancel_requested')
    await canceler.exited
    const service = new SecurityService({}, { config: { stateDir: state } })
    assert.equal((await service.getScanContext({ scanId: started.scanId })).scan.status, 'canceled')
    assert.equal((await service.getScanContext({ scanId: childScan.childScanId })).scan.status, 'canceled')
  } finally {
    if (first.process.exitCode === null && first.process.signalCode === null) { first.process.kill('SIGKILL'); await first.exited }
    if (canceler?.process.exitCode === null && canceler?.process.signalCode === null) { canceler.process.kill('SIGKILL'); await canceler.exited }
    await rm(root, { recursive: true, force: true })
  }
})
