import test from 'node:test'
import assert from 'node:assert/strict'
import { access, mkdtemp, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { SecurityService } from '../lib/service.js'
import { WorkerRegistry } from '../lib/deep-worker.js'
import { DeepCoordinator, readDeepStatus } from '../lib/deep-coordinator.js'
import { createSecurityTools } from '../lib/tools.js'
import { acquireStateLock } from '../lib/state-lock.js'

async function fixture(behavior = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-coordinator-')))
  const target = join(root, 'target')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\nconst value = 1\n')
  const service = new SecurityService({}, { config: { stateDir: join(root, 'state'), ...(behavior.maxFileBytes ? { maxFileBytes: behavior.maxFileBytes } : {}) } })
  const registry = new WorkerRegistry()
  const stats = { started: 0, active: 0, peak: 0 }
  const host = {
    async ensureReady() {},
    async start({ childId, signal }) {
      stats.started++
      const run = stats.started
      stats.active++
      stats.peak = Math.max(stats.peak, stats.active)
      const result = (async () => {
        try {
          if (behavior.waitForWorker) await behavior.waitForWorker(run)
          else await new Promise((resolve, reject) => {
            const timer = setTimeout(resolve, behavior.delay ?? 30)
            signal.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason) }, { once: true })
          })
          if (!(typeof behavior.skipReads === 'function' ? behavior.skipReads(run) : behavior.skipReads)) for (const path of registry.list(childId)) {
            const content = await registry.read(childId, path)
            registry.acceptRead(childId, path, content)
          }
          const draft = (typeof behavior.result === 'function' ? behavior.result(run) : behavior.result) ?? {
            findings: [], reviewState: { completeness: 'complete', surfaces: [{ label: 'All source', disposition: 'no_issue_found' }] },
          }
          return { stopReason: 'completed', structured: { draftJson: JSON.stringify(draft) } }
        } finally { stats.active-- }
      })()
      return { childId, result, dispose: async () => {} }
    },
  }
  const coordinator = new DeepCoordinator(service, registry, host)
  return { root, target, service, registry, coordinator, stats, cleanup: () => rm(root, { recursive: true, force: true }) }
}

test('automatic Deep bounds parallelism and attempts, then seals independently complete reviews', { timeout: 60000 }, async () => {
  const secondWorker = Promise.withResolvers()
  const f = await fixture({ waitForWorker: (run) => {
    if (run === 2) secondWorker.resolve()
    if (run === 1) return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Second worker did not start')), 15000)
      void secondWorker.promise.then(() => { clearTimeout(timer); resolve() })
    })
  } })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 2, maxDiscoveryRuns: 3, stopAfterNoNew: 20 }, { agent: { id: 'owner' } })
    assert.match(started.recoveryClaim, /^[a-f0-9]{64}$/)
    await f.coordinator.wait(started.scanId)
    const parent = (await f.service.getScanContext({ scanId: started.scanId })).scan
    assert.equal(parent.status, 'completed')
    assert.equal(f.stats.started, 3)
    assert.equal(f.stats.peak, 2)
    assert.equal(parent.findingsCount, 0)
    assert.equal(parent.progress.discoveryRuns, 3)
    const coverage = await f.service.store.readScanFile(started.scanId, 'coverage.json')
    assert.deepEqual(coverage.sourceDelivery, { deliveredFiles: 1, eligibleFiles: 1 })
    assert.equal(coverage.surfaces.filter(surface => surface.sourceEvidence?.length).length, 0)
    if (process.env.CODEX_SECURITY_REFERENCE_ROOT) {
      const validator = join(process.env.CODEX_SECURITY_REFERENCE_ROOT, 'scripts', 'validate_scan_contract.py')
      const directory = (await f.service.store.get(started.scanId)).dir
      const result = execFileSync('python', [validator, '--scan-dir', directory], { encoding: 'utf8' })
      assert.equal(JSON.parse(result).status, 'valid')
    }
  } finally {
    secondWorker.resolve()
    await f.coordinator.dispose()
    await f.cleanup()
  }
})

test('zero findings without a complete worker read receipt fails closed', async () => {
  const f = await fixture({ skipReads: true })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const parent = (await f.service.getScanContext({ scanId: started.scanId })).scan
    assert.equal(parent.status, 'failed')
    assert.match(parent.error, /complete|receipt|review/i)
  } finally { await f.cleanup() }
})

test('Deep retains sealed unit evidence and requires delivery to the claiming worker', async () => {
  const draft = { findings: [], reviewState: { completeness: 'complete', surfaces: [{
    id: 'constant-value', label: 'Fixture value', invariant: 'The value is declared as a constant.',
    disposition: 'no_issue_found', notes: 'The declaration uses const.',
    sourceEvidence: [{ path: 'app.js', startLine: 1, endLine: 1, excerpt: 'const value = 1' }],
  }] } }
  const f = await fixture({ result: draft, skipReads: run => run === 1 })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const parent = (await f.service.getScanContext({ scanId: started.scanId })).scan
    assert.equal(parent.status, 'completed')
    const coverage = await f.service.store.readScanFile(started.scanId, 'coverage.json')
    assert.equal(coverage.completeness, 'partial')
    assert.deepEqual(coverage.sourceDelivery, { deliveredFiles: 1, eligibleFiles: 1 })
    assert.deepEqual(coverage.surfaces.map(surface => surface.id), ['worker-2-constant-value'])
    assert.equal(coverage.surfaces[0].invariant, draft.reviewState.surfaces[0].invariant)
    const [ref] = coverage.surfaces[0].sourceEvidence
    assert.equal(ref.path, 'app.js')
    assert.match(ref.excerptSha256, /^[a-f0-9]{64}$/)
    assert.equal(ref.excerpt, undefined)
  } finally { await f.coordinator.dispose(); await f.cleanup() }
})

test('malformed worker output cannot produce a clean scan', async () => {
  const f = await fixture({ result: { findings: 'not an array' } })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const parent = (await f.service.getScanContext({ scanId: started.scanId })).scan
    assert.equal(parent.status, 'failed')
  } finally { await f.cleanup() }
})

test('no-new budget stops new launches while accounting for workers already running', async () => {
  const f = await fixture()
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 2, maxDiscoveryRuns: 8, stopAfterNoNew: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    assert.equal(f.stats.started, 2)
    assert.equal((await f.service.getScanContext({ scanId: started.scanId })).scan.status, 'completed')
  } finally { await f.cleanup() }
})

test('a partial worker with no findings does not consume the no-new stopping threshold', async () => {
  const f = await fixture({ skipReads: (run) => run === 1 })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2, stopAfterNoNew: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    assert.equal(f.stats.started, 2)
    assert.equal((await f.service.getScanContext({ scanId: started.scanId })).scan.status, 'completed')
  } finally { await f.cleanup() }
})

test('only the owner or a holder of the recovery claim can cancel a running campaign', async () => {
  const f = await fixture({ delay: 10000 })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2 }, { agent: { id: 'owner' } })
    await assert.rejects(f.coordinator.cancel({ scanId: started.scanId }, { agent: { id: 'other' } }), /claim/i)
    await f.coordinator.cancel({ scanId: started.scanId, recoveryClaim: started.recoveryClaim }, { agent: { id: 'other' } })
    await f.coordinator.wait(started.scanId)
    await assert.rejects(readDeepStatus(f.service, started.scanId, { agent: { id: 'other' } }), /claim/i)
    assert.equal((await readDeepStatus(f.service, started.scanId, { agent: { id: 'owner' } })).status, 'canceled')
    assert.equal(f.stats.active, 0)
  } finally { await f.cleanup() }
})

test('host disposal leaves an interrupted campaign resumable', async () => {
  const f = await fixture({ delay: 10000 })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2 }, { agent: { id: 'owner' } })
    while (!f.stats.active) await new Promise((resolve) => setTimeout(resolve, 10))
    await f.coordinator.dispose()
    assert.equal((await f.service.getScanContext({ scanId: started.scanId })).scan.status, 'running')
    assert.equal(f.stats.active, 0)
  } finally { await f.cleanup() }
})

test('budgets reject non-integer and non-finite values before creating a scan', async () => {
  const f = await fixture()
  try {
    for (const [key, value] of [['workers', 1.5], ['maxDiscoveryRuns', Infinity], ['stopAfterNoNew', 0], ['maxTimeMinutes', -1]]) {
      await assert.rejects(f.coordinator.start({ targetPath: f.target, [key]: value }, { agent: { id: 'owner' } }), /budget|integer|range/i)
    }
    assert.equal((await f.service.status()).scans, 0)
  } finally { await f.cleanup() }
})

test('same fingerprint at different source locations is retained as unresolved instead of silently merged', async () => {
  const f = await fixture({ result: (run) => ({ findings: [{
    ruleId: 'test/duplicate', title: 'Unsafe operation', summary: 'Source requires review.',
    severity: { level: 'high' }, confidence: { level: 'medium', rationale: 'Static analysis.' },
    identity: { anchor: 'same-anchor' }, locations: [{ path: 'app.js', startLine: run }], remediation: 'Review and correct the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }] } }) })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2, stopAfterNoNew: 4 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed')
    assert.equal(result.findings.length, 2)
    assert.equal(result.coverage.completeness, 'partial')
    assert.ok(result.coverage.deferred.some((entry) => entry.id === 'deep-identity-collision'))
  } finally { await f.cleanup() }
})

test('colliding top-level identities preserve both locations in partial coverage', async () => {
  const f = await fixture({ result: (run) => ({ findings: [{
    ruleId: 'test/duplicate', title: 'Unsafe operation', summary: 'Source requires review.', severity: { level: 'high' },
    confidence: { level: 'medium', rationale: 'Static analysis.' }, anchor: 'same-anchor', instance: 'same-instance',
    locations: [{ path: 'app.js', startLine: run }], remediation: 'Review the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }] } }) })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed', result.scan.error)
    assert.equal(result.findings.length, 2)
    assert.equal(result.coverage.completeness, 'partial')
  } finally { await f.cleanup() }
})

test('conflicting severities and evidence for the same identity cannot be silently downgraded', async () => {
  const f = await fixture({ result: (run) => ({ findings: [{
    ruleId: 'test/severity', title: 'Unsafe operation', summary: 'Source requires review.', severity: { level: run === 1 ? 'low' : 'critical' },
    confidence: { level: 'medium', rationale: 'Static analysis.' }, identity: { anchor: 'same-anchor' },
    locations: [{ path: 'app.js', startLine: 1 }], remediation: 'Review the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }] } }) })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 2 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed', result.scan.error)
    assert.equal(result.findings.length, 2)
    assert.equal(result.scan.policy.status, 'fail')
    assert.equal(result.coverage.completeness, 'partial')
  } finally { await f.cleanup() }
})

test('managed completed findings require the owner session or recovery claim for triage', async () => {
  const f = await fixture({ result: { findings: [{
    ruleId: 'test/triage', title: 'Candidate', summary: 'Static finding.', severity: { level: 'high' },
    confidence: { level: 'medium', rationale: 'Source evidence.' }, locations: [{ path: 'app.js', startLine: 1 }], remediation: 'Correct the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }] } } })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    const args = { scanId: started.scanId, findingId: result.findings[0].findingId, status: 'false_positive' }
    await assert.rejects(f.service.setFindingTriage(args), /managed|coordinator/i)
    const tool = createSecurityTools(f.service, () => f.coordinator).find((entry) => entry.name === 'codex_security_set_finding_triage')
    await assert.rejects(tool.execute(args, { agent: { id: 'other' } }), /claim/i)
    const accepted = await tool.execute({ ...args, recoveryClaim: started.recoveryClaim }, { agent: { id: 'other' } })
    assert.equal(accepted.triage.status, 'false_positive')
  } finally { await f.cleanup() }
})

test('source changes after binding cannot produce a sealed clean result', async () => {
  const f = await fixture({ delay: 100 })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    while (!f.stats.active) await new Promise((resolve) => setTimeout(resolve, 10))
    await writeFile(join(f.target, 'app.js'), 'const value = 2\n')
    await f.coordinator.wait(started.scanId)
    assert.equal((await f.service.getScanContext({ scanId: started.scanId })).scan.status, 'failed')
  } finally { await f.cleanup() }
})

test('replacing the bound target directory with identical content fails closed', async () => {
  const f = await fixture()
  const originalStart = f.service.startScan.bind(f.service)
  f.service.startScan = async (...args) => {
    const scan = await originalStart(...args)
    if (args[1] === 'deep' && args[2]?.managedParent) {
      await rename(f.target, join(f.root, 'original-target'))
      await mkdir(f.target)
      await writeFile(join(f.target, 'app.js'), 'const value = 1\nconst value = 1\n')
    }
    return scan
  }
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const scan = (await f.service.getScanContext({ scanId: started.scanId })).scan
    assert.equal(scan.status, 'failed')
    assert.match(scan.error, /directory|target.*changed/i)
    assert.equal(f.stats.started, 0)
  } finally { await f.cleanup() }
})

test('cancellation during startup does not leave an unowned running campaign', async () => {
  const f = await fixture()
  let unblock
  const gate = new Promise((resolve) => { unblock = resolve })
  const originalStart = f.service.startScan.bind(f.service)
  f.service.startScan = async (...args) => {
    await gate
    args[2].signal.throwIfAborted()
    return originalStart(...args)
  }
  try {
    const started = await f.coordinator.start({ targetPath: f.target }, { agent: { id: 'owner' } })
    const tool = createSecurityTools(f.service, () => f.coordinator).find((entry) => entry.name === 'codex_security_cancel_scan')
    await tool.execute({ scanId: started.scanId }, { agent: { id: 'owner' } })
    unblock()
    await f.coordinator.wait(started.scanId)
    const scans = await f.service.store.list()
    assert.equal(scans.length, 0)
    assert.equal((await readDeepStatus(f.service, started.scanId, { agent: { id: 'owner' } })).status, 'canceled')
    assert.equal(f.stats.started, 0)
  } finally { unblock(); await f.coordinator.dispose(); await f.cleanup() }
})

test('starting a Deep campaign returns its recovery claim before slow target binding', async () => {
  const f = await fixture()
  let unblock
  const gate = new Promise((resolve) => { unblock = resolve })
  const original = f.service.startScan.bind(f.service)
  f.service.startScan = async (...args) => { await gate; return original(...args) }
  const pending = f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
  try {
    const result = await Promise.race([pending.then((value) => ({ value })), new Promise((resolve) => setTimeout(() => resolve({ timeout: true }), 250))])
    assert.equal(result.timeout, undefined)
    assert.match(result.value.recoveryClaim, /^[a-f0-9]{64}$/)
  } finally {
    unblock()
    const started = await pending.catch(() => undefined)
    if (started) await f.coordinator.dispose()
    await f.cleanup()
  }
})

test('asynchronous initialization rejects a target directory replaced after start returns', async () => {
  const f = await fixture()
  let unblock
  const gate = new Promise((resolve) => { unblock = resolve })
  const original = f.service.startScan.bind(f.service)
  f.service.startScan = async (...args) => { await gate; return original(...args) }
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await rename(f.target, join(f.root, 'original-target'))
    await mkdir(f.target)
    await writeFile(join(f.target, 'app.js'), 'different()\n')
    unblock()
    await f.coordinator.wait(started.scanId)
    const status = await readDeepStatus(f.service, started.scanId, { agent: { id: 'owner' } })
    assert.equal(status.status, 'failed')
    assert.match(status.error, /target|directory.*changed/i)
    assert.equal(f.stats.started, 0)
  } finally { unblock(); await f.coordinator.dispose(); await f.cleanup() }
})

test('cancellation interrupts child target binding before a child scan can seal', async () => {
  const f = await fixture()
  let reached
  const entering = new Promise((resolve) => { reached = resolve })
  const original = f.service.startScan.bind(f.service)
  f.service.startScan = async (...args) => {
    if (args[1] === 'standard' && args[2]?.managedParent) {
      reached()
      await new Promise((resolve, reject) => {
        const signal = args[2].signal
        if (!signal) { setTimeout(resolve, 2000); return }
        if (signal.aborted) reject(signal.reason)
        else signal.addEventListener('abort', () => reject(signal.reason), { once: true })
      })
    }
    return original(...args)
  }
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await entering
    await f.coordinator.cancel({ scanId: started.scanId }, { agent: { id: 'owner' } })
    const elapsed = await Promise.race([f.coordinator.wait(started.scanId).then(() => 'done'), new Promise((resolve) => setTimeout(() => resolve('timeout'), 600))])
    assert.equal(elapsed, 'done')
    assert.equal((await readDeepStatus(f.service, started.scanId, { agent: { id: 'owner' } })).status, 'canceled')
  } finally { await f.coordinator.dispose(); await f.cleanup() }
})

test('a time limit after a child draft does not leave a managed running child', async () => {
  const f = await fixture()
  const original = f.service.recordScanDraft.bind(f.service)
  let parentId
  f.service.recordScanDraft = async (args, options) => {
    const result = await original(args, options)
    if (args.scanId !== parentId) f.coordinator.controllers.get(parentId).abort(new Error('wall-clock budget expired'))
    return result
  }
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    parentId = started.scanId
    await f.coordinator.wait(parentId)
    const scans = await f.service.store.list()
    assert.equal(scans.find((scan) => scan.scanId === parentId).status, 'failed')
    assert.equal(scans.find((scan) => scan.scanId !== parentId).status, 'failed')
  } finally { await f.cleanup() }
})

test('cancellation interrupts startup while another process holds the index lock', async () => {
  const f = await fixture()
  await f.service.store.init()
  const release = await acquireStateLock(join(f.service.store.stateDir, '.locks', 'index.sqlite'))
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await new Promise((resolve) => setTimeout(resolve, 150))
    await f.coordinator.cancel({ scanId: started.scanId }, { agent: { id: 'owner' } })
    const outcome = await Promise.race([f.coordinator.wait(started.scanId).then(() => 'done'), new Promise((resolve) => setTimeout(() => resolve('timeout'), 600))])
    assert.equal(outcome, 'done')
    assert.equal((await readDeepStatus(f.service, started.scanId, { agent: { id: 'owner' } })).status, 'canceled')
  } finally { release(); await f.coordinator.dispose(); await f.cleanup() }
})

test('oversized files remain deferred while verified findings from other files are preserved', async () => {
  const f = await fixture({ maxFileBytes: 1024, result: { findings: [{
    ruleId: 'test/small-file', title: 'Candidate', summary: 'Static finding.', severity: { level: 'high' },
    confidence: { level: 'medium', rationale: 'Source evidence.' }, locations: [{ path: 'other.js', startLine: 1 }], remediation: 'Correct the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }] } } })
  try {
    await writeFile(join(f.target, 'app.js'), 'a'.repeat(2048))
    await writeFile(join(f.target, 'other.js'), 'unsafe()\n')
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed', result.scan.error)
    assert.equal(result.findings.length, 1)
    assert.equal(result.coverage.completeness, 'partial')
    assert.ok(result.coverage.deferred.length)
  } finally { await f.cleanup() }
})

test('worker exclusions and unresolved questions remain visible in partial parent coverage', async () => {
  const f = await fixture({ result: { findings: [{
    ruleId: 'test/exclusion', title: 'Candidate', summary: 'Static finding.', severity: { level: 'high' },
    confidence: { level: 'medium', rationale: 'Source evidence.' }, locations: [{ path: 'app.js', startLine: 1 }], remediation: 'Correct the operation.',
  }], reviewState: { completeness: 'complete', surfaces: [{ label: 'source', disposition: 'reported' }],
    explicitExclusions: [{ pattern: 'app.js', reason: 'Part was not reviewed.' }], openQuestions: [{ question: 'Is the entry point reachable?' }] } } })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed', result.scan.error)
    assert.equal(result.coverage.completeness, 'partial')
    assert.equal(result.coverage.explicitExclusions[0].pattern, 'app.js')
    assert.equal(result.coverage.openQuestions[0].question, 'Is the entry point reachable?')
  } finally { await f.cleanup() }
})

test('parent coverage preserves worker surfaces and remaps deferred surface references', async () => {
  const f = await fixture({ result: { findings: [{
    ruleId: 'test/surface', title: 'Candidate', summary: 'Static finding.', severity: { level: 'high' },
    confidence: { level: 'medium', rationale: 'Source evidence.' }, locations: [{ path: 'app.js', startLine: 1 }], remediation: 'Correct the operation.',
  }], reviewState: { completeness: 'partial', surfaces: [{ id: 'auth', label: 'Authentication', disposition: 'needs_follow_up', notes: 'Token validation remains uncertain.' }],
    deferred: [{ id: 'auth-question', reason: 'Reachability is unresolved.', surfaceIds: ['auth'] }] } } })
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(started.scanId)
    const result = await f.service.getScan({ scanId: started.scanId })
    assert.equal(result.scan.status, 'completed', result.scan.error)
    const surface = result.coverage.surfaces.find((entry) => entry.label === 'Authentication')
    assert.equal(surface.notes, 'Token validation remains uncertain.')
    const deferred = result.coverage.deferred.find((entry) => entry.id.includes('auth-question'))
    assert.deepEqual(deferred.surfaceIds, [surface.id])
  } finally { await f.cleanup() }
})

test('a cancel request racing with an in-progress seal is never acknowledged and then ignored', async () => {
  const f = await fixture()
  const originalComplete = f.service.completeScan.bind(f.service)
  let cancellation
  f.service.completeScan = async (args) => {
    if (args.scanId === parentId) {
      cancellation = f.coordinator.cancel({ scanId: parentId }, { agent: { id: 'owner' } })
      void cancellation.catch(() => undefined)
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    return originalComplete(args)
  }
  let parentId
  try {
    const started = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    parentId = started.scanId
    await f.coordinator.wait(parentId)
    assert.ok(cancellation)
    const outcome = await cancellation.then((value) => ({ value }), (error) => ({ error }))
    const status = (await f.service.getScanContext({ scanId: parentId })).scan.status
    if (outcome.value) assert.equal(status, 'canceled')
    else { assert.equal(status, 'completed'); assert.match(outcome.error.message, /already|completed/i) }
  } finally { await f.cleanup() }
})

test('canceling while a child waits to publish its seal leaves no final documents', async () => {
  const f = await fixture()
  const complete = f.service.completeScan.bind(f.service)
  const update = f.service.store.update.bind(f.service.store)
  let sealing
  let release
  const publishing = Promise.withResolvers()
  f.service.completeScan = async (args, options) => {
    sealing = args.scanId
    try { return await complete(args, options) } finally { sealing = undefined }
  }
  f.service.store.update = async (scanId, mutate, options) => {
    if (scanId === sealing) {
      release = await acquireStateLock(join(f.service.store.stateDir, '.locks', 'index.sqlite'))
      publishing.resolve(scanId)
    }
    return update(scanId, mutate, options)
  }
  try {
    const { scanId } = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    const childId = await publishing.promise
    await f.coordinator.cancel({ scanId }, { agent: { id: 'owner' } })
    release()
    release = undefined
    await f.coordinator.wait(scanId)
    const child = await f.service.getScan({ scanId: childId })
    assert.equal(child.scan.status, 'canceled')
    assert.equal(child.manifest, null)
    const { dir } = await f.service.store.get(childId)
    await assert.rejects(access(join(dir, 'scan-manifest.json')), { code: 'ENOENT' })
    await assert.rejects(access(join(dir, 'report.md')), { code: 'ENOENT' })
  } finally {
    release?.()
    await f.coordinator.dispose()
    await f.cleanup()
  }
})

test('journal transitions avoid serializing historical run payloads', async () => {
  const f = await fixture()
  const processResult = f.coordinator.processResult.bind(f.coordinator)
  let serializations = 0
  f.coordinator.processResult = async (journal, run, controller) => {
    await processResult(journal, run, controller)
    if (run.number === 1) {
      Object.defineProperty(run.draft, 'toJSON', {
        value() { serializations++; return { ...this } },
      })
    }
  }
  try {
    const { scanId } = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 3 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(scanId)
    assert.equal((await f.service.getScan({ scanId })).scan.status, 'completed')
    assert.equal(serializations, 1)
  } finally { await f.cleanup() }
})


test('an interrupted terminal journal write cannot turn a sealed Deep result into failure', async () => {
  const f = await fixture()
  const save = f.coordinator.save.bind(f.coordinator)
  let statusDuringGap
  f.coordinator.save = async (journal) => {
    if (journal.status === 'completed' && statusDuringGap === undefined) {
      statusDuringGap = (await readDeepStatus(f.service, journal.scanId, { agent: { id: 'owner' } })).status
      throw new Error('journal temporarily unavailable')
    }
    return save(journal)
  }
  try {
    const { scanId } = await f.coordinator.start({ targetPath: f.target, workers: 1, maxDiscoveryRuns: 1 }, { agent: { id: 'owner' } })
    await f.coordinator.wait(scanId)
    assert.equal(statusDuringGap, 'completed')
    assert.equal((await f.service.getScan({ scanId })).manifest.status, 'completed')
    const journal = JSON.parse(await readFile(join(f.service.store.stateDir, 'deep', scanId + '.json'), 'utf8'))
    assert.equal(journal.status, 'completed')
    assert.equal(journal.error, undefined)
  } finally { await f.cleanup() }
})
