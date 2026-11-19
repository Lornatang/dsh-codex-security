import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { SecurityService } from '../lib/service.js'

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'dcs-review-coverage-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const target = join(root, 'source')
  await mkdir(target)
  await writeFile(join(target, 'settings.txt'), 'theme = light\npolicy = retain\n')
  await writeFile(join(target, 'excluded.txt'), 'policy = ignore\n')
  const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
  const { scan } = await service.startScan({ targetPath: target, includePaths: ['settings.txt'] }, 'standard')
  return { service, scan, target }
}

const excerpt = 'policy = retain'
const citation = { path: 'settings.txt', startLine: 2, endLine: 2, excerpt }
const surface = {
  id: 'retention', label: 'Configuration', invariant: 'The retention setting is explicit.', disposition: 'no_issue_found',
  notes: 'The setting is explicitly retained.', sourceEvidence: [citation],
}

async function record(service, scan, surfaces, metadata = {}) {
  return service.recordScanDraft({ scanId: scan.scanId, complete: true, findings: [], reviewState: { ...metadata, surfaces } })
}

test('a focused unit displays only host-verified source references and legacy delivery stays unknown', async (t) => {
  const { service, scan } = await fixture(t)
  await record(service, scan, [surface, { id: 'legacy', label: 'Older surface', disposition: 'no_issue_found',
    sourceEvidenceVerified: true }], { sourceDelivery: { deliveredFiles: 1, eligibleFiles: 1 } })
  const completed = await service.completeScan({ scanId: scan.scanId })
  const coverage = JSON.parse(await readFile(completed.coveragePath, 'utf8'))
  assert.deepEqual(coverage.surfaces[0].sourceEvidence, [{
    path: 'settings.txt', startLine: 2, endLine: 2, excerptSha256: createHash('sha256').update(excerpt).digest('hex'),
  }])
  assert.equal(coverage.surfaces[1].sourceEvidence, undefined)
  assert.equal(coverage.surfaces[1].sourceEvidenceVerified, undefined)
  assert.equal(coverage.sourceDelivery, undefined)
  const report = await readFile(completed.reportPath, 'utf8')
  assert.match(report, /Files enumerated \| 1/)
  assert.match(report, /Files delivered to contributing workers \| unavailable/)
  assert.match(report, /Unit records with verified source and a disposition \| 1/)
  assert.match(report, /settings\.txt:2/)
})

test('a completed unit needs exact in-scope evidence, while an explicit gap can stay open', async (t) => {
  const { service, scan } = await fixture(t)
  for (const ref of [{ ...citation, excerpt: 'policy' }, { path: 'excluded.txt', startLine: 1, endLine: 1, excerpt: 'policy = ignore' }]) {
    await record(service, scan, [{ ...surface, sourceEvidence: [ref] }])
    await assert.rejects(service.completeScan({ scanId: scan.scanId }), /coverage source evidence/)
  }
  await assert.rejects(record(service, scan, [{ ...surface, sourceEvidence: [] }]), /requires source evidence/)
  await record(service, scan, [{ ...surface, disposition: 'needs_follow_up', sourceEvidence: [], notes: 'Deployment selection is unknown.' }])
  const completed = await service.completeScan({ scanId: scan.scanId })
  const coverage = JSON.parse(await readFile(completed.coveragePath, 'utf8'))
  assert.equal(coverage.completeness, 'partial')
})

test('a revision diff checks unit evidence against committed lines', async (t) => {
  const { service, target } = await fixture(t)
  const git = (...args) => execFileSync('git', ['-C', target, ...args], { stdio: 'pipe' })
  const commit = (message) => {
    git('add', 'settings.txt')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', message)
  }
  git('init', '-q')
  commit('base')
  const file = join(target, 'settings.txt')
  await writeFile(file, 'theme = dark\npolicy = retain\n')
  commit('head')
  const { scan } = await service.startScan({ targetPath: target, diffTarget: 'HEAD^' }, 'standard')
  await service.prepareReviewItems({ scanId: scan.scanId })
  await service.updateReviewItem({ scanId: scan.scanId, path: 'settings.txt', status: 'reviewed' })
  await writeFile(file, 'theme = local\npolicy = retain\n')
  const cited = excerpt => ({ ...surface, sourceEvidence: [{ ...citation, startLine: 1, endLine: 1, excerpt }] })
  await record(service, scan, [cited('theme = local')])
  await assert.rejects(service.completeScan({ scanId: scan.scanId }), /does not match the bound source/)
  await record(service, scan, [cited('theme = dark')])
  git('rm', '--cached', '-q', 'settings.txt')
  await rm(file)
  assert.equal((await service.completeScan({ scanId: scan.scanId })).status, 'completed')
})

test('pre-upgrade draft extensions do not become verified source or prevent sealing', async (t) => {
  const { service, scan } = await fixture(t)
  const legacy = { id: 'legacy', label: 'Legacy source note', disposition: 'no_issue_found' }
  await record(service, scan, [legacy])
  const { dir } = await service.store.get(scan.scanId)
  const checkpoint = join(dir, 'checkpoints', 'scan-draft.json')
  const draft = JSON.parse(await readFile(checkpoint, 'utf8'))
  Object.assign(draft.input.reviewState.surfaces[0], { sourceEvidence: 'Historical free text', invariant: { id: 'old-extension' } })
  await writeFile(checkpoint, JSON.stringify(draft))
  const completed = await service.completeScan({ scanId: scan.scanId })
  const coverage = JSON.parse(await readFile(completed.coveragePath, 'utf8'))
  assert.deepEqual(coverage.surfaces, [{ ...legacy, receiptRefs: [] }])
})
