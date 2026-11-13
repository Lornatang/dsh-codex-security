import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import { SecurityService } from '../lib/service.js'
import { resolveTarget } from '../lib/target.js'
import { createSecurityTools } from '../lib/tools.js'
import { ScanStore } from '../lib/store.js'
import { TOOL_NAMES, VERSION } from '../lib/constants.js'

const options = { maxFiles: 100, maxFileBytes: 1024 }
const draft = (findings = [], complete = true, surfaces = [{ label: 'source', disposition: 'no_issue_found' }]) => ({
  complete, findings, reviewState: { surfaces, explicitExclusions: [], deferred: [] },
})
const finding = {
  ruleId: 'demo/injection', title: 'Injection', summary: 'Untrusted input reaches a sink.',
  severity: { level: 'high' }, confidence: { level: 'high', rationale: 'Source and sink are visible.' },
  taxonomy: { category: 'injection', cwe: 'CWE-89' },
  locations: [{ path: 'src/app.js', startLine: 1 }], remediation: 'Validate the input.',
}

async function fixture(git = false) {
  const temp = await mkdtemp(join(tmpdir(), 'dcs-regression-'))
  const target = join(temp, 'target')
  await mkdir(join(target, 'src'), { recursive: true })
  await mkdir(join(target, 'other'), { recursive: true })
  await writeFile(join(target, 'src', 'app.js'), 'unsafe(input)\n')
  await writeFile(join(target, 'other', 'other.js'), 'const x = 1\n')
  const runGit = (...args) => execFileSync('git', args, { cwd: target, stdio: 'ignore' })
  if (git) {
    runGit('init', '-q')
    runGit('add', '.')
    runGit('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'initial')
  }
  const service = new SecurityService({}, { config: { stateDir: join(temp, 'state') } })
  return { temp, target, service, runGit, cleanup: () => rm(temp, { recursive: true, force: true }) }
}

test('target scope is preserved and snapshot digests change with file contents', async () => {
  const f = await fixture(true)
  const directory = await fixture(false)
  try {
    const scoped = await resolveTarget({ ...options, targetPath: join(f.target, 'src') })
    assert.deepEqual(scoped.scope.includePaths, ['src'])
    assert.deepEqual(scoped.files, ['src/app.js'])
    await assert.rejects(resolveTarget({ ...options, targetPath: join(f.target, 'src'), includePaths: ['other'] }), /within targetPath/)
    const localScope = await resolveTarget({ ...options, targetPath: directory.target, includePaths: ['src'] })
    assert.deepEqual(localScope.files, ['src/app.js'])
    const missing = join(f.temp, 'missing')
    await assert.rejects(resolveTarget({ ...options, targetPath: missing }), /existing directory/)
    assert.equal(await access(missing).then(() => true, () => false), false)

    await writeFile(join(f.target, 'src', 'app.js'), 'unsafe(value)\n')
    const gitBefore = await resolveTarget({ ...options, targetPath: f.target })
    await writeFile(join(f.target, 'src', 'app.js'), 'unsafe(other)\n')
    const gitAfter = await resolveTarget({ ...options, targetPath: f.target })
    assert.equal(gitBefore.target.dirty, true)
    assert.notEqual(gitBefore.target.snapshotDigest, gitAfter.target.snapshotDigest)

    const before = await resolveTarget({ ...options, targetPath: directory.target })
    await writeFile(join(directory.target, 'src', 'app.js'), 'unsafe(value)\n')
    const after = await resolveTarget({ ...options, targetPath: directory.target })
    assert.notEqual(before.target.snapshotDigest, after.target.snapshotDigest)
  } finally { await f.cleanup(); await directory.cleanup() }
})

test('diff scan binds all changed and untracked files and requires dispositions', async () => {
  const f = await fixture(true)
  try {
    await writeFile(join(f.target, 'src', 'app.js'), 'unsafe(changed)\n')
    await writeFile(join(f.target, 'src', 'new.js'), 'newFile()\n')
    const tools = createSecurityTools(f.service)
    const start = tools.find((tool) => tool.name === 'codex_security_start_standard_scan')
    assert.ok(start.parameters.properties.workingTree)
    const started = await start.execute({ targetPath: f.target, workingTree: true })
    assert.equal(started.scan.target.kind, 'git_diff')
    assert.equal(started.skill, 'security-diff-scan')
    assert.deepEqual(started.scan.diffFiles.map((item) => item.path).sort(), ['src/app.js', 'src/new.js'])
    const items = await f.service.prepareReviewItems({ scanId: started.scanId })
    assert.equal(items.total, 2)
    await f.service.recordScanDraft({ scanId: started.scanId, ...draft() })
    await assert.rejects(f.service.completeScan({ scanId: started.scanId }), /every bound diff file/)
    await writeFile(join(f.target, 'src', 'later.js'), 'not in bound snapshot\n')
    assert.equal((await f.service.prepareReviewItems({ scanId: started.scanId })).total, 2)
    for (const item of items.items) {
      await f.service.updateReviewItem({ scanId: started.scanId, reviewId: item.reviewId, status: 'reviewed', note: 'Reviewed.' })
    }
    await assert.rejects(f.service.completeScan({ scanId: started.scanId }), /target changed/)
    await rm(join(f.target, 'src', 'later.js'))
    const completed = await f.service.completeScan({ scanId: started.scanId })
    assert.equal(completed.status, 'completed')
    await assert.rejects(f.service.updateReviewItem({ scanId: started.scanId, path: 'src/app.js', status: 'reviewed' }), /cannot be modified/)
  } finally { await f.cleanup() }
})

test('incomplete coverage cannot be sealed or reported as a successful comparison', async () => {
  const f = await fixture()
  try {
    const base = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: base.scanId, ...draft([finding], false) })
    await assert.rejects(f.service.completeScan({ scanId: base.scanId }), /draft is incomplete/)
    await f.service.recordScanDraft({ scanId: base.scanId, ...draft([], true, []) })
    await assert.rejects(f.service.completeScan({ scanId: base.scanId }), /coverage surface/)
    await f.service.recordScanDraft({ scanId: base.scanId, ...draft([finding]) })
    await f.service.completeScan({ scanId: base.scanId })
    const head = await f.service.startScan({ targetPath: f.target }, 'standard')
    await assert.rejects(f.service.compareScans({ baseScanId: base.scanId, headScanId: head.scanId }), /both scans must be completed/)
    await f.service.recordScanDraft({ scanId: head.scanId, ...draft() })
    await f.service.completeScan({ scanId: head.scanId })
    const result = await f.service.compareScans({ baseScanId: base.scanId, headScanId: head.scanId })
    assert.equal(result.counts.closed, 1)
    const different = await f.service.startScan({ targetPath: f.target, includePaths: ['src'] }, 'standard')
    await f.service.recordScanDraft({ scanId: different.scanId, ...draft() })
    await f.service.completeScan({ scanId: different.scanId })
    await assert.rejects(f.service.compareScans({ baseScanId: base.scanId, headScanId: different.scanId }), /incompatible/)
  } finally { await f.cleanup() }
})

test('sealed evidence remains unchanged and output documents satisfy their schemas', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.saveArtifact({ scanId: scan.scanId, path: 'artifacts/evidence.txt', content: 'original' })
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft([finding]) })
    const complete = await f.service.completeScan({ scanId: scan.scanId })
    const scanDir = dirname(complete.reportPath)
    const manifest = JSON.parse(await readFile(complete.manifestPath, 'utf8'))
    const record = manifest.scan.artifacts.find((item) => item.path === 'artifacts/evidence.txt')
    await assert.rejects(f.service.saveArtifact({ scanId: scan.scanId, path: 'artifacts/evidence.txt', content: 'changed' }), /cannot change artifacts/)
    await assert.rejects(f.service.recordScanDraft({ scanId: scan.scanId, ...draft() }), /cannot be modified/)
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(scanDir, 'findings.json') }), /scan storage/)
    const hash = createHash('sha256').update(await readFile(join(scanDir, record.path))).digest('hex')
    assert.equal(hash, record.sha256)

    const ajv = new Ajv2020({ allErrors: true, strict: false })
    addFormats(ajv)
    for (const [kind, file] of [['findings', complete.findingsPath], ['coverage', complete.coveragePath], ['scan-manifest', complete.manifestPath]]) {
      const schema = JSON.parse(await readFile(new URL('../schemas/' + kind + '.schema.json', import.meta.url)))
      const validate = ajv.compile(schema)
      assert.equal(validate(JSON.parse(await readFile(file, 'utf8'))), true, JSON.stringify(validate.errors))
    }
  } finally { await f.cleanup() }
})

test('concurrent candidate updates are retained and a missing index is rebuilt on list', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'deep')
    const calls = Array.from({ length: 12 }, (_, i) => f.service.recordDiscoveryCandidates({
      scanId: scan.scanId, candidates: [{ ruleId: 'demo/rule', title: 'Candidate ' + i, severity: 'high', path: 'src/app.js', anchor: 'anchor-' + i }],
    }))
    const results = await Promise.all(calls)
    assert.equal(results.reduce((sum, result) => sum + result.added, 0), 12)
    assert.equal((await f.service.listCandidates({ scanId: scan.scanId })).total, 12)
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    await assert.rejects(f.service.completeScan({ scanId: scan.scanId }), /candidates need a final disposition/)
    await rm(join(f.temp, 'state', 'index.json'))
    const reopened = new ScanStore(join(f.temp, 'state'))
    assert.equal((await reopened.list()).length, 1)
  } finally { await f.cleanup() }
})

test('explicitly deferred candidates remain visible and cannot produce a clean comparison', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    const recorded = await f.service.recordDiscoveryCandidates({ scanId: scan.scanId, candidates: [{ ruleId: 'demo/rule', title: 'Needs review', severity: 'high', path: 'src/app.js' }] })
    const candidateId = recorded.candidates[0].candidateId
    await f.service.recordCandidateValidations({ scanId: scan.scanId, validations: [{ candidateId, status: 'deferred', summary: 'Missing evidence.' }] })
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    await assert.rejects(f.service.completeScan({ scanId: scan.scanId }), /candidates need a final disposition/)
    await f.service.recordScanDraft({ scanId: scan.scanId, findings: [], complete: true, reviewState: {
      surfaces: [{ label: 'source', disposition: 'needs_follow_up' }], deferred: [{ id: candidateId, reason: 'Missing evidence.' }],
    } })
    await f.service.completeScan({ scanId: scan.scanId })
    await assert.rejects(f.service.compareScans({ baseScanId: scan.scanId, headScanId: scan.scanId }), /comparable coverage/)
  } finally { await f.cleanup() }
})

test('a concurrent save cannot mutate a scan once completion has acquired its lock', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    const [completion, save] = await Promise.allSettled([
      f.service.completeScan({ scanId: scan.scanId }),
      f.service.saveArtifact({ scanId: scan.scanId, path: 'artifacts/late.txt', content: 'late' }),
    ])
    assert.equal(completion.status, 'fulfilled')
    assert.equal(save.status, 'rejected')
    assert.match(save.reason.message, /cannot change artifacts/)
  } finally { await f.cleanup() }
})

test('generic start tool uses the configured default mode', async () => {
  const f = await fixture()
  try {
    const service = new SecurityService({}, { config: { stateDir: join(f.temp, 'other-state'), defaultMode: 'deep' } })
    const start = createSecurityTools(service).find((tool) => tool.name === 'codex_security_start_scan')
    const scan = await start.execute({ targetPath: f.target })
    assert.equal(scan.scan.mode, 'deep')
    const explicit = await start.execute({ targetPath: f.target, mode: 'prompt-only' })
    assert.equal(explicit.scan.mode, 'prompt-only')
  } finally { await f.cleanup() }
})

test('published documentation tracks the registered tool surface', async () => {
  const root = new URL('../', import.meta.url)
  const docs = await readFile(new URL('docs/TOOLS.md', root), 'utf8')
  const documented = [...docs.matchAll(/^### `(codex_security_[a-z_]+)`$/gm)].map((match) => match[1]).sort()
  assert.deepEqual(documented, [...TOOL_NAMES].sort())
  const pkg = JSON.parse(await readFile(new URL('package.json', root), 'utf8'))
  assert.equal(pkg.version, VERSION)
  assert.ok(pkg.files.includes('docs'))
  assert.ok(pkg.files.includes('examples'))
  assert.equal(pkg.files.includes('README.zh.md'), false)
  await assert.rejects(access(new URL('README.zh.md', root)))
})
