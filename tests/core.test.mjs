import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply, loadBundledSkills, SecurityService } from '../lib/index.js'
import { handleRequest } from '../lib/routes.js'
import { normalizeFinding, normalizeAnchor, policyGate, toSarif } from '../lib/contracts.js'
import { SKILL_NAMES, TOOL_NAMES } from '../lib/constants.js'
import { ScanStore } from '../lib/store.js'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function mockContext(patchPath) {
  const registeredTools = []
  const registeredSkills = []
  return {
    registeredTools,
    registeredSkills,
    profileContext: { patchPath },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    tools: { register(definition) { registeredTools.push(definition); return () => {} } },
    skills: { register(skill) { registeredSkills.push(skill); return () => {} } },
    get() { return undefined },
    on() { return () => {} },
    effect(setup) { const dispose = setup(); return () => { if (typeof dispose === 'function') dispose() } },
  }
}

async function tempDir(prefix) {
  return mkdtemp(join(tmpdir(), prefix))
}

async function makeTarget() {
  const root = await tempDir('dcs-target-')
  await mkdir(join(root, 'src'), { recursive: true })
  await writeFile(join(root, 'src', 'app.js'), [
    'export function handler(req) {',
    '  const id = req.query.id',
    '  return db.query(\`SELECT * FROM users WHERE id = \${id}\`)',
    '}',
    '',
  ].join('\n'))
  await writeFile(join(root, 'README.md'), '# demo target\n')
  return root
}

function sampleDraft(scanId, overrides = {}) {
  return {
    scanId,
    complete: true,
    findings: [
      {
        ruleId: 'injection/sql',
        title: 'SQL injection in handler',
        summary: 'The id query parameter is concatenated into a SQL statement, allowing an attacker to control query structure.',
        severity: { level: 'high', score: 8, rationale: 'Unauthenticated input reaches the query' },
        confidence: { level: 'high', rationale: 'Source and sink are both visible' },
        taxonomy: { category: 'injection', cwe: 'CWE-89' },
        locations: [{ path: 'src/app.js', startLine: 3, role: 'sink' }],
        remediation: 'Use a parameterized query instead of string interpolation.',
        rootCause: 'Untrusted input is interpolated directly into SQL.',
        provenance: { source: 'agent-review' },
      },
    ],
    reviewState: {
      surfaces: [
        { id: 'surface-1', label: 'HTTP handlers', disposition: 'reported', riskArea: 'injection' },
        { id: 'surface-2', label: 'Static assets', disposition: 'not_applicable' },
      ],
      explicitExclusions: [],
      deferred: [],
    },
    ...overrides,
  }
}

test('apply registers the documented tool surface and bundled skills', async () => {
  const stateDir = await tempDir('dcs-state-')
  const ctx = mockContext(join(stateDir, 'cordis.patch.yml'))
  apply(ctx, { stateDir })
  assert.equal(ctx.registeredTools.length, 27)
  const names = ctx.registeredTools.map((tool) => tool.name).sort()
  assert.deepEqual(names, [...TOOL_NAMES].sort())
  for (const tool of ctx.registeredTools) {
    assert.equal(tool.parameters.type, 'object')
    assert.equal(typeof tool.description, 'string')
    assert.equal(typeof tool.output.render, 'function')
    assert.equal(typeof tool.execute, 'function')
    assert.ok((tool.timeoutMs ?? 0) > 0)
  }
  const skills = loadBundledSkills(repoRoot)
  const skillNames = skills.map((skill) => skill.name).sort()
  assert.deepEqual(skillNames, [...SKILL_NAMES].sort())
  for (const skill of skills) {
    assert.ok(skill.description.length > 10)
    assert.ok(skill.content.length > 100)
    assert.ok(!skill.content.startsWith('---'))
  }
  assert.equal(ctx.registeredSkills.length, skills.length)
})

test('finding identity is stable across line moves and unique per location', () => {
  const base = sampleDraft('cs_' + 'a'.repeat(24)).findings[0]
  const first = normalizeFinding('cs_' + 'a'.repeat(24), base, { rootPath: '/tmp' })
  const moved = normalizeFinding('cs_' + 'a'.repeat(24), { ...base, locations: [{ path: 'src/app.js', startLine: 40 }] }, { rootPath: '/tmp' })
  const elsewhere = normalizeFinding('cs_' + 'a'.repeat(24), { ...base, locations: [{ path: 'src/other.js', startLine: 3 }] }, { rootPath: '/tmp' })
  assert.match(first.findingId, /^csf_[a-f0-9]{24}$/)
  assert.match(first.occurrenceId, /^occ_[a-f0-9]{24}$/)
  assert.match(first.fingerprints.primary, /^codex-security\/v1:sha256:[a-f0-9]{64}$/)
  assert.equal(first.fingerprints.primary, moved.fingerprints.primary)
  assert.notEqual(first.fingerprints.primary, elsewhere.fingerprints.primary)
  assert.notEqual(first.occurrenceId, moved.occurrenceId)
  assert.equal(normalizeAnchor('injection/sql', 'src/app.js'), normalizeAnchor('injection/sql', 'src/app.js'))
})

test('policy gate fails at or above the configured severity', () => {
  const base = sampleDraft('cs_' + 'b'.repeat(24)).findings[0]
  const finding = normalizeFinding('cs_' + 'b'.repeat(24), base, { rootPath: '/tmp' })
  assert.equal(policyGate([finding], 'high').status, 'fail')
  assert.equal(policyGate([finding], 'critical').status, 'pass')
  assert.equal(policyGate([finding], 'off').status, 'pass')
  assert.equal(policyGate([finding], 'high').failing, 1)
  const sarif = toSarif({ scanId: 'cs_' + 'b'.repeat(24), target: { displayName: 'demo', rootPath: '/tmp/demo' }, mode: 'standard' }, [finding])
  assert.equal(sarif.version, '2.1.0')
  assert.equal(sarif.runs[0].results.length, 1)
  assert.equal(sarif.runs[0].results[0].properties['security-severity'], '8.0')
})

test('scan lifecycle seals findings, coverage, report and manifest', async () => {
  const target = await makeTarget()
  const stateDir = await tempDir('dcs-state-')
  try {
    const ctx = mockContext(join(stateDir, 'cordis.patch.yml'))
    const service = new SecurityService(ctx, { config: { stateDir, failOnSeverity: 'critical' } })
    const setup = await service.inspectSetup()
    assert.equal(setup.ok, true)

    const targetInfo = await service.inspectTarget({ targetPath: target })
    assert.equal(targetInfo.ok, true)
    assert.equal(targetInfo.target.kind, 'directory_snapshot')
    assert.ok(targetInfo.inventory.inspectedFiles >= 2)

    const started = await service.startScan({ targetPath: target, notes: 'unit test scan' }, 'standard')
    assert.match(started.scanId, /^cs_[a-f0-9]{24}$/)
    assert.equal(started.skill, 'security-scan')

    const draftResult = await service.recordScanDraft({ scanId: started.scanId, draft: sampleDraft(started.scanId) })
    assert.equal(draftResult.findingsCount, 1)
    assert.equal(draftResult.severityCounts.high, 1)

    const completed = await service.completeScan({ scanId: started.scanId })
    assert.equal(completed.status, 'completed')
    assert.equal(completed.findingsCount, 1)
    assert.equal(completed.policy.status, 'pass')
    const scanDir = dirname(completed.reportPath)
    for (const name of ['findings.json', 'coverage.json', 'report.md', 'sarif.json', 'scan-manifest.json']) {
      const content = await readFile(join(scanDir, name), 'utf8')
      assert.ok(content.length > 0, name + ' should not be empty')
    }
    const manifest = JSON.parse(await readFile(join(scanDir, 'scan-manifest.json'), 'utf8'))
    assert.equal(manifest.documentType, 'codex-security.scan-manifest')
    assert.equal(manifest.scan.status, 'completed')
    assert.ok(manifest.scan.artifacts.length >= 4, 'manifest should seal findings, coverage, sarif and report')
    for (const artifact of manifest.scan.artifacts) {
      const bytes = await readFile(join(scanDir, artifact.path))
      assert.equal(bytes.byteLength > 0, true, artifact.path)
    }
    const findings = JSON.parse(await readFile(join(scanDir, 'findings.json'), 'utf8'))
    assert.equal(findings.documentType, 'codex-security.findings')
    assert.equal(findings.findings[0].fingerprints.algorithm, 'codex-security/v1')
    const coverage = JSON.parse(await readFile(join(scanDir, 'coverage.json'), 'utf8'))
    assert.equal(coverage.surfaces.length, 2)
    assert.equal(coverage.mode, 'repository')
    const report = await readFile(join(scanDir, 'report.md'), 'utf8')
    assert.match(report, /SQL injection in handler/)
    assert.match(report, /CWE-89/)

    const second = await service.startScan({ targetPath: target }, 'standard')
    await service.recordScanDraft({ scanId: second.scanId, draft: sampleDraft(second.scanId) })
    await service.completeScan({ scanId: second.scanId })
    const comparison = await service.compareScans({ baseScanId: started.scanId, headScanId: second.scanId })
    assert.equal(comparison.counts.open, 1)
    assert.equal(comparison.counts.closed, 0)

    const listed = await service.listScans({})
    assert.equal(listed.total, 2)
    const findingList = await service.listFindings({ scanId: started.scanId })
    assert.equal(findingList.total, 1)
    const findingId = findingList.findings[0].findingId
    const triage = await service.setFindingTriage({ scanId: started.scanId, findingId, status: 'triaged', note: 'unit test' })
    assert.equal(triage.triage.status, 'triaged')
    const detail = await service.getScan({ scanId: started.scanId })
    assert.equal(detail.findings[0].status, 'triaged')

    const exported = await service.exportFindings({ scanId: started.scanId, format: 'sarif' })
    assert.equal(exported.format, 'sarif')
    const exportedSarif = JSON.parse(await readFile(exported.path, 'utf8'))
    assert.equal(exportedSarif.version, '2.1.0')
    assert.equal(exportedSarif.runs[0].results.length, 1)

    const artifact = await service.saveArtifact({ scanId: second.scanId, path: 'notes/evidence.md', content: '# evidence\n', mediaType: 'text/markdown' })
    assert.match(artifact.artifact.path, /^artifacts\/notes\/evidence\.md$/)
    const read = await service.readArtifact({ scanId: second.scanId, path: 'notes/evidence.md' })
    assert.match(read.content, /# evidence/)

    const status = await service.status()
    assert.equal(status.ok, true)
    assert.equal(status.completed, 2)
  } finally {
    await rm(target, { recursive: true, force: true })
    await rm(stateDir, { recursive: true, force: true })
  }
})

test('routes expose status, scan list and sealed artifacts', async () => {
  const target = await makeTarget()
  const stateDir = await tempDir('dcs-state-')
  try {
    const ctx = mockContext(join(stateDir, 'cordis.patch.yml'))
    const service = new SecurityService(ctx, { config: { stateDir } })
    const started = await service.startScan({ targetPath: target }, 'standard')
    await service.recordScanDraft({ scanId: started.scanId, draft: sampleDraft(started.scanId) })
    await service.completeScan({ scanId: started.scanId })

    const call = async (pathname) => {
      const headers = {}
      let body = ''
      const req = { method: 'GET', url: pathname, headers, async *[Symbol.asyncIterator]() { /* no body */ } }
      const res = {
        statusCode: 0,
        setHeader(name, value) { headers[name] = value },
        end(chunk) { body = String(chunk ?? '') },
      }
      await handleRequest(service, req, res)
      return { status: res.statusCode, headers, body }
    }

    const status = await call('/plugins/codex-security/status')
    assert.equal(status.status, 200)
    const statusPayload = JSON.parse(status.body)
    assert.equal(statusPayload.ok, true)
    assert.equal(statusPayload.completed, 1)

    const scans = await call('/plugins/codex-security/scans')
    assert.equal(scans.status, 200)
    assert.equal(JSON.parse(scans.body).total, 1)

    const scan = await call('/plugins/codex-security/scans/' + started.scanId)
    assert.equal(scan.status, 200)
    assert.equal(JSON.parse(scan.body).scan.scanId, started.scanId)

    const exported = await call('/plugins/codex-security/export/' + started.scanId + '?format=markdown')
    assert.equal(exported.status, 200)
    assert.match(exported.headers['content-disposition'], /attachment; filename=/)
    assert.match(exported.body, /SQL injection/)

    const missing = await call('/plugins/codex-security/scans/cs_' + 'f'.repeat(24))
    assert.equal(missing.status, 404)
    assert.equal(JSON.parse(missing.body).ok, false)
  } finally {
    await rm(target, { recursive: true, force: true })
    await rm(stateDir, { recursive: true, force: true })
  }
})

test('store recovers scans from disk when the index is missing', async () => {
  const stateDir = await tempDir('dcs-state-')
  try {
    const store = new ScanStore(stateDir)
    await store.init()
    const target = { kind: 'directory_snapshot', rootPath: stateDir, targetId: 'target_x', displayName: 'demo', snapshotDigest: 'codex-security-snapshot/v1:sha256:' + '0'.repeat(64) }
    const record = await store.create({
      scanId: 'cs_' + 'c'.repeat(24),
      mode: 'standard',
      promptOnly: false,
      target,
      scope: { includePaths: ['.'], excludePaths: [] },
      inventory: { inspectedFiles: 1, totalBytes: 10, languages: {}, truncated: false },
      warnings: [],
    })
    assert.ok(record.scanId)
    const found = await store.get('cs_' + 'c'.repeat(24))
    assert.ok(found)
    await rm(join(stateDir, 'index.json'), { force: true })
    const recovered = await store.get('cs_' + 'c'.repeat(24))
    assert.ok(recovered, 'scan should be recoverable from its directory')
    const list = await store.list()
    assert.equal(list.length, 1)
  } finally {
    await rm(stateDir, { recursive: true, force: true })
  }
})
