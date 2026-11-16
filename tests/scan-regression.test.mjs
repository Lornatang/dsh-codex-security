import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { access, mkdtemp, mkdir, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
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
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'dcs-regression-')))
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

test('Codex-compatible draft and sealed artifacts preserve evidence and identities', async () => {
  const f = await fixture(true)
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    const stableTarget = scan.scan.target.targetId
    await f.service.saveArtifact({ scanId: scan.scanId, path: 'artifacts/review.txt', content: 'Evidence receipt' })
    const value = {
      ...finding, identity: { anchor: 'query/sink', instance: 'customer' },
      severity: { level: 'high', vector: 'CVSS:3.1/AV:N' }, taxonomy: { category: 'custom-api-risk', cwe: ['CWE-89'] },
      provenance: { source: 'review', worker: 'worker-1' }, custom_field: { retained: true }, locations: [{ path: 'src/app.js', startLine: 1, custom_location: 'retained' }],
      codeEvidence: [{ id: 'sink', label: 'Query', path: 'src/app.js', startLine: 1, code: 'unsafe(input)', explanation: 'Untrusted data reaches the sink.' }],
      code_evidence: [{ id: 'source', code: 'request.input' }],
      rootCause: { summary: 'A missing control.', evidenceRefs: ['sink'] }, root_cause: { summary: 'Input remains untrusted.', evidence_refs: ['source'] },
    }
    const review = { completeness: 'complete', mode: 'repository', includePaths: ['.'], excludePaths: [], custom_coverage: 'retained', surfaces: [{ id: 'source', label: 'Source', disposition: 'reported', receiptRefs: ['artifacts/review.txt'], worker: 'worker-1' }], explicitExclusions: [], deferred: [] }
    const tool = createSecurityTools(f.service).find((entry) => entry.name === 'codex_security_record_scan_draft')
    await tool.execute({ scanId: scan.scanId, complete: true, findings: [value], coverage: review, scope: { runtimeStatus: 'executed', validationMode: 'dynamic', limitations: ['An integration environment was unavailable.'], artifactsReviewed: ['src/app.js'] }, threatModel: { format: 'markdown', content: '# Threat model\n\nAn external caller provides input.\n' } })
    const completed = await f.service.completeScan({ scanId: scan.scanId })
    const findings = JSON.parse(await readFile(completed.findingsPath, 'utf8'))
    const coverage = JSON.parse(await readFile(completed.coveragePath, 'utf8'))
    const manifest = JSON.parse(await readFile(completed.manifestPath, 'utf8'))
    const result = findings.findings[0]
    const hash = (text) => createHash('sha256').update(text).digest('hex')
    const expected = 'codex-security/v1:sha256:' + hash(['codex-security/v1', stableTarget, result.ruleId, result.identity.anchor, result.identity.instance].join('\0'))
    assert.equal(result.fingerprints.primary, expected)
    assert.equal(result.findingId, 'csf_' + hash(expected).slice(0, 24))
    assert.equal(result.occurrenceId, 'occ_' + hash(scan.scanId + '\0' + expected).slice(0, 24))
    assert.equal(result.severity.scoringSystem, 'dsh-severity/v1')
    assert.equal(result.severity.vector, 'CVSS:3.1/AV:N')
    assert.equal(result.taxonomy.category, 'custom-api-risk')
    assert.equal(result.provenance.worker, 'worker-1')
    assert.deepEqual(result.custom_field, { retained: true })
    assert.deepEqual(result.rootCause, value.rootCause)
    assert.deepEqual(result.root_cause, value.root_cause)
    assert.deepEqual(result.code_evidence, value.code_evidence)
    assert.equal(result.locations[0].custom_location, 'retained')
    assert.equal(coverage.completeness, 'complete')
    assert.equal(coverage.custom_coverage, 'retained')
    assert.equal(coverage.surfaces[0].worker, 'worker-1')
    assert.equal(manifest.scan.coverageRef, 'coverage.json')
    assert.equal(manifest.scan.scope.runtimeStatus, 'executed')
    assert.equal(manifest.scan.scope.validationMode, 'dynamic')
    assert.deepEqual(manifest.scan.scope.limitations, ['An integration environment was unavailable.'])
    assert.deepEqual(manifest.scan.scope.artifactsReviewed, ['src/app.js'])
    assert.equal(manifest.scan.threatModel.content, '# Threat model\n\nAn external caller provides input.\n')
    assert.equal(await readFile(join(dirname(completed.reportPath), 'threatmodel.md'), 'utf8'), manifest.scan.threatModel.content)
    assert.match(await readFile(completed.reportPath, 'utf8'), /Files inventoried/)
    await writeFile(join(f.target, 'src', 'app.js'), 'changed(input)\n')
    f.runGit('add', '.')
    f.runGit('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'next')
    const after = await resolveTarget({ ...options, targetPath: f.target })
    assert.equal(after.target.targetId, stableTarget)
    // Optional: exercise the installed reference validator without making CI
    // depend on a proprietary Codex installation.
    if (process.env.CODEX_SECURITY_REFERENCE_ROOT) {
      const validator = join(process.env.CODEX_SECURITY_REFERENCE_ROOT, 'scripts', 'validate_scan_contract.py')
      const output = execFileSync('python', [validator, '--scan-dir', dirname(completed.reportPath)], { encoding: 'utf8' })
      assert.equal(JSON.parse(output).status, 'valid')
    }
  } finally { await f.cleanup() }
})

test('unsealed threat-model projections follow the latest draft or context', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    const dir = join(f.temp, 'state', 'repositories', scan.scan.repoKey, 'scans', scan.scanId)
    await f.service.recordScanDraft({ scanId: scan.scanId, complete: false, findings: [], coverage: { completeness: 'partial', surfaces: [{ label: 'source', disposition: 'needs_follow_up' }] }, threatModel: { format: 'markdown', content: '# Initial model\n' } })
    assert.equal(await readFile(join(dir, 'threatmodel.md'), 'utf8'), '# Initial model\n')
    await assert.rejects(f.service.saveArtifact({ scanId: scan.scanId, path: 'threatmodel.md', content: 'overwrite' }), /reserved|internal|sealed/i)
    await f.service.updateScanContext({ scanId: scan.scanId, threatModel: { format: 'markdown', content: '# Updated model\n' } })
    assert.equal(await readFile(join(dir, 'threatmodel.md'), 'utf8'), '# Updated model\n')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    const sealed = await f.service.completeScan({ scanId: scan.scanId })
    const manifest = JSON.parse(await readFile(sealed.manifestPath, 'utf8'))
    assert.equal(manifest.scan.threatModel.content, '# Updated model\n')
    assert.equal(await readFile(join(dir, 'threatmodel.md'), 'utf8'), '# Updated model\n')
  } finally { await f.cleanup() }
})

test('coverage refuses false completeness, missing receipts, duplicate identities and mismatched scope', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    const source = { label: 'source', disposition: 'no_issue_found' }
    await assert.rejects(f.service.recordScanDraft({ scanId: scan.scanId, findings: [finding, finding], reviewState: { surfaces: [source] } }), /duplicate finding identity/)
    await assert.rejects(f.service.recordScanDraft({ scanId: scan.scanId, findings: [{ ...finding, rootCause: { summary: 'Missing', evidenceRefs: ['unknown'] } }], reviewState: { surfaces: [source] } }), /unknown code evidence/)
    await assert.rejects(f.service.recordScanDraft({ scanId: scan.scanId, findings: [{ ...finding, severity: { level: 'high', score: 11 } }], reviewState: { surfaces: [source] } }), /severity.score/)
    await assert.rejects(f.service.recordScanDraft({ scanId: scan.scanId, findings: [], coverage: { surfaces: [source], includePaths: ['different'] } }), /coverage scope/)
    await f.service.recordScanDraft({ scanId: scan.scanId, complete: true, findings: [], coverage: { surfaces: [{ ...source, receiptRefs: ['artifacts/missing.txt'] }] } })
    await assert.rejects(f.service.completeScan({ scanId: scan.scanId }), /receipt is not a saved artifact/)
    await f.service.recordScanDraft({ scanId: scan.scanId, complete: true, findings: [], coverage: { completeness: 'complete', surfaces: [{ ...source, disposition: 'needs_follow_up' }] } })
    await assert.rejects(f.service.completeScan({ scanId: scan.scanId }), /complete coverage/)
    await f.service.recordScanDraft({ scanId: scan.scanId, complete: true, findings: [], coverage: { completeness: 'unknown', surfaces: [source] } })
    await f.service.completeScan({ scanId: scan.scanId })
    await assert.rejects(f.service.compareScans({ baseScanId: scan.scanId, headScanId: scan.scanId }), /comparable coverage/)
  } finally { await f.cleanup() }
})

test('coverage rejects receipt paths redirected through a directory link', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.saveArtifact({ scanId: scan.scanId, path: 'artifacts/review/receipt.txt', content: 'evidence' })
    await f.service.recordScanDraft({ scanId: scan.scanId, complete: true, findings: [], coverage: { surfaces: [{ label: 'source', disposition: 'no_issue_found', receiptRefs: ['artifacts/review/receipt.txt'] }] } })
    const dir = join(f.temp, 'state', 'repositories', scan.scan.repoKey, 'scans', scan.scanId)
    const original = join(dir, 'artifacts', 'review')
    const relocated = join(dir, 'artifacts', 'review-moved')
    await rename(original, relocated)
    await symlink(relocated, original, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(f.service.completeScan({ scanId: scan.scanId }), /scan-local regular file/)
  } finally { await f.cleanup() }
})

test('legacy unsealed checkpoints migrate and sealed scans remain comparable', async () => {
  const f = await fixture()
  const hash = (value) => createHash('sha256').update(value).digest('hex')
  const legacyIdentity = (value) => {
    const primary = 'codex-security/v1:sha256:' + hash(['codex-security/v1', value.ruleId, value.locations[0].path, value.identity.anchor, value.identity.instance ?? ''].join('\0'))
    return { primary, findingId: 'csf_' + hash('finding\0' + primary).slice(0, 24), occurrenceId: 'occ_' + hash('occ\0' + primary + '\0' + value.locations[0].path + '\0' + value.locations[0].startLine).slice(0, 24) }
  }
  try {
    const stable = { ...finding, anchor: 'query/stable' }
    const first = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: first.scanId, ...draft([stable]) })
    const dir = join(f.temp, 'state', 'repositories', first.scan.repoKey, 'scans', first.scanId)
    const checkpointPath = join(dir, 'checkpoints', 'scan-draft.json')
    const checkpoint = JSON.parse(await readFile(checkpointPath, 'utf8'))
    const previous = legacyIdentity(checkpoint.findings[0])
    Object.assign(checkpoint.findings[0], { findingId: previous.findingId, occurrenceId: previous.occurrenceId, fingerprints: { algorithm: 'codex-security/v1', primary: previous.primary } })
    await writeFile(checkpointPath, JSON.stringify(checkpoint))
    const sealed = await f.service.completeScan({ scanId: first.scanId })
    assert.equal(sealed.migratedDraftIds[0].previous, previous.findingId)
    assert.notEqual(sealed.migratedDraftIds[0].current, previous.findingId)

    // Simulate a historically sealed scan produced by the old implementation.
    const document = JSON.parse(await readFile(sealed.findingsPath, 'utf8'))
    Object.assign(document.findings[0], { findingId: previous.findingId, occurrenceId: previous.occurrenceId, fingerprints: { algorithm: 'codex-security/v1', primary: previous.primary } })
    const bytes = JSON.stringify(document, null, 2) + '\n'
    await writeFile(sealed.findingsPath, bytes)
    const manifest = JSON.parse(await readFile(sealed.manifestPath, 'utf8'))
    manifest.scan.artifacts.find((item) => item.path === 'findings.json').sha256 = hash(bytes)
    await writeFile(sealed.manifestPath, JSON.stringify(manifest))
    const before = await readFile(sealed.findingsPath, 'utf8')
    const next = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: next.scanId, ...draft([{ ...stable, locations: [{ path: 'other/other.js', startLine: 1 }] }]) })
    await f.service.completeScan({ scanId: next.scanId })
    const compared = await f.service.compareScans({ baseScanId: first.scanId, headScanId: next.scanId })
    assert.deepEqual(compared.counts, { base: 1, head: 1, closed: 0, new: 0, open: 1 })
    assert.equal(await readFile(sealed.findingsPath, 'utf8'), before)
    const ambiguous = structuredClone(document.findings[0])
    ambiguous.locations[0].path = 'other/other.js'
    const duplicate = legacyIdentity(ambiguous)
    Object.assign(ambiguous, { findingId: duplicate.findingId, occurrenceId: duplicate.occurrenceId, fingerprints: { algorithm: 'codex-security/v1', primary: duplicate.primary } })
    document.findings.push(ambiguous)
    const ambiguousBytes = JSON.stringify(document, null, 2) + '\n'
    await writeFile(sealed.findingsPath, ambiguousBytes)
    manifest.scan.artifacts.find((item) => item.path === 'findings.json').sha256 = hash(ambiguousBytes)
    await writeFile(sealed.manifestPath, JSON.stringify(manifest))
    await assert.rejects(f.service.compareScans({ baseScanId: first.scanId, headScanId: next.scanId }), /ambiguous legacy finding identity/)
  } finally { await f.cleanup() }
})

test('recording remediation preserves an existing triage status', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft([finding]) })
    await f.service.completeScan({ scanId: scan.scanId })
    const findingId = (await f.service.listFindings({ scanId: scan.scanId })).findings[0].findingId
    await f.service.setFindingTriage({ scanId: scan.scanId, findingId, status: 'accepted_risk', note: 'A recorded decision.' })
    const result = await f.service.setFindingRemediation({ scanId: scan.scanId, findingId, remediation: 'Document the alternative.' })
    assert.equal(result.triage.status, 'accepted_risk')
    assert.equal(result.triage.note, 'A recorded decision.')
    const changed = await f.service.setFindingRemediation({ scanId: scan.scanId, findingId, remediation: 'Fix ready.', status: 'open' })
    assert.equal(changed.triage.status, 'open')
  } finally { await f.cleanup() }
})

test('Codex-style discovery, validation and attack-path evidence survives round trips', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    const discovery = {
      summary: 'Untrusted input reaches a query.', context: 'HTTP route', evidence: 'Query is built from request input.',
      cwe_ids: ['CWE-89'], locations: [{ path: 'src/app.js', start_line: 1, role: 'sink' }, { path: 'other/other.js', start_line: 1, role: 'source' }], instance: 'customer',
    }
    const added = await f.service.recordDiscoveryCandidates({ scanId: scan.scanId, candidates: [discovery] })
    assert.equal(added.added, 1)
    const candidateId = added.candidates[0].candidateId
    assert.equal(added.candidates[0].severity, undefined)
    assert.deepEqual(added.candidates[0].discovery, discovery)
    assert.equal((await f.service.recordDiscoveryCandidates({ scanId: scan.scanId, candidates: [discovery] })).duplicates, 1)
    const validation = {
      disposition: 'reportable', confidence: 'high', confidence_rationale: 'Callers and sink are visible.',
      counterevidence_or_proof_gap: 'No parameterization found.', evidence: ['Source at other/other.js:1', 'Sink at src/app.js:1'],
      method: 'static review', remaining_uncertainty: 'Deployment reachability.', rubric: ['source', 'control', 'sink'],
      source: 'request data', sink: 'query', custom_field: { retained: true },
    }
    await f.service.recordCandidateValidations({ scanId: scan.scanId, validations: [{ candidateId, validation }] })
    const attackPath = {
      decision: 'reportable', dataflow: 'Request to query.', reachability: 'HTTP route.', counterevidence: 'No guard found.',
      impact: 'high', likelihood: 'medium', severity: 'high', severity_rationale: 'Query manipulation.', change_conditions: 'Safe query parameters.',
      custom_field: { retained: true },
    }
    await f.service.recordCandidateAttackPaths({ scanId: scan.scanId, attackPaths: [{ candidateId, attackPath }] })
    const stored = (await f.service.listCandidates({ scanId: scan.scanId })).candidates[0]
    assert.equal(stored.status, 'validated')
    assert.deepEqual(stored.discovery, discovery)
    assert.deepEqual(stored.validation, validation)
    assert.deepEqual(stored.attackPath, attackPath)
    await assert.rejects(f.service.recordCandidateValidations({ scanId: scan.scanId, validations: [{ candidateId, validation: { ...validation, confidence: 'certain' } }] }), /confidence/)
    await assert.rejects(f.service.recordCandidateAttackPaths({ scanId: scan.scanId, attackPaths: [{ candidateId, attackPath: { ...attackPath, decision: 'ignore', severity: 'high' } }] }), /decision or severity/)
    assert.deepEqual((await f.service.listCandidates({ scanId: scan.scanId })).candidates[0].attackPath, attackPath)
    await f.service.recordCandidateValidations({ scanId: scan.scanId, validations: [{ candidateId, status: 'suppressed', summary: 'An existing guard defeats the claim.' }] })
    await f.service.recordCandidateAttackPaths({ scanId: scan.scanId, attackPaths: [{ candidateId, summary: 'The guard prevents the path.' }] })
    const updated = (await f.service.listCandidates({ scanId: scan.scanId })).candidates[0]
    assert.equal(updated.status, 'rejected')
    assert.equal(updated.validation, undefined)
    assert.equal(updated.attackPath, undefined)
    const dir = join(f.temp, 'state', 'repositories', scan.scan.repoKey, 'scans', scan.scanId)
    const history = JSON.parse(await readFile(join(dir, 'validations.json'), 'utf8')).validations
    assert.deepEqual(history[0].validation, validation)
  } finally { await f.cleanup() }
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
    assert.equal(JSON.parse(await readFile(completed.coveragePath, 'utf8')).mode, 'working_tree')
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
    const scoped = await f.service.completeScan({ scanId: different.scanId })
    assert.equal(JSON.parse(await readFile(scoped.coveragePath, 'utf8')).mode, 'scoped_path')
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

test('exports never replace existing files and enforce canonical output boundaries', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    const completed = await f.service.completeScan({ scanId: scan.scanId })
    const existing = join(f.target, 'src', 'app.js')
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: existing }), /exist/i)
    assert.equal(await readFile(existing, 'utf8'), 'unsafe(input)\n')
    const dest = join(f.target, 'result.json')
    const attempts = await Promise.allSettled(Array.from({ length: 4 }, () => f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: dest })))
    assert.equal(attempts.filter((item) => item.status === 'fulfilled').length, 1)
    assert.equal(attempts.filter((item) => item.status === 'rejected').length, 3)
    const content = await readFile(dest, 'utf8')
    assert.doesNotThrow(() => JSON.parse(content))
    const first = await f.service.exportFindings({ scanId: scan.scanId, format: 'markdown' })
    const second = await f.service.exportFindings({ scanId: scan.scanId, format: 'markdown' })
    assert.notEqual(first.path, second.path)
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(f.target, '.git', 'hooks', 'pre-commit') }), /version.control/i)
    const alias = join(f.target, 'scan-alias')
    await symlink(dirname(completed.reportPath), alias, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(alias, 'new.json') }), /scan storage/i)
    const outside = join(f.temp, 'outside')
    await mkdir(outside)
    const escape = join(f.target, 'outside-alias')
    await symlink(outside, escape, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(escape, 'new.json') }), /outside/i)
  } finally { await f.cleanup() }
})

test('large sealed exports are returned in full', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    const completed = await f.service.completeScan({ scanId: scan.scanId })
    const dir = dirname(completed.reportPath)
    const padding = 'x'.repeat(1024 * 1024 + 17)
    for (const [format, filename] of [['json', 'findings.json'], ['sarif', 'sarif.json']]) {
      const path = join(dir, filename)
      const doc = JSON.parse(await readFile(path, 'utf8'))
      doc.padding = padding
      await writeFile(path, JSON.stringify(doc))
      const exported = await f.service.exportContent(scan.scanId, format)
      assert.equal(JSON.parse(exported.content).padding, padding)
    }
    await writeFile(completed.reportPath, padding)
    assert.equal((await f.service.exportContent(scan.scanId, 'markdown')).content, padding)
  } finally { await f.cleanup() }
})

test('outside exports remain exclusive and never enter scan or version-control storage', async () => {
  const f = await fixture()
  try {
    const service = new SecurityService({}, { config: { stateDir: join(f.temp, 'state'), allowExportOutsideWorkspace: true } })
    const scan = await service.startScan({ targetPath: f.target }, 'standard')
    await service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    const completed = await service.completeScan({ scanId: scan.scanId })
    const output = join(f.temp, 'outside', 'nested', 'result.json')
    const exported = await service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: output })
    assert.equal(exported.path, output)
    const content = await readFile(output, 'utf8')
    assert.doesNotThrow(() => JSON.parse(content))
    await assert.rejects(service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: output }), /already exists/i)
    await assert.rejects(service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(dirname(completed.reportPath), 'new.json') }), /scan storage/i)
    await assert.rejects(service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(f.temp, '.git', 'hooks', 'result.json') }), /version.control/i)
  } finally { await f.cleanup() }
})

test('exports reject a separate Git metadata directory inside the workspace', async () => {
  const f = await fixture()
  try {
    const metadata = join(f.target, 'metadata')
    execFileSync('git', ['init', '-q', '--separate-git-dir', metadata, f.target], { stdio: 'ignore' })
    f.runGit('add', 'src', 'other')
    f.runGit('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'initial')
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    await f.service.completeScan({ scanId: scan.scanId })
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(metadata, 'refs', 'heads', 'export') }), /version.control/i)
  } finally { await f.cleanup() }
})

test('a directory snapshot that later becomes a Git repository protects its metadata', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    assert.equal(scan.scan.target.kind, 'directory_snapshot')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    await f.service.completeScan({ scanId: scan.scanId })
    const metadata = join(f.target, 'git-store')
    execFileSync('git', ['init', '-q', '--separate-git-dir', metadata, f.target], { stdio: 'ignore' })
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: join(metadata, 'result.json') }), /version.control/i)
    const safe = join(f.target, 'result.json')
    const exported = await f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: safe })
    assert.equal(exported.path, safe)
  } finally { await f.cleanup() }
})

test('a directory snapshot with broken Git metadata fails closed', async () => {
  const f = await fixture()
  try {
    const scan = await f.service.startScan({ targetPath: f.target }, 'standard')
    await f.service.recordScanDraft({ scanId: scan.scanId, ...draft() })
    await f.service.completeScan({ scanId: scan.scanId })
    await writeFile(join(f.target, '.git'), 'gitdir: missing-metadata\n')
    const output = join(f.target, 'result.json')
    await assert.rejects(f.service.exportFindings({ scanId: scan.scanId, format: 'json', outputPath: output }), /cannot resolve target version-control metadata/)
    assert.equal(await access(output).then(() => true, () => false), false)
  } finally { await f.cleanup() }
})

test('a plain directory snapshot can be exported without Git installed', async () => {
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'dcs-no-git-')))
  try {
    const helper = fileURLToPath(new URL('./fixtures/export-without-git.mjs', import.meta.url))
    const output = execFileSync(process.execPath, [helper, temp], { encoding: 'utf8', env: { ...process.env, PATH: '', Path: '' } })
    const result = JSON.parse(output)
    assert.equal(result.kind, 'directory_snapshot')
    assert.doesNotThrow(() => JSON.parse(result.content))
  } finally { await rm(temp, { recursive: true, force: true }) }
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
    const scan = await start.execute({ targetPath: f.target, manual: true })
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
  assert.ok(pkg.files.includes('README.zh.md'))
  await access(new URL('README.zh.md', root))
})
