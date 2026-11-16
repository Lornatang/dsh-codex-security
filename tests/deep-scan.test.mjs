import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SecurityService } from '../lib/service.js'

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-deep-')))
  const target = join(root, 'target')
  await mkdir(target)
  await writeFile(join(target, 'app.js'), 'const value = 1\n')
  const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
  return { root, target, service, cleanup: () => rm(root, { recursive: true, force: true }) }
}

test('managed scans reject ordinary mutations but permit coordinator-owned mutations', async () => {
  const f = await fixture()
  try {
    const parentId = 'cs_' + 'a'.repeat(24)
    const scan = await f.service.startScan({ targetPath: f.target }, 'deep', { scanId: parentId, managedParent: parentId })
    const draft = { scanId: scan.scanId, complete: true, findings: [], reviewState: { surfaces: [{ label: 'source', disposition: 'no_issue_found' }] } }
    await assert.rejects(f.service.recordScanDraft(draft), /managed|coordinator/i)
    await assert.rejects(f.service.cancelScan({ scanId: scan.scanId }), /managed|coordinator/i)
    const accepted = await f.service.withManagedAccess(draft, () => f.service.recordScanDraft(draft))
    assert.equal(accepted.findingsCount, 0)
    assert.equal((await f.service.getScanContext({ scanId: scan.scanId })).draft.present, true)
  } finally { await f.cleanup() }
})
