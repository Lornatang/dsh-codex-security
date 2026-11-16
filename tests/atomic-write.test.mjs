import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, toNamespacedPath } from 'node:path'
import { writeFileAtomic } from '../lib/util.js'
import { SecurityService } from '../lib/service.js'

test('Windows atomic replacement waits for a transient reader denying delete sharing', { skip: process.platform !== 'win32' }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'dcs-atomic-'))
  const path = join(root, 'index.json')
  const require = createRequire(import.meta.url)
  const api = require(`@koromix/koffi-${process.platform}-${process.arch}`)
  const kernel = api.load('kernel32.dll')
  const create = kernel.func('void * __stdcall CreateFileW(const char16_t *, uint32_t, uint32_t, void *, uint32_t, uint32_t, void *)')
  const close = kernel.func('int __stdcall CloseHandle(void *)')
  let handle
  try {
    await writeFile(path, 'old')
    handle = create(toNamespacedPath(path), 0x80000000, 3, null, 3, 0x80, null)
    assert.ok(handle && handle !== -1n && handle !== 0xffffffffffffffffn)
    const pending = writeFileAtomic(path, 'new')
    void pending.catch(() => undefined)
    await new Promise((resolve) => setTimeout(resolve, 100))
    close(handle)
    handle = undefined
    await pending
    assert.equal(await readFile(path, 'utf8'), 'new')
  } finally { if (handle) close(handle); await rm(root, { recursive: true, force: true }) }
})

test('artifact listings never expose in-progress atomic temporary files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dcs-list-'))
  try {
    const service = new SecurityService({}, { config: { stateDir: join(root, 'state') } })
    const scan = await service.startScan({ targetPath: root, excludePaths: ['state/**'] }, 'standard')
    const directory = (await service.store.get(scan.scanId)).dir
    await writeFile(join(directory, '.123.456.abcdef01.tmp'), 'unfinished')
    assert.ok(!(await service.store.listArtifacts(scan.scanId)).some((entry) => entry.path.endsWith('.tmp')))
  } finally { await rm(root, { recursive: true, force: true }) }
})
