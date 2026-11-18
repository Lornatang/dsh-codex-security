import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, symlink, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readEvidenceLine } from '../lib/target.js'

test('evidence line reads stay inside the target, even through a parent symlink', async () => {
  const root = await mkdtemp(join(tmpdir(), 'codex-evidence-'))
  try {
    const repo = join(root, 'repo')
    await mkdir(join(repo, 'src'), { recursive: true })
    await writeFile(join(repo, 'src', 'app.js'), 'first line\nsecond line\n')
    await writeFile(join(root, 'outside.txt'), 'host secret\n')
    assert.equal(await readEvidenceLine(repo, 'src/app.js', 2, 1000), 'second line')
    assert.equal(await readEvidenceLine(repo, '../outside.txt', 1, 1000), undefined)
    assert.equal(await readEvidenceLine(repo, join(root, 'outside.txt'), 1, 1000), undefined)
    let linked = true
    try {
      await symlink(root, join(repo, 'link'), process.platform === 'win32' ? 'junction' : 'dir')
    } catch {
      linked = false
    }
    if (linked) assert.equal(await readEvidenceLine(repo, 'link/outside.txt', 1, 1000), undefined)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
