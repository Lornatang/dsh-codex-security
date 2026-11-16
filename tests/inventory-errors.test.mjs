import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolveTarget } from '../lib/target.js'
import { statusEntries, trackedFiles } from '../lib/git.js'

test('directory enumeration errors fail closed rather than hiding a subtree', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-inventory-')))
  const hidden = join(root, 'unreadable')
  const original = fs.promises.readdir
  try {
    await mkdir(hidden)
    await writeFile(join(root, 'app.js'), 'safe()\n')
    await writeFile(join(hidden, 'unsafe.js'), 'unsafe()\n')
    fs.promises.readdir = async (path, ...args) => {
      if (String(path) === hidden) throw Object.assign(new Error('simulated access denial'), { code: 'EACCES' })
      return original(path, ...args)
    }
    syncBuiltinESMExports()
    await assert.rejects(resolveTarget({ targetPath: root, maxFiles: 100, maxFileBytes: 1024 }), /enumerat|access|unreadable/i)
  } finally {
    fs.promises.readdir = original
    syncBuiltinESMExports()
    await rm(root, { recursive: true, force: true })
  }
})

test('failed Git inventory and status commands cannot become empty successful results', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-git-error-')))
  try {
    await assert.rejects(trackedFiles(root), /git|inventory|files/i)
    await assert.rejects(statusEntries(root), /git|status/i)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('an unusable Git metadata directory cannot silently fall back to a non-Git inventory', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-git-metadata-')))
  try {
    await mkdir(join(root, '.git'))
    await writeFile(join(root, 'app.js'), 'safe()\n')
    await assert.rejects(resolveTarget({ targetPath: root, maxFiles: 100, maxFileBytes: 1024 }), /git|metadata/i)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a source directory symlink is reported as an incomplete inventory', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dcs-inventory-link-')))
  try {
    const target = join(root, 'target')
    const outside = join(root, 'outside')
    await mkdir(target)
    await mkdir(outside)
    await writeFile(join(target, 'app.js'), 'safe()\n')
    await writeFile(join(outside, 'unreviewed.js'), 'unsafe()\n')
    await symlink(outside, join(target, 'linked'), process.platform === 'win32' ? 'junction' : 'dir')
    const resolved = await resolveTarget({ targetPath: target, maxFiles: 100, maxFileBytes: 1024 })
    assert.ok(resolved.warnings.some((warning) => /symbolic link/i.test(warning)))
  } finally { await rm(root, { recursive: true, force: true }) }
})
