import assert from 'node:assert/strict'
import { execFile, execFileSync } from 'node:child_process'
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { createExportValidator, writeSecureExport } from '../lib/secure-export.js'
import { gitString } from '../lib/git.js'
import { isWithin } from '../lib/util.js'

const attacker = fileURLToPath(new URL('./fixtures/swap-export-directory.mjs', import.meta.url))
const fileAttacker = fileURLToPath(new URL('./fixtures/swap-export-file.mjs', import.meta.url))
const gitAttacker = fileURLToPath(new URL('./fixtures/retarget-git-metadata.mjs', import.meta.url))
const exporter = fileURLToPath(new URL('./fixtures/export-process.mjs', import.meta.url))
const run = promisify(execFile)
const makeTemp = async (prefix) => realpath(await mkdtemp(prefix))

for (const kind of ['scan', 'git']) test(`logical ${kind} storage paths remain protected through child links`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-inner-alias-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'state', 'repositories')
  const gitRoot = join(root, 'state', 'metadata')
  const protectedRoot = kind === 'scan' ? scanRoot : gitRoot
  const output = join(protectedRoot, 'alias', 'report.json')
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    await mkdir(gitRoot)
    await symlink(workspace, join(protectedRoot, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [gitRoot], allowOutside: true })
    await assert.rejects(writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'unsafe', validate }), kind === 'scan' ? /scan storage/ : /version.control/)
    assert.equal(await access(join(workspace, 'report.json')).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const kind of ['scan', 'git']) for (const timing of ['existing', 'before-publish']) test(`a link inside ${kind} storage at ${timing} cannot alias the physical export directory`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-scan-link-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'state', 'repositories')
  const gitRoot = join(root, 'state', 'metadata')
  const alias = join(kind === 'scan' ? scanRoot : gitRoot, 'alias')
  const output = join(workspace, 'report.json')
  let attempted
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    await mkdir(gitRoot)
    if (timing === 'existing') await symlink(workspace, alias, process.platform === 'win32' ? 'junction' : 'dir')
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [gitRoot], allowOutside: false })
    await assert.rejects(writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'unsafe', validate,
      onPhase: async phase => { if (phase === 'before-publish') attempted = execFileSync(process.execPath, [attacker, alias, alias + '-unused', workspace, 'link-only'], { encoding: 'utf8' }) },
    }), kind === 'scan' ? /scan storage contains links/ : /version-control metadata contains links/)
    if (timing === 'before-publish') assert.equal(attempted, 'swapped')
    assert.equal(await access(output).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a scan-storage root that is itself a link remains supported', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-scan-root-link-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'repositories')
  const actualStorage = join(root, 'storage')
  const output = join(workspace, 'report.json')
  try {
    await mkdir(workspace)
    await mkdir(actualStorage)
    await symlink(actualStorage, scanRoot, process.platform === 'win32' ? 'junction' : 'dir')
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [], allowOutside: false })
    const result = await writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate })
    assert.equal(await readFile(result, 'utf8'), 'safe')
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const kind of ['scan', 'git']) for (const alias of [false, true]) test(`relocated ${kind} storage remains protected, alias=${alias}`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-protected-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'state', 'repositories')
  const gitRoot = join(root, 'metadata')
  const relocated = join(workspace, 'relocated')
  const original = kind === 'scan' ? scanRoot : gitRoot
  const output = join(relocated, 'report.json')
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    await mkdir(gitRoot)
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [gitRoot], allowOutside: kind === 'git' })
    await rename(original, relocated)
    if (alias) await symlink(relocated, original, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'unsafe', validate }), kind === 'scan' ? /scan storage/ : /version.control/)
    assert.equal(await access(output).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const kind of ['scan', 'git']) for (const phase of ['pinned', 'before-mkdir', 'before-publish', 'before-cleanup']) {
  test(`changing the ${kind} root at ${phase} is detected`, async () => {
    const root = await makeTemp(join(tmpdir(), 'dcs-export-root-race-'))
    const workspace = join(root, 'workspace')
    const scanRoot = join(root, 'state', 'repositories')
    const gitRoot = join(root, 'state', 'metadata')
    const protectedRoot = kind === 'scan' ? scanRoot : gitRoot
    const directory = phase === 'before-mkdir' ? join(workspace, 'missing') : workspace
    const output = join(directory, 'report.json')
    let attempted
    try {
      await mkdir(workspace)
      await mkdir(scanRoot, { recursive: true })
      await mkdir(gitRoot)
      const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [gitRoot], allowOutside: kind === 'git' })
      await assert.rejects(writeSecureExport({
        requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate,
        onPhase: async observed => {
          if (observed === phase && !attempted) attempted = execFileSync(process.execPath, [attacker, protectedRoot, protectedRoot + '-moved', workspace, 'link'], { encoding: 'utf8' })
        },
      }), kind === 'scan' ? /scan storage/ : /version.control/)
      assert.equal(attempted, 'swapped')
      assert.equal(await access(output).then(() => true, () => false), phase === 'before-cleanup')
      if (phase === 'before-mkdir') assert.equal(await access(directory).then(() => true, () => false), false)
      assert.equal((await readdir(workspace)).filter(name => name.endsWith('.tmp')).length, 0)
    } finally { await rm(root, { recursive: true, force: true }) }
  })
}

for (const mode of ['gitfile', 'commondir']) test(`re-resolves Git metadata after ${mode} changes`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-git-race-'))
  const workspace = join(root, 'workspace')
  const oldGit = join(root, 'old-git')
  const newGit = join(root, 'new-git')
  const scanRoot = join(root, 'state', 'repositories')
  const output = join(newGit, 'report.json')
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    execFileSync('git', ['init', '-q', '--separate-git-dir', oldGit, workspace])
    execFileSync('git', ['init', '--bare', '-q', newGit])
    const resolveGitDirs = async () => Promise.all(['--git-dir', '--git-common-dir'].map(async flag => {
      const directory = await gitString(workspace, ['rev-parse', '--path-format=absolute', flag])
      if (!directory) throw new Error('cannot resolve Git metadata')
      return resolve(workspace, directory)
    }))
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [root], scanRoot, gitDirs: await resolveGitDirs(), resolveGitDirs, allowOutside: true })
    let attempted = false
    await assert.rejects(writeSecureExport({
      requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate,
      onPhase: async phase => {
        if (phase !== 'before-publish' || attempted) return
        attempted = true
        execFileSync(process.execPath, [gitAttacker, mode, mode === 'gitfile' ? join(workspace, '.git') : join(oldGit, 'commondir'), newGit])
        assert.ok((await resolveGitDirs()).some(path => path.toLowerCase() === newGit.toLowerCase()))
      },
    }), /version.control/)
    assert.equal(attempted, true)
    assert.equal(await access(output).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const phase of ['before-mkdir', 'before-publish', 'before-cleanup']) test(`moving a pinned directory into scan storage at ${phase} fails`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-move-into-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'state', 'repositories')
  const moved = join(scanRoot, 'moved-workspace')
  const output = phase === 'before-mkdir' ? join(workspace, 'missing', 'report.json') : join(workspace, 'report.json')
  let attempted
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [], allowOutside: false })
    let failure
    try {
      await writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate,
        onPhase: async observed => { if (observed === phase && !attempted) attempted = execFileSync(process.execPath, [attacker, workspace, moved, scanRoot, 'move-only'], { encoding: 'utf8' }) },
      })
    } catch (error) { failure = error }
    if (process.platform === 'win32') {
      assert.match(attempted, /EBUSY|EPERM|EACCES/)
      assert.equal(failure, undefined)
      assert.equal(await readFile(output, 'utf8'), 'safe')
    } else {
      assert.equal(attempted, 'swapped')
      assert.match(failure?.message ?? '', /directory changed/)
      assert.equal(await access(join(moved, 'report.json')).then(() => true, () => false), phase === 'before-cleanup')
      assert.equal(await access(join(moved, 'missing')).then(() => true, () => false), false)
    }
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('POSIX checkpoints cannot observe a directory moved out and back between checks', { skip: process.platform === 'win32' }, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-roundtrip-'))
  const workspace = join(root, 'workspace')
  const scanRoot = join(root, 'state', 'repositories')
  const output = join(workspace, 'report.json')
  try {
    await mkdir(workspace)
    await mkdir(scanRoot, { recursive: true })
    const validate = await createExportValidator({ requestedOutput: output, allowedRoots: [workspace], scanRoot, gitDirs: [], allowOutside: false })
    let attempted
    const path = await writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate,
      onPhase: async phase => { if (phase === 'before-publish') attempted = execFileSync(process.execPath, [attacker, workspace, join(scanRoot, 'moved'), scanRoot, 'roundtrip'], { encoding: 'utf8' }) },
    })
    assert.equal(attempted, 'swapped')
    assert.equal(await readFile(path, 'utf8'), 'safe')
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('exports through search-only ancestors without requiring directory read access', { skip: !['linux', 'darwin'].includes(process.platform) }, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-search-only-'))
  const ancestor = join(root, 'ancestor')
  const directory = join(ancestor, 'output')
  const output = join(directory, 'report.json')
  try {
    await mkdir(ancestor)
    await mkdir(directory)
    await chmod(ancestor, 0o100)
    await chmod(directory, 0o300)
    const path = await writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate: async () => {} })
    assert.equal(await readFile(path, 'utf8'), 'safe')
  } finally {
    await chmod(ancestor, 0o700).catch(() => {})
    await chmod(directory, 0o700).catch(() => {})
    await rm(root, { recursive: true, force: true })
  }
})

test('on Windows directory traversal does not require listing ancestors', { skip: process.platform !== 'win32' }, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-traverse-only-'))
  const ancestor = join(root, 'ancestor')
  const output = join(ancestor, 'output', 'report.json')
  try {
    await mkdir(join(ancestor, 'output'), { recursive: true })
    execFileSync('icacls.exe', [ancestor, '/deny', '*S-1-1-0:(RD)'])
    await assert.rejects(readdir(ancestor), { code: 'EPERM' })
    const path = await writeSecureExport({ requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe', validate: async () => {} })
    assert.equal(await readFile(path, 'utf8'), 'safe')
  } finally {
    try { execFileSync('icacls.exe', [ancestor, '/remove:d', '*S-1-1-0']) } catch {}
    await rm(root, { recursive: true, force: true })
  }
})

test('without the optional native package, loading works and export fails before creating paths', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-no-native-'))
  try {
    await copyFile(new URL('../lib/secure-export.js', import.meta.url), join(root, 'secure-export.js'))
    await copyFile(new URL('../lib/util.js', import.meta.url), join(root, 'util.js'))
    await writeFile(join(root, 'package.json'), '{"type":"module"}')
    const script = `import { writeSecureExport } from './secure-export.js';
      try { await writeSecureExport({ requestedOutput: ${JSON.stringify(join(root, 'missing', 'result.json'))}, requested: true, scanId: 'cs_test', extension: 'json', content: 'x', validate: async () => {} }); }
      catch (error) { process.stdout.write(error.message); }`
    const output = await run(process.execPath, ['--input-type=module', '-e', script], { cwd: root, env: { ...process.env, NODE_PATH: '' } })
    assert.match(output.stdout, /requires native filesystem support/)
    assert.equal(await access(join(root, 'missing')).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('different processes never replace the same destination', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-processes-'))
  const output = join(root, 'report.json')
  try {
    const results = await Promise.all(Array.from({ length: 8 }, async () => JSON.parse((await run(process.execPath, [exporter, output])).stdout)))
    assert.equal(results.filter((item) => item.ok).length, 1, JSON.stringify(results))
    assert.equal(results.filter((item) => !item.ok && /already exists/.test(item.message)).length, 7, JSON.stringify(results))
    assert.equal(await readFile(output, 'utf8'), '{"valid":true}')
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('different processes allocate distinct default names', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-defaults-'))
  const output = join(root, 'report.json')
  try {
    const results = await Promise.all(Array.from({ length: 8 }, async () => JSON.parse((await run(process.execPath, [exporter, output, 'default'])).stdout)))
    assert.ok(results.every((item) => item.ok), JSON.stringify(results))
    assert.equal(new Set(results.map((item) => item.path)).size, 8)
    for (const result of results) assert.equal(await readFile(result.path, 'utf8'), '{"valid":true}')
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('the final name appears only after a complete file is published', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-atomic-'))
  const output = join(root, 'report.json')
  const content = 'x'.repeat(2 * 1024 * 1024 + 7)
  try {
    let reachedPublication = false
    await writeSecureExport({
      requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content, validate: async () => {},
      onPhase: async (phase) => {
        if (phase === 'before-publish') {
          reachedPublication = true
          assert.equal(await access(output).then(() => true, () => false), false)
        }
      },
    })
    assert.equal(reachedPublication, true)
    assert.equal(await readFile(output, 'utf8'), content)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a concurrent process cannot substitute the staged file', async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-stage-'))
  const output = join(root, 'report.json')
  let attack
  try {
    const result = await writeSecureExport({
      requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'ORIGINAL', validate: async () => {},
      onPhase: async (phase) => {
        if (phase === 'before-publish') attack = execFileSync(process.execPath, [fileAttacker, root], { encoding: 'utf8' })
      },
    })
    assert.notEqual(attack, 'no-stage')
    assert.equal(await readFile(result, 'utf8'), 'ORIGINAL')
    if (process.platform === 'win32') assert.match(attack, /EBUSY|EPERM|EACCES/)
    else assert.equal(attack, 'swapped')
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const mode of ['link', 'directory']) test(`a replaced ancestor cannot redirect a nested export: ${mode}`, async () => {
  const root = await makeTemp(join(tmpdir(), 'dcs-export-ancestor-'))
  const allowed = join(root, 'allowed')
  const moved = join(root, 'moved')
  const forbidden = join(root, 'outside')
  const output = join(allowed, 'nested', 'report.json')
  let attempted
  let failure
  try {
    await mkdir(join(allowed, 'nested'), { recursive: true })
    await mkdir(forbidden)
    try {
      await writeSecureExport({
        requestedOutput: output, requested: true, scanId: 'cs_test', extension: 'json', content: 'safe',
        validate: async (path) => { if (!isWithin(allowed, path)) throw new Error('outside allowed directory') },
        onPhase: async (phase) => {
          if (phase === 'before-publish' && !attempted) attempted = execFileSync(process.execPath, [attacker, allowed, moved, forbidden, mode], { encoding: 'utf8' })
        },
      })
    } catch (error) { failure = error }
    if (process.platform === 'win32') {
      assert.match(attempted, /EBUSY|EPERM|EACCES/)
      assert.equal(failure, undefined)
      assert.equal(await readFile(output, 'utf8'), 'safe')
    } else {
      assert.equal(attempted, 'swapped')
      assert.ok(failure)
      if (mode === 'directory') await rename(allowed, forbidden)
      else await unlink(allowed)
      await rename(moved, allowed)
    }
    assert.equal(await access(join(forbidden, 'nested', 'report.json')).then(() => true, () => false), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const phase of ['pinned', 'before-mkdir', 'before-publish', 'before-cleanup']) {
  for (const mode of ['link', 'directory']) {
    for (const protectedName of ['outside', '.git', 'repositories']) {
      test(`directory swap at ${phase}: ${mode} into ${protectedName}`, async () => {
        const root = await makeTemp(join(tmpdir(), 'dcs-export-race-'))
        const allowed = join(root, 'allowed')
        const moved = join(root, 'moved')
        const protectedDirectory = join(root, protectedName)
        const destination = phase === 'before-mkdir' ? join(allowed, 'nested', 'report.json') : join(allowed, 'report.json')
        let attempted
        let result
        let failure
        try {
          await mkdir(allowed)
          await mkdir(protectedDirectory)
          try {
            result = await writeSecureExport({
              requestedOutput: destination, requested: true, scanId: 'cs_test', extension: 'json', content: '{"safe":true}',
              validate: async (output) => {
                if (!isWithin(allowed, output) || isWithin(protectedDirectory, output)) throw new Error('outside allowed directory')
              },
              onPhase: async (observed) => {
                if (observed !== phase || attempted) return
                attempted = execFileSync(process.execPath, [attacker, allowed, moved, protectedDirectory, mode], { encoding: 'utf8' })
              },
            })
          } catch (error) { failure = error }
          assert.ok(attempted, 'the barrier must run')
          if (process.platform === 'win32') {
            assert.match(attempted, /EBUSY|EPERM|EACCES/)
            assert.equal(failure, undefined)
            assert.equal(await readFile(result, 'utf8'), '{"safe":true}')
          } else {
            assert.equal(attempted, 'swapped')
            assert.ok(failure, 'a detected move must fail the export')
            if (mode === 'directory') await rename(allowed, protectedDirectory)
            else await unlink(allowed)
            await rename(moved, allowed)
          }
          assert.equal(await access(join(protectedDirectory, 'report.json')).then(() => true, () => false), false)
          assert.equal(await access(join(protectedDirectory, 'nested')).then(() => true, () => false), false)
          if (phase !== 'before-cleanup' && process.platform !== 'win32') {
            assert.equal(await access(join(allowed, 'report.json')).then(() => true, () => false), false)
          }
        } finally { await rm(root, { recursive: true, force: true }) }
      })
    }
  }
}
