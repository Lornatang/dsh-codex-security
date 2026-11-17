import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { matchesAny, matchesScopePath, globToRegExp, readText, writeFileAtomic } from '../lib/util.js'
import { readEvidenceLine } from '../lib/target.js'
import { resolveRevision } from '../lib/git.js'

test('glob matching is linear-time and resists catastrophic backtracking', () => {
  const longPath = 'a/'.repeat(400) + 'secret'
  const nested = '**/'.repeat(60) + 'secret'
  const ambiguous = '*a'.repeat(40) + 'b'
  const start = Date.now()
  assert.equal(matchesAny(longPath, [nested]), true)
  assert.equal(matchesAny('a'.repeat(4000), [ambiguous]), false)
  assert.equal(matchesAny('a'.repeat(4000) + 'b', [ambiguous]), true)
  const elapsed = Date.now() - start
  assert.ok(elapsed < 3000, 'glob matching took too long: ' + elapsed + 'ms')
})

test('glob semantics preserved for include/exclude patterns', () => {
  assert.equal(matchesAny('state/foo.json', ['state/**']), true)
  assert.equal(matchesAny('src/foo.json', ['state/**']), false)
  assert.equal(matchesAny('a.ts', ['*.ts']), true)
  assert.equal(matchesAny('dir/a.ts', ['*.ts']), true)
  assert.equal(matchesAny('a.js', ['*.ts']), false)
  assert.equal(matchesAny('src/a.ts', ['src/*.ts']), true)
  assert.equal(matchesAny('src/sub/a.ts', ['src/*.ts']), false)
  assert.equal(matchesAny('src/sub/a.ts', ['src/**/*.ts']), true)
  assert.equal(matchesAny('a.js', ['!*.ts']), true)
  assert.equal(matchesAny('a.ts', ['!*.ts']), false)
  assert.equal(matchesAny('dir/', ['dir/']), true)
  assert.equal(matchesScopePath('src/foo.ts', ['src']), true)
  assert.equal(matchesScopePath('other/foo.ts', ['src']), false)
})

test('safe matcher agrees with the hardened regex on a pattern corpus', () => {
  const patterns = ['*.ts', '**/*.ts', 'src/**', 'src/*.ts', '!*.log', 'a?c', '**', 'foo/', './src/**', 'dist/**/*.{js,map}', '*a*a*b', 'node_modules/**', '**/test/**']
  const paths = ['a.ts', 'src/a.ts', 'src/sub/a.ts', 'a.log', 'abc', 'aXC', 'foo', 'foo/bar', 'src/x.js', 'dist/a.js', 'dist/a.map', 'aaab', 'node_modules/x/y.js', 'pkg/test/a.ts', 'x/y/b']
  for (const pattern of patterns) {
    let expected
    try { expected = globToRegExp(pattern) } catch { continue }
    for (const path of paths) {
      assert.equal(matchesAny(path, [pattern]), expected.test(path), 'divergence for ' + JSON.stringify(pattern) + ' on ' + JSON.stringify(path))
    }
  }
})

test('readText reads at most the requested byte limit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dcs-readtext-'))
  try {
    const path = join(root, 'big.txt')
    await writeFile(path, 'x'.repeat(5 * 1024 * 1024))
    const text = await readText(path, 1024)
    assert.equal(text.length, 1024)
    assert.equal(await readText(join(root, 'missing.txt'), 1024), undefined)
    await writeFile(path, 'hello')
    assert.equal(await readText(path, 1024), 'hello')
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('writeFileAtomic replaces content and leaves no temporary residue', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dcs-atomic2-'))
  try {
    const path = join(root, 'nested', 'index.json')
    await writeFileAtomic(path, 'first')
    await writeFileAtomic(path, 'second')
    assert.equal(await readFile(path, 'utf8'), 'second')
    const { readdir } = await import('node:fs/promises')
    const entries = await readdir(join(root, 'nested'))
    assert.deepEqual(entries, ['index.json'])
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('readEvidenceLine refuses path traversal and symlink escape', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dcs-evidence-'))
  const outside = await mkdtemp(join(tmpdir(), 'dcs-outside-'))
  try {
    await mkdir(join(root, 'src'), { recursive: true })
    await writeFile(join(root, 'src', 'a.ts'), 'line one\nline two\n')
    await writeFile(join(outside, 'secret.txt'), 'TOP SECRET\n')
    assert.equal(await readEvidenceLine(root, 'src/a.ts', 2, 1024 * 1024), 'line two')
    assert.equal(await readEvidenceLine(root, '../' + outside.split('/').pop() + '/secret.txt', 1, 1024 * 1024), undefined)
    assert.equal(await readEvidenceLine(root, join(outside, 'secret.txt'), 1, 1024 * 1024), undefined)
    await symlink(join(outside, 'secret.txt'), join(root, 'link.txt'))
    assert.equal(await readEvidenceLine(root, 'link.txt', 1, 1024 * 1024), undefined)
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(outside, { recursive: true, force: true })
  }
})

test('resolveRevision rejects option-like revisions', async () => {
  await assert.rejects(() => resolveRevision('/nonexistent-repo', '--help'), /invalid git revision/)
  await assert.rejects(() => resolveRevision('/nonexistent-repo', '-O/tmp/x'), /invalid git revision/)
  const root = await mkdtemp(join(tmpdir(), 'dcs-git-'))
  try {
    const git = (args) => execFileSync('git', args, { cwd: root, stdio: 'pipe' }).toString().trim()
    git(['init', '-q'])
    git(['config', 'user.email', 't@example.com'])
    git(['config', 'user.name', 'Test'])
    await writeFile(join(root, 'a.txt'), 'a')
    git(['add', '.'])
    git(['commit', '-q', '-m', 'init'])
    const head = await resolveRevision(root, 'HEAD')
    assert.match(head, /^[a-f0-9]{40}$/)
  } finally { await rm(root, { recursive: true, force: true }) }
})
