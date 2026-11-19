import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'

const run = promisify(execFile)
const MAX_BUFFER = 64 * 1024 * 1024

export interface GitResult { ok: boolean; stdout: string; stderr: string }

export async function git(root: string, args: string[], timeoutMs = 60000, signal?: AbortSignal): Promise<GitResult> {
  try {
    const result = await run('git', args, { cwd: root, timeout: timeoutMs, maxBuffer: MAX_BUFFER, windowsHide: true, signal })
    return { ok: true, stdout: String(result.stdout), stderr: String(result.stderr) }
  } catch (error) {
    signal?.throwIfAborted()
    const failed = error as { stdout?: string; stderr?: string; message?: string }
    return { ok: false, stdout: String(failed.stdout ?? ''), stderr: String(failed.stderr ?? failed.message ?? 'git failed') }
  }
}

export async function gitString(root: string, args: string[], timeoutMs?: number, signal?: AbortSignal): Promise<string | undefined> {
  const result = await git(root, args, timeoutMs, signal)
  return result.ok ? result.stdout.trim() : undefined
}


export async function repoRoot(path: string, signal?: AbortSignal): Promise<string | undefined> {
  return gitString(path, ['rev-parse', '--show-toplevel'], undefined, signal)
}

export async function headRevision(root: string, signal?: AbortSignal): Promise<string | undefined> {
  return gitString(root, ['rev-parse', 'HEAD'], undefined, signal)
}

export async function currentBranch(root: string, signal?: AbortSignal): Promise<string | undefined> {
  return gitString(root, ['rev-parse', '--abbrev-ref', 'HEAD'], undefined, signal)
}

export async function remoteUrl(root: string, signal?: AbortSignal): Promise<string | undefined> {
  return gitString(root, ['config', '--get', 'remote.origin.url'], undefined, signal)
}

export async function resolveRevision(root: string, ref: string, signal?: AbortSignal): Promise<string | undefined> {
  if (typeof ref !== 'string' || ref.length === 0 || ref.startsWith('-')) throw new Error('codex-security: invalid git revision: ' + ref)
  return gitString(root, ['rev-parse', '--verify', ref + '^{commit}'], undefined, signal)
}

export interface StatusEntry { code: string; path: string }

export async function statusEntries(root: string, signal?: AbortSignal): Promise<StatusEntry[]> {
  const result = await git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'], undefined, signal)
  if (!result.ok) throw new Error('codex-security: git status failed: ' + result.stderr.trim())
  const items: StatusEntry[] = []
  const parts = result.stdout.split('\u0000').filter(Boolean)
  for (let i = 0; i < parts.length; i++) {
    const entry = parts[i] as string
    const code = entry.slice(0, 2)
    const path = entry.slice(3)
    if (!path) continue
    // Renames emit an extra path entry in porcelain v1 -z output.
    if (code.startsWith('R') || code.startsWith('C')) i += 1
    items.push({ code, path })
  }
  return items
}

export async function trackedFiles(root: string, signal?: AbortSignal): Promise<string[]> {
  const result = await git(root, ['ls-files', '-z'], undefined, signal)
  if (!result.ok) throw new Error('codex-security: git file inventory failed: ' + result.stderr.trim())
  return result.stdout.split('\u0000').filter(Boolean)
}

export interface ChangedFile { status: string; path: string; oldPath?: string }

export async function changedFiles(root: string, options: { base?: string; head?: string; staged?: boolean; workingTree?: boolean; signal?: AbortSignal }): Promise<ChangedFile[]> {
  const args: string[] = ['--no-replace-objects', 'diff', '--name-status', '-z', '--find-renames']
  if (options.staged) args.push('--cached')
  if (options.base) {
    const resolved = await resolveRevision(root, options.base, options.signal)
    if (!resolved) throw new Error('codex-security: invalid diff base: ' + options.base)
    if (options.workingTree) {
      const mergeBase = await gitString(root, ['--no-replace-objects', 'merge-base', resolved, options.head ?? 'HEAD'], undefined, options.signal)
      if (!mergeBase) throw new Error('codex-security: cannot resolve merge base: ' + options.base)
      args.push(mergeBase)
    } else {
      args.push(resolved + '...' + (options.head ?? 'HEAD'))
    }
  } else if (!options.staged) {
    args.push(options.head ?? 'HEAD')
  }
  const result = await git(root, [...args, '--'], undefined, options.signal)
  if (!result.ok) throw new Error('codex-security: git diff failed: ' + result.stderr.trim())
  const parts = result.stdout.split('\u0000').filter(Boolean)
  const files: ChangedFile[] = []
  for (let i = 0; i < parts.length; i++) {
    const status = parts[i] as string
    const path = parts[i + 1]
    if (!path) break
    i += 1
    if (status.startsWith('R') || status.startsWith('C')) {
      const next = parts[i + 1]
      i += 1
      files.push({ status: status.charAt(0), path: next ?? path, oldPath: path })
    } else {
      files.push({ status: status.charAt(0), path })
    }
  }
  if (options.workingTree && !options.staged) {
    const seen = new Set(files.map((file) => file.path))
    for (const entry of await statusEntries(root, options.signal)) {
      if (entry.code === '??' && !seen.has(entry.path)) files.push({ status: 'A', path: entry.path })
    }
  }
  return files
}

/** Read a bounded prefix of a regular file from the exact commit. */
export async function revisionFilePrefix(root: string, revision: string, path: string, limit: number): Promise<Buffer | undefined> {
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(revision) || path.includes('\0') || !Number.isSafeInteger(limit) || limit <= 0) return undefined
  const entry = await git(root, ['--no-replace-objects', '--literal-pathspecs', 'ls-tree', '-z', '--full-tree', revision, '--', path])
  const match = /^100(?:644|755) blob ([a-f0-9]{40}|[a-f0-9]{64})\t/.exec(entry.stdout)
  if (!entry.ok || !match || entry.stdout.slice(match[0].length) !== path + '\0') return undefined

  const child = spawn('git', ['--no-replace-objects', 'cat-file', 'blob', match[1]!], {
    cwd: root, timeout: 60000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'],
  })
  const exited = new Promise<number | null>((resolve) => {
    child.once('error', () => resolve(null))
    child.once('close', resolve)
  })
  const chunks: Buffer[] = []
  let size = 0
  try {
    for await (const chunk of child.stdout) {
      const prefix = (chunk as Buffer).subarray(0, limit - size)
      chunks.push(prefix)
      size += prefix.length
      if (size === limit) {
        child.kill()
        break
      }
    }
    const code = await exited
    return size === limit || code === 0 ? Buffer.concat(chunks, size) : undefined
  } catch {
    child.kill()
    await exited
    return undefined
  }
}

export async function fileDigest(path: string, signal?: AbortSignal): Promise<string | undefined> {
  try {
    const hash = createHash('sha256')
    for await (const chunk of createReadStream(path, { signal })) hash.update(chunk as Buffer)
    return hash.digest('hex')
  } catch { signal?.throwIfAborted(); return undefined }
}
