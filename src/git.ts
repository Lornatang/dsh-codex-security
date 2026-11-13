import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'

const run = promisify(execFile)
const MAX_BUFFER = 64 * 1024 * 1024

export interface GitResult { ok: boolean; stdout: string; stderr: string }

export async function git(root: string, args: string[], timeoutMs = 60000): Promise<GitResult> {
  try {
    const result = await run('git', args, { cwd: root, timeout: timeoutMs, maxBuffer: MAX_BUFFER, windowsHide: true })
    return { ok: true, stdout: String(result.stdout), stderr: String(result.stderr) }
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string; message?: string }
    return { ok: false, stdout: String(failed.stdout ?? ''), stderr: String(failed.stderr ?? failed.message ?? 'git failed') }
  }
}

export async function gitString(root: string, args: string[], timeoutMs?: number): Promise<string | undefined> {
  const result = await git(root, args, timeoutMs)
  return result.ok ? result.stdout.trim() : undefined
}

export async function isGitRepo(root: string): Promise<boolean> {
  return (await gitString(root, ['rev-parse', '--is-inside-work-tree'])) === 'true'
}

export async function repoRoot(path: string): Promise<string | undefined> {
  return gitString(path, ['rev-parse', '--show-toplevel'])
}

export async function headRevision(root: string): Promise<string | undefined> {
  return gitString(root, ['rev-parse', 'HEAD'])
}

export async function currentBranch(root: string): Promise<string | undefined> {
  return gitString(root, ['rev-parse', '--abbrev-ref', 'HEAD'])
}

export async function remoteUrl(root: string): Promise<string | undefined> {
  return gitString(root, ['config', '--get', 'remote.origin.url'])
}

export async function resolveRevision(root: string, ref: string): Promise<string | undefined> {
  return gitString(root, ['rev-parse', '--verify', ref + '^{commit}'])
}

export interface StatusEntry { code: string; path: string }

export async function statusEntries(root: string): Promise<StatusEntry[]> {
  const result = await git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
  if (!result.ok) return []
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

export async function trackedFiles(root: string): Promise<string[]> {
  const result = await git(root, ['ls-files', '-z'])
  if (!result.ok) return []
  return result.stdout.split('\u0000').filter(Boolean)
}

export interface ChangedFile { status: string; path: string; oldPath?: string }

export async function changedFiles(root: string, options: { base?: string; staged?: boolean; workingTree?: boolean }): Promise<ChangedFile[]> {
  const args: string[] = ['diff', '--name-status', '-z', '--find-renames']
  if (options.staged) args.push('--cached')
  if (options.base) {
    const resolved = await resolveRevision(root, options.base) ?? options.base
    args.push(resolved + '...HEAD')
  } else if (!options.staged) {
    args.push('HEAD')
  }
  const result = await git(root, args)
  if (!result.ok) return []
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
  return files
}

/** Digest of the working tree diff including untracked files, used for snapshot identity. */
export async function worktreeDigest(root: string): Promise<string> {
  const hash = createHash('sha256')
  const status = await git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
  hash.update('status\u0000' + (status.ok ? status.stdout : ''))
  const diff = await git(root, ['diff', 'HEAD'])
  hash.update('diff\u0000' + (diff.ok ? diff.stdout : diff.stderr))
  const staged = await git(root, ['diff', '--cached'])
  hash.update('staged\u0000' + (staged.ok ? staged.stdout : ''))
  const untracked = await git(root, ['ls-files', '--others', '--exclude-standard', '-z'])
  if (untracked.ok) {
    const names = untracked.stdout.split('\u0000').filter(Boolean).sort()
    hash.update('untracked\u0000' + names.join('\u0000'))
  }
  return hash.digest('hex')
}

export async function fileDigest(path: string): Promise<string | undefined> {
  const { createHash: create } = await import('node:crypto')
  const { readFile } = await import('node:fs/promises')
  try {
    return create('sha256').update(await readFile(path)).digest('hex')
  } catch { return undefined }
}
