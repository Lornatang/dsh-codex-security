import { lstat, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'

export interface StateLockOptions {
  signal?: AbortSignal
  timeoutMs?: number
}

/**
 * Hold SQLite's OS-backed writer lock on a persistent local lock database.
 * The database is never removed; the OS releases the lock on process exit.
 */
export async function acquireStateLock(path: string, options: StateLockOptions = {}): Promise<() => void> {
  const lockPath = resolve(path)
  const timeoutMs = options.timeoutMs ?? 30000
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error('codex-security: invalid state-lock timeout')
  options.signal?.throwIfAborted()
  await mkdir(dirname(lockPath), { recursive: true, mode: 0o700 })
  const parent = await lstat(dirname(lockPath))
  if (!parent.isDirectory() || parent.isSymbolicLink()) throw new Error('codex-security: state-lock directory must be a real directory')
  const existing = await lstat(lockPath).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined
    throw error
  })
  if (existing && (!existing.isFile() || existing.isSymbolicLink())) throw new Error('codex-security: state-lock path must be a regular file')
  options.signal?.throwIfAborted()
  const db = new DatabaseSync(lockPath)
  let held = false
  try {
    db.exec('PRAGMA busy_timeout=0')
    const deadline = Date.now() + timeoutMs
    for (;;) {
      options.signal?.throwIfAborted()
      try {
        db.exec('BEGIN IMMEDIATE')
        held = true
        break
      } catch (error) {
        const value = error as { errcode?: number; code?: string }
        if (value.code !== 'ERR_SQLITE_ERROR' || ![5, 6].includes(value.errcode ?? -1)) throw error
        if (Date.now() >= deadline) throw new Error('codex-security: timed out waiting for the state lock')
        await delay(Math.min(25, Math.max(1, deadline - Date.now())), undefined, { signal: options.signal })
      }
    }
    let released = false
    return () => {
      if (released) return
      released = true
      try { db.exec('ROLLBACK') } finally { db.close() }
    }
  } catch (error) {
    if (held) { try { db.exec('ROLLBACK') } catch { /* close still releases the lock */ } }
    db.close()
    throw error
  }
}
