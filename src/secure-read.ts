import { createHash } from 'node:crypto'
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { isAbsolute, parse, relative, resolve, sep, toNamespacedPath } from 'node:path'
import { setImmediate as yieldEventLoop } from 'node:timers/promises'

const require = createRequire(import.meta.url)
interface NativeLibrary { func(signature: string): unknown }
interface NativeApi { version: string; load(name: string | null): NativeLibrary; errno(): number }
type Identity = { dev: bigint; ino: bigint }

function nativeApi(): NativeApi {
  try {
    const value = require(`@koromix/koffi-${process.platform}-${process.arch}`) as NativeApi
    if (value.version !== '3.3.8' || typeof value.load !== 'function') throw new Error('incompatible native module')
    return value
  } catch (error) {
    throw new Error('codex-security: secure worker reads require native filesystem support', { cause: error })
  }
}

/** Require an exact portable relative path; never normalize away traversal. */
export function workerSourcePath(value: string): string {
  if (typeof value !== 'string' || !value || isAbsolute(value) || value.includes('\\') || value.includes('\0')) throw new Error('codex-security: invalid worker source path')
  const parts = value.split('/')
  if (parts.some((part) => !part || part === '.' || part === '..')) throw new Error('codex-security: invalid worker source path')
  if (process.platform === 'win32' && parts.some((part) => part.includes(':') || /[. ]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
    throw new Error('codex-security: invalid worker source path')
  }
  return parts.join('/')
}

export function sourceRootIdentity(root: string): { path: string; identity: Identity } {
  const path = realpathSync(root)
  const info = statSync(path, { bigint: true })
  if (!info.isDirectory()) throw new Error('codex-security: worker target must be a directory')
  return { path, identity: { dev: info.dev, ino: info.ino } }
}

function assertIdentity(value: Identity, expected: Identity): void {
  if (value.dev !== expected.dev || value.ino !== expected.ino) throw new Error('codex-security: worker target directory changed')
}

function validateContent(data: Buffer, expectedHash?: string): Buffer {
  if (expectedHash && createHash('sha256').update(data).digest('hex') !== expectedHash) throw new Error('codex-security: worker source changed since snapshot')
  return data
}

interface PinnedFile { read(block: Buffer): number; verify(): void; close(): void; size?: bigint }

function openPosix(root: string, source: string, rootIdentity: Identity): PinnedFile {
  const api = nativeApi()
  if (!constants.O_DIRECTORY || !constants.O_NOFOLLOW) throw new Error('codex-security: secure worker reads are unavailable')
  const rawOpenat = api.load(null).func('int openat(int, const char *, int, ...)') as (fd: number, path: string, flags: number, type: string, mode: number) => number
  const flags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  const paths: Array<{ path: string; fd: number; identity: Identity }> = []
  const fds: number[] = []
  const volume = parse(root).root
  const close = (): void => { for (const fd of fds.reverse()) { try { closeSync(fd) } catch { /* Continue closing remaining handles. */ } }; fds.length = 0 }
  try {
    let fd = openSync(volume, flags)
    fds.push(fd)
    const volumeInfo = fstatSync(fd, { bigint: true })
    paths.push({ path: volume, fd, identity: { dev: volumeInfo.dev, ino: volumeInfo.ino } })
    let current = volume
    for (const component of relative(volume, root).split(sep).filter(Boolean)) {
      current = resolve(current, component)
      fd = rawOpenat(fd, component, flags, 'unsigned int', 0)
      if (fd < 0) throw new Error('codex-security: secure worker directory open failed (errno ' + api.errno() + ')')
      fds.push(fd)
      const info = fstatSync(fd, { bigint: true })
      if (!info.isDirectory()) throw new Error('codex-security: worker source parent is not a directory')
      paths.push({ path: current, fd, identity: { dev: info.dev, ino: info.ino } })
    }
    assertIdentity(paths[paths.length - 1]!.identity, rootIdentity)
    const parts = source.split('/')
    for (const component of parts.slice(0, -1)) {
      current = resolve(current, component)
      fd = rawOpenat(fd, component, flags, 'unsigned int', 0)
      if (fd < 0) throw new Error('codex-security: secure worker directory open failed (errno ' + api.errno() + ')')
      fds.push(fd)
      const info = fstatSync(fd, { bigint: true })
      if (!info.isDirectory()) throw new Error('codex-security: worker source parent is not a directory')
      paths.push({ path: current, fd, identity: { dev: info.dev, ino: info.ino } })
    }
    const file = rawOpenat(fd, parts[parts.length - 1]!, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK, 'unsigned int', 0)
    if (file < 0) throw new Error('codex-security: secure worker file open failed (errno ' + api.errno() + ')')
    fds.push(file)
    const before = fstatSync(file, { bigint: true })
    if (!before.isFile()) throw new Error('codex-security: worker source is not a regular file')
    return { size: before.size, close,
      read: (block) => readSync(file, block, 0, block.length, null),
      verify: () => {
        const after = fstatSync(file, { bigint: true })
        if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error('codex-security: worker source changed while reading')
        for (const directory of paths) {
          const currentInfo = lstatSync(directory.path, { bigint: true })
          if (!currentInfo.isDirectory() || currentInfo.isSymbolicLink()) throw new Error('codex-security: worker source directory changed')
          assertIdentity(currentInfo, directory.identity)
        }
      } }
  } catch (error) { close(); throw error }
}

interface WindowsApi {
  create(path: string, access: number, share: number, security: null, disposition: number, flags: number, template: null): bigint
  attributes(path: string): number
  close(handle: bigint): number
  lastError(): number
  read(handle: bigint, buffer: Buffer, size: number, read: number[], overlapped: null): number
}

function openWindows(root: string, source: string, rootIdentity: Identity): PinnedFile {
  const kernel = nativeApi().load('kernel32.dll')
  const native: WindowsApi = {
    create: kernel.func('void * __stdcall CreateFileW(const char16_t *, uint32_t, uint32_t, void *, uint32_t, uint32_t, void *)') as WindowsApi['create'],
    attributes: kernel.func('uint32_t __stdcall GetFileAttributesW(const char16_t *)') as WindowsApi['attributes'],
    close: kernel.func('int __stdcall CloseHandle(void *)') as WindowsApi['close'],
    lastError: kernel.func('uint32_t __stdcall GetLastError(void)') as WindowsApi['lastError'],
    read: kernel.func('int __stdcall ReadFile(void *, void *, uint32_t, _Out_ uint32_t *, void *)') as WindowsApi['read'],
  }
  const handles: bigint[] = []
  const close = (): void => { for (const handle of handles.reverse()) native.close(handle); handles.length = 0 }
  const invalid = (handle: bigint): boolean => !handle || handle === -1n || handle === 0xffffffffffffffffn || handle === 0xffffffffn
  const pinDirectory = (path: string): void => {
    const name = toNamespacedPath(path)
    const handle = native.create(name, 0x20, 1, null, 3, 0x02200000, null)
    if (invalid(handle)) throw new Error('codex-security: secure worker directory open failed (' + native.lastError() + ')')
    handles.push(handle)
    const attr = native.attributes(name)
    if (attr === 0xffffffff || !(attr & 0x10) || (attr & 0x400)) throw new Error('codex-security: worker source directory is a reparse point or changed')
  }
  const volume = parse(root).root
  try {
    pinDirectory(volume)
    let current = volume
    for (const component of relative(volume, root).split(sep).filter(Boolean)) { current = resolve(current, component); pinDirectory(current) }
    assertIdentity(statSync(root, { bigint: true }), rootIdentity)
    const parts = source.split('/')
    for (const component of parts.slice(0, -1)) { current = resolve(current, component); pinDirectory(current) }
    const path = toNamespacedPath(resolve(current, parts[parts.length - 1]!))
    const handle = native.create(path, 0x80000000, 1, null, 3, 0x00200080, null)
    if (invalid(handle)) throw new Error('codex-security: secure worker file open failed (' + native.lastError() + ')')
    handles.push(handle)
    const attributes = native.attributes(path)
    if (attributes === 0xffffffff || (attributes & 0x10) || (attributes & 0x400)) throw new Error('codex-security: worker source file is a reparse point or changed')
    return { close,
      read: (block) => {
        const read = [0]
        if (!native.read(handle, block, block.length, read, null)) throw new Error('codex-security: secure worker read failed (' + native.lastError() + ')')
        return read[0] ?? 0
      },
      verify: () => assertIdentity(statSync(root, { bigint: true }), rootIdentity) }
  } catch (error) { close(); throw error }
}

/** Read through pinned handles, then verify the exact bytes against the bound snapshot. */
export function readWorkerSource(root: string, path: string, maxBytes: number, identity: Identity, expectedHash?: string): Buffer {
  const source = workerSourcePath(path)
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error('codex-security: invalid worker source size limit')
  const file = process.platform === 'win32' ? openWindows(root, source, identity) : openPosix(root, source, identity)
  try {
    if (file.size !== undefined && file.size > BigInt(maxBytes)) throw new Error('codex-security: worker source exceeds the size limit')
    const pieces: Buffer[] = []
    let total = 0
    for (;;) {
      const block = Buffer.alloc(Math.min(65536, maxBytes - total + 1))
      const count = file.read(block)
      if (!count) break
      total += count
      if (total > maxBytes) throw new Error('codex-security: worker source exceeds the size limit')
      pieces.push(block.subarray(0, count))
    }
    file.verify()
    return validateContent(Buffer.concat(pieces), expectedHash)
  } finally { file.close() }
}

/** Hash oversized files through the same pinned handles without exposing their contents. */
export async function digestWorkerSource(root: string, path: string, identity: Identity, signal?: AbortSignal): Promise<string> {
  const source = workerSourcePath(path)
  signal?.throwIfAborted()
  const file = process.platform === 'win32' ? openWindows(root, source, identity) : openPosix(root, source, identity)
  try {
    const hash = createHash('sha256')
    let blocks = 0
    for (;;) {
      signal?.throwIfAborted()
      const block = Buffer.alloc(65536)
      const count = file.read(block)
      if (!count) break
      hash.update(block.subarray(0, count))
      if (++blocks % 16 === 0) await yieldEventLoop()
    }
    signal?.throwIfAborted()
    file.verify()
    return hash.digest('hex')
  } finally { file.close() }
}
