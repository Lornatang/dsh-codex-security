import { randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, writeFile as writeFileCallback } from 'node:fs';
import { link, lstat, mkdir, readdir, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep, toNamespacedPath } from 'node:path';
import { getSystemErrorName, promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { canonicalProspectivePath, isWithin } from './util.js';
const writeFile = promisify(writeFileCallback);
const require = createRequire(import.meta.url);
let koffi;
function getKoffi() {
    if (koffi)
        return koffi;
    try {
        return koffi = require('koffi');
    }
    catch (error) {
        throw new Error('codex-security: secure export requires native filesystem support for this platform', { cause: error });
    }
}
async function captureProtected(path) {
    const canonical = await canonicalProspectivePath(path);
    try {
        const info = await stat(canonical, { bigint: true });
        return { path, canonical, ...(info.isDirectory() ? { identity: { dev: info.dev, ino: info.ino } } : {}) };
    }
    catch (error) {
        if (error.code !== 'ENOENT')
            throw error;
        return { path, canonical };
    }
}
/** Reject links inside protected trees, which can alias external output paths. */
async function assertProtectedTreeHasNoLinks(root, existed, label) {
    const pending = [root];
    while (pending.length) {
        const directory = pending.pop();
        let entries, before, after;
        try {
            before = await lstat(directory, { bigint: true });
            if (!before.isDirectory() || before.isSymbolicLink())
                throw new Error('protected directory changed or is a link');
            entries = await readdir(directory, { withFileTypes: true });
            after = await lstat(directory, { bigint: true });
            if (!after.isDirectory() || before.dev !== after.dev || before.ino !== after.ino)
                throw new Error('protected directory changed');
        }
        catch (error) {
            if (!existed && directory === root && error.code === 'ENOENT')
                continue;
            throw new Error(`codex-security: cannot inspect ${label}`, { cause: error });
        }
        for (const entry of entries) {
            if (entry.isSymbolicLink())
                throw new Error(`codex-security: refusing to export while ${label} contains links`);
            if (entry.isDirectory())
                pending.push(join(directory, entry.name));
        }
    }
}
/** Re-resolve protected locations and retain their original directory identities. */
export async function createExportValidator(options) {
    const scan = await captureProtected(options.scanRoot);
    const git = await Promise.all(options.gitDirs.map(captureProtected));
    return async (output) => {
        if (/(?:^|[\\/])\.(?:git|hg|svn)(?:[\\/]|$)/i.test(options.requestedOutput) || /(?:^|[\\/])\.(?:git|hg|svn)(?:[\\/]|$)/i.test(output)) {
            throw new Error('codex-security: refusing to export into version-control metadata');
        }
        const scanPaths = [scan.canonical, await canonicalProspectivePath(scan.path)];
        const currentGitDirs = await options.resolveGitDirs?.() ?? [];
        const gitPaths = [...git.map((item) => item.canonical), ...await Promise.all([...git.map((item) => item.path), ...currentGitDirs].map(canonicalProspectivePath))];
        if ([scan.path, ...scanPaths].some((path) => isWithin(path, options.requestedOutput)) || scanPaths.some((path) => isWithin(path, output))) {
            throw new Error('codex-security: refusing to export into scan storage');
        }
        if ([...git.map((item) => item.path), ...currentGitDirs, ...gitPaths].some((path) => isWithin(path, options.requestedOutput)) || gitPaths.some((path) => isWithin(path, output))) {
            throw new Error('codex-security: refusing to export into version-control metadata');
        }
        await assertProtectedTreeHasNoLinks(scanPaths[1], !!scan.identity, 'scan storage');
        for (const path of new Set(gitPaths))
            await assertProtectedTreeHasNoLinks(path, false, 'version-control metadata');
        const identities = [scan, ...git].filter((item) => item.identity);
        for (let current = dirname(output); identities.length; current = dirname(current)) {
            try {
                const info = await stat(current, { bigint: true });
                const match = identities.find((item) => info.dev === item.identity.dev && info.ino === item.identity.ino);
                if (match)
                    throw new Error(match === scan ? 'codex-security: refusing to export into scan storage' : 'codex-security: refusing to export into version-control metadata');
            }
            catch (error) {
                if (!['ENOENT', 'ENOTDIR'].includes(error.code ?? ''))
                    throw error;
            }
            if (dirname(current) === current)
                break;
        }
        if (!options.allowOutside && !options.allowedRoots.some((root) => isWithin(root, output))) {
            throw new Error('codex-security: refusing to write outside the workspace/state dir; pass an in-workspace outputPath or enable allowExportOutsideWorkspace');
        }
    };
}
function posixFunctions() {
    const libc = getKoffi().load(null);
    if (!constants.O_DIRECTORY || !constants.O_NOFOLLOW)
        throw new Error('codex-security: secure export is unavailable on this platform');
    // Both APIs are variadic; Darwin ARM64 uses a different ABI for variadic arguments.
    const openat = libc.func('int openat(int, const char *, int, ...)');
    const fcntl = libc.func('int fcntl(int, int, ...)');
    return {
        openat: (parent, name, flags, mode) => openat(parent, name, flags, 'unsigned int', mode),
        mkdirat: libc.func('int mkdirat(int, const char *, unsigned int)'),
        linkat: libc.func('int linkat(int, const char *, int, const char *, int)'),
        unlinkat: libc.func('int unlinkat(int, const char *, int)'),
        fcntl: (fd, command, value) => fcntl(fd, command, 'int', value),
        ...(process.platform === 'darwin' ? { clonefileat: libc.func('int fclonefileat(int, int, const char *, int)') } : {}),
    };
}
function nativeError(operation) {
    const errno = getKoffi().errno();
    const error = new Error(`codex-security: ${operation} failed (errno ${errno})`);
    try {
        error.code = getSystemErrorName(-errno);
    }
    catch {
        error.code = 'EIO';
    }
    return error;
}
function directoryFlags() {
    // Search-only handles preserve exports through execute-only ancestors.
    const search = process.platform === 'linux' ? 0x200000 : process.platform === 'darwin' ? 0x40000000 : constants.O_RDONLY;
    return search | constants.O_DIRECTORY | constants.O_NOFOLLOW;
}
function assertDirectoriesCurrent(directories) {
    for (const directory of directories) {
        let info;
        try {
            info = lstatSync(directory.path, { bigint: true });
        }
        catch (error) {
            throw new Error('codex-security: export directory changed during export', { cause: error });
        }
        if (!info.isDirectory() || info.dev !== directory.dev || info.ino !== directory.ino) {
            throw new Error('codex-security: export directory changed during export');
        }
    }
}
function addPosixDirectory(directories, fd, path) {
    try {
        const info = fstatSync(fd, { bigint: true });
        if (!info.isDirectory())
            throw new Error('codex-security: export parent must be a directory');
        directories.push({ fd, path, dev: info.dev, ino: info.ino });
    }
    catch (error) {
        closeSync(fd);
        throw error;
    }
}
function openatDirectory(native, parent, name) {
    const fd = native.openat(parent, name, directoryFlags(), 0);
    if (fd < 0)
        throw nativeError('opening export directory');
    if (native.fcntl(fd, 2, 1) < 0) {
        const error = nativeError('securing export descriptor');
        closeSync(fd);
        throw error;
    }
    return fd;
}
async function validatePosix(directories, output, validate) {
    assertDirectoriesCurrent(directories);
    await validate(output);
    assertDirectoriesCurrent(directories);
}
async function writePosixFile(native, directories, name, options) {
    const parent = directories[directories.length - 1];
    const temporary = `.${process.pid}.${randomBytes(12).toString('hex')}.tmp`;
    const output = join(parent.path, name);
    const check = () => validatePosix(directories, output, options.validate);
    await check();
    const fd = native.openat(parent.fd, temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    if (fd < 0)
        throw nativeError('creating temporary export');
    try {
        if (native.fcntl(fd, 2, 1) < 0)
            throw nativeError('securing export descriptor');
        await writeFile(fd, options.content, 'utf8');
        await check();
        await options.onPhase?.('before-publish');
        await check();
        // Publish from the open file, never from the replaceable temporary name.
        // If the platform or filesystem cannot do that, create the final name
        // exclusively and write it directly instead.
        let published;
        if (process.platform === 'linux')
            published = native.linkat(-100, `/proc/self/fd/${fd}`, parent.fd, name, 0x400);
        else if (native.clonefileat)
            published = native.clonefileat(fd, parent.fd, name, 0);
        else
            published = -2;
        if (published < 0) {
            const error = published === -2 ? undefined : nativeError('publishing export');
            if (error && !['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EINVAL', 'EXDEV', 'ENOENT'].includes(error.code ?? ''))
                throw error;
            const destination = native.openat(parent.fd, name, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
            if (destination < 0)
                throw nativeError('creating export');
            try {
                if (native.fcntl(destination, 2, 1) < 0)
                    throw nativeError('securing export descriptor');
                await writeFile(destination, options.content, 'utf8');
            }
            finally {
                closeSync(destination);
            }
        }
        await check();
    }
    finally {
        closeSync(fd);
        await options.onPhase?.('before-cleanup');
        if (native.unlinkat(parent.fd, temporary, 0) < 0) {
            const error = nativeError('removing temporary export');
            if (error.code !== 'ENOENT')
                throw error;
        }
    }
    await check();
}
async function writePosix(options, output) {
    const native = posixFunctions();
    const targetDir = dirname(output);
    const parts = targetDir.split('/').filter(Boolean);
    const directories = [];
    try {
        addPosixDirectory(directories, openSync('/', directoryFlags()), '/');
        let firstMissing = parts.length;
        for (let index = 0; index < parts.length; index++) {
            const parent = directories[directories.length - 1];
            const path = join(parent.path, parts[index]);
            try {
                addPosixDirectory(directories, openatDirectory(native, parent.fd, parts[index]), path);
            }
            catch (error) {
                if (error.code !== 'ENOENT')
                    throw error;
                firstMissing = index;
                break;
            }
        }
        await options.onPhase?.('pinned');
        await validatePosix(directories, output, options.validate);
        for (let index = firstMissing; index < parts.length; index++) {
            const parent = directories[directories.length - 1];
            const name = parts[index];
            await options.onPhase?.('before-mkdir');
            await validatePosix(directories, output, options.validate);
            if (native.mkdirat(parent.fd, name, 0o700) < 0) {
                const error = nativeError('creating export directory');
                if (error.code !== 'EEXIST')
                    throw error;
            }
            addPosixDirectory(directories, openatDirectory(native, parent.fd, name), join(parent.path, name));
            await validatePosix(directories, output, options.validate);
        }
        for (let suffix = 0;; suffix++) {
            const filename = suffix ? `${options.scanId}-${suffix}.${options.extension}` : basename(output);
            try {
                await writePosixFile(native, directories, filename, options);
                return join(targetDir, filename);
            }
            catch (error) {
                if (error.code !== 'EEXIST')
                    throw error;
                if (options.requested)
                    throw new Error('codex-security: export destination already exists: ' + join(targetDir, filename), { cause: error });
            }
        }
    }
    finally {
        for (const directory of directories.reverse())
            closeSync(directory.fd);
    }
}
function windowsFunctions() {
    const kernel = getKoffi().load('kernel32.dll');
    return {
        create: kernel.func('void * __stdcall CreateFileW(const char16_t *, uint32_t, uint32_t, void *, uint32_t, uint32_t, void *)'),
        attributes: kernel.func('uint32_t __stdcall GetFileAttributesW(const char16_t *)'),
        close: kernel.func('int __stdcall CloseHandle(void *)'),
        lastError: kernel.func('uint32_t __stdcall GetLastError(void)'),
        mutex: kernel.func('void * __stdcall CreateMutexW(void *, int, const char16_t *)'),
        wait: kernel.func('uint32_t __stdcall WaitForSingleObject(void *, uint32_t)'),
        release: kernel.func('int __stdcall ReleaseMutex(void *)'),
        write: kernel.func('int __stdcall WriteFile(void *, const void *, uint32_t, _Out_ uint32_t *, void *)'),
    };
}
function invalidHandle(value) { return value === -1n || value === 0xffffffffffffffffn || value === 0xffffffffn; }
async function writeWindowsBytes(native, handle, data) {
    for (let offset = 0; offset < data.length;) {
        const chunk = data.subarray(offset, Math.min(offset + 1024 * 1024, data.length));
        const written = [0];
        if (!native.write(handle, chunk, chunk.length, written, null) || !written[0]) {
            throw new Error(`codex-security: cannot write export (${native.lastError()})`);
        }
        offset += written[0];
        if (offset < data.length)
            await delay(0);
    }
}
async function writeWindowsFile(native, path, options) {
    const temporary = join(dirname(path), `.${process.pid}.${randomBytes(12).toString('hex')}.tmp`);
    await options.validate(path);
    // DELETE_ON_CLOSE removes our own file by handle; the sharing mode prevents
    // a concurrent process from renaming, replacing or modifying the stage.
    const stage = native.create(toNamespacedPath(temporary), 0xc0010000, 1, null, 1, 0x04000080, null);
    if (!stage || invalidHandle(stage))
        throw new Error(`codex-security: cannot create temporary export (${native.lastError()})`);
    try {
        const data = Buffer.from(options.content, 'utf8');
        await writeWindowsBytes(native, stage, data);
        await options.validate(path);
        await options.onPhase?.('before-publish');
        await options.validate(path);
        try {
            await link(temporary, path);
        }
        catch (error) {
            if (!['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS'].includes(error.code ?? ''))
                throw error;
            const destination = native.create(toNamespacedPath(path), 0x40000000, 1, null, 1, 0x80, null);
            if (!destination || invalidHandle(destination)) {
                const code = native.lastError();
                const failure = new Error(`codex-security: cannot create export (${code})`);
                if (code === 80 || code === 183)
                    failure.code = 'EEXIST';
                throw failure;
            }
            try {
                await writeWindowsBytes(native, destination, data);
            }
            finally {
                native.close(destination);
            }
        }
        await options.validate(path);
        await options.onPhase?.('before-cleanup');
    }
    finally {
        native.close(stage);
    }
    await options.validate(path);
}
async function acquireWindowsExportLock(native) {
    // Win32 mutexes are reentrant on the same thread, so serialize local calls
    // separately even if multiple copies of the package are loaded.
    const key = Symbol.for('@lornatang/dsh-codex-security/export-queue');
    const globals = globalThis;
    const queue = globals[key] ??= { tail: Promise.resolve() };
    const previous = queue.tail;
    let releaseQueue;
    const held = new Promise((resolve) => { releaseQueue = resolve; });
    queue.tail = previous.then(() => held);
    await previous;
    let handle;
    let acquired = false;
    try {
        handle = native.mutex(null, 0, 'Global\\dsh-codex-security-export-v1');
        if (!handle || invalidHandle(handle))
            throw new Error(`codex-security: cannot acquire export lock (${native.lastError()})`);
        const deadline = Date.now() + 30000;
        for (;;) {
            const status = native.wait(handle, 0);
            if (status === 0 || status === 0x80) {
                acquired = true;
                break;
            }
            if (status !== 0x102)
                throw new Error(`codex-security: cannot acquire export lock (${native.lastError()})`);
            if (Date.now() >= deadline)
                throw new Error('codex-security: timed out waiting for another export');
            await delay(25);
        }
        const owned = handle;
        return () => {
            try {
                native.release(owned);
            }
            finally {
                try {
                    native.close(owned);
                }
                finally {
                    releaseQueue();
                }
            }
        };
    }
    catch (error) {
        if (handle && !invalidHandle(handle)) {
            if (acquired)
                native.release(handle);
            native.close(handle);
        }
        releaseQueue();
        throw error;
    }
}
function pinWindowsDirectory(native, path, share = 1) {
    // FILE_TRAVERSE enforces sharing restrictions without requiring directory listing.
    const windowsPath = toNamespacedPath(path);
    const handle = native.create(windowsPath, 0x20, share, null, 3, 0x02200000, null);
    if (invalidHandle(handle)) {
        const code = native.lastError();
        if (code === 2 || code === 3)
            return undefined;
        throw new Error(`codex-security: cannot secure export directory (${code}): ${path}`);
    }
    const attributes = native.attributes(windowsPath);
    if (attributes === 0xffffffff || !(attributes & 0x10) || (attributes & 0x400)) {
        native.close(handle);
        throw new Error('codex-security: export directory changed or contains a reparse point: ' + path);
    }
    return handle;
}
async function writeWindows(options, output) {
    const native = windowsFunctions();
    const releaseLock = await acquireWindowsExportLock(native);
    const targetDir = dirname(output);
    const root = parse(targetDir).root;
    const components = relative(root, targetDir).split(sep).filter(Boolean);
    const guards = [];
    let sentinel;
    try {
        const rootHandle = pinWindowsDirectory(native, root);
        if (rootHandle === undefined)
            throw new Error('codex-security: export volume is unavailable');
        guards.push({ path: root, handle: rootHandle });
        let firstMissing = components.length;
        for (let index = 0; index < components.length; index++) {
            const path = resolve(guards[guards.length - 1].path, components[index]);
            const handle = pinWindowsDirectory(native, path);
            if (handle === undefined) {
                firstMissing = index;
                break;
            }
            guards.push({ path, handle });
        }
        await options.onPhase?.('pinned');
        await options.validate(output);
        for (let index = firstMissing; index < components.length; index++) {
            const path = resolve(guards[guards.length - 1].path, components[index]);
            await options.onPhase?.('before-mkdir');
            await options.validate(output);
            try {
                await mkdir(path, { mode: 0o700 });
            }
            catch (error) {
                if (error.code !== 'EEXIST')
                    throw error;
            }
            const handle = pinWindowsDirectory(native, path);
            if (handle === undefined)
                throw new Error('codex-security: export directory changed during creation');
            guards.push({ path, handle });
            await options.validate(output);
        }
        // A non-deletable child keeps the final directory nonempty, preventing it
        // from becoming a reparse point while write-sharing is enabled for link().
        const sentinelPath = join(targetDir, `.codex-export-${randomBytes(12).toString('hex')}.lock`);
        sentinel = native.create(toNamespacedPath(sentinelPath), 0x80010000, 3, null, 1, 0x04000080, null);
        if (invalidHandle(sentinel)) {
            sentinel = undefined;
            throw new Error('codex-security: cannot secure export directory');
        }
        for (const guard of guards) {
            const upgraded = pinWindowsDirectory(native, guard.path, 3);
            if (upgraded === undefined)
                throw new Error('codex-security: export directory changed while securing it');
            native.close(guard.handle);
            guard.handle = upgraded;
        }
        for (let suffix = 0;; suffix++) {
            const filename = suffix ? `${options.scanId}-${suffix}.${options.extension}` : basename(output);
            const path = join(targetDir, filename);
            try {
                await writeWindowsFile(native, path, options);
                return path;
            }
            catch (error) {
                if (error.code !== 'EEXIST')
                    throw error;
                if (options.requested)
                    throw new Error('codex-security: export destination already exists: ' + path, { cause: error });
            }
        }
    }
    finally {
        try {
            if (sentinel !== undefined)
                native.close(sentinel);
            for (const guard of guards.reverse())
                native.close(guard.handle);
        }
        finally {
            releaseLock();
        }
    }
}
/** Pin the output directory object before applying policy or mutating the tree. */
export async function writeSecureExport(options) {
    const output = await canonicalProspectivePath(options.requestedOutput);
    if (!isAbsolute(output))
        throw new Error('codex-security: export path must be absolute');
    return process.platform === 'win32' ? writeWindows(options, output) : writePosix(options, output);
}
