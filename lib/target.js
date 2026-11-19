import { lstat, realpath, stat } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { isProbablyBinary, isWithin, joinWithin, languageOf, listFiles, matchesAny, matchesScopePath, normalizeLine, sanitizeRelative, stableTargetId, truncate } from './util.js';
import { changedFiles, currentBranch, fileDigest, headRevision, remoteUrl, repoRoot, resolveRevision, revisionFilePrefix, statusEntries, trackedFiles } from './git.js';
const DEFAULT_EXCLUDES = ['.git/**', 'node_modules/**', 'dist/**', 'build/**', 'out/**', 'coverage/**', '.next/**', '.nuxt/**', 'vendor/**', 'target/**', '.venv/**', '__pycache__/**', '*.min.js', '*.min.css', '*.map', '*.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'composer.lock', 'go.sum'];
export async function resolveTarget(options) {
    options.signal?.throwIfAborted();
    const requestedPath = resolve(options.targetPath && options.targetPath.length > 0 ? options.targetPath : process.cwd());
    const targetStat = await stat(requestedPath).catch(() => undefined);
    if (!targetStat?.isDirectory())
        throw new Error('codex-security: targetPath must be an existing directory: ' + requestedPath);
    const requested = await realpath(requestedPath);
    const repo = await repoRoot(requested, options.signal);
    if (!repo) {
        if (process.env['GIT_DIR'] !== undefined || process.env['GIT_COMMON_DIR'] !== undefined)
            throw new Error('codex-security: cannot resolve configured Git metadata');
        for (let directory = requested;; directory = dirname(directory)) {
            try {
                await lstat(join(directory, '.git'));
                throw new Error('codex-security: cannot resolve Git metadata at ' + directory);
            }
            catch (error) {
                if (!['ENOENT', 'ENOTDIR'].includes(error.code ?? ''))
                    throw error;
            }
            if (dirname(directory) === directory)
                break;
        }
    }
    const rootPath = repo ?? requested;
    const gitRepo = repo !== undefined;
    const requestedIncludes = (options.includePaths ?? []).map((value) => value.trim()).filter(Boolean);
    const subdir = gitRepo ? relative(rootPath, requested).split(sep).join('/') : '';
    let includePaths = requestedIncludes;
    if (subdir) {
        includePaths = requestedIncludes.length === 0 ? [subdir] : requestedIncludes.map((pattern) => {
            const clean = pattern.replace(/^\.\//, '').replace(/\/$/, '');
            if (!clean || clean === '.')
                return subdir;
            if (clean !== subdir && !clean.startsWith(subdir + '/'))
                throw new Error('codex-security: includePaths must stay within targetPath: ' + pattern);
            return clean;
        });
    }
    const excludePaths = (options.excludePaths ?? []).map((value) => value.trim()).filter(Boolean);
    const scope = { includePaths: includePaths.length > 0 ? includePaths : ['.'], excludePaths };
    const warnings = [];
    const status = gitRepo ? await statusEntries(rootPath, options.signal) : [];
    const dirty = status.length > 0;
    const revision = gitRepo ? await headRevision(rootPath, options.signal) : undefined;
    const baseRevision = options.diffTarget ? await resolveRevision(rootPath, options.diffTarget, options.signal) : undefined;
    if (options.diffTarget && !baseRevision)
        throw new Error('codex-security: diff target could not be resolved: ' + options.diffTarget);
    if (!gitRepo && (options.diffTarget || options.workingTree))
        throw new Error('codex-security: diff scans require a git repository');
    let kind = 'directory_snapshot';
    if (gitRepo)
        kind = options.diffTarget || options.workingTree ? 'git_diff' : 'git_worktree';
    const diff = kind === 'git_diff' ? await resolveDiff(rootPath, { diffTarget: baseRevision, workingTree: options.workingTree === true, head: revision, signal: options.signal }) : undefined;
    const diffFiles = diff?.files.filter((file) => (matchesScopePath(file.path, scope.includePaths) || (file.oldPath !== undefined && matchesScopePath(file.oldPath, scope.includePaths))) &&
        !matchesAny(file.path, excludePaths));
    const changedPaths = diffFiles ? new Set(diffFiles.map((file) => file.path)) : undefined;
    const inventoryFiles = await collectFiles(rootPath, options, includePaths, excludePaths, gitRepo, changedPaths);
    const files = inventoryFiles.files;
    for (const path of inventoryFiles.symlinks ?? [])
        warnings.push('inventory omitted symbolic link: ' + path);
    if (files.length === 0)
        warnings.push('no reviewable text files matched the requested scope');
    if (inventoryFiles.truncated)
        warnings.push('inventory truncated at maxFiles=' + options.maxFiles);
    let totalBytes = 0;
    const languages = {};
    for (const file of files) {
        options.signal?.throwIfAborted();
        try {
            const info = await stat(resolve(rootPath, file));
            totalBytes += info.size;
        }
        catch { /* file disappeared between listing and stat */ }
        const language = languageOf(file);
        languages[language] = (languages[language] ?? 0) + 1;
    }
    const snapshot = createHash('sha256');
    snapshot.update(JSON.stringify({ kind, revision: revision ?? null, baseRevision: baseRevision ?? null, diffFiles: diffFiles ?? null }));
    // Commit-only diffs are bound to immutable revisions; working-tree and
    // directory scans must also bind the actual content being reviewed.
    if (kind !== 'git_diff' || options.workingTree) {
        for (const file of [...files].sort()) {
            const absolute = resolve(rootPath, file);
            const info = await lstat(absolute).catch(() => undefined);
            const digest = info?.isFile() ? await fileDigest(absolute, options.signal) : undefined;
            if (!digest)
                warnings.push('snapshot could not hash file: ' + file);
            snapshot.update('\u0000' + file + '\u0000' + (digest ?? 'unavailable'));
        }
    }
    const snapshotDigest = 'codex-security-snapshot/v1:sha256:' + snapshot.digest('hex');
    const targetId = stableTargetId(rootPath);
    const remoteValue = gitRepo ? await remoteUrl(rootPath, options.signal) : undefined;
    const remote = remoteValue ? safeRemote(remoteValue) : undefined;
    const branch = gitRepo ? await currentBranch(rootPath, options.signal) : undefined;
    const target = {
        kind,
        targetId,
        displayName: displayNameFor(rootPath, remote),
        rootPath,
        snapshotDigest,
        dirty,
        ...(remote ? { remote } : {}),
        ...(revision ? { revision } : {}),
        ...(branch ? { branch } : {}),
        ...(options.diffTarget ? { diffTarget: options.diffTarget } : {}),
        ...(options.workingTree ? { workingTree: true } : {}),
        ...(baseRevision ? { baseRevision } : {}),
        ...(revision ? { headRevision: revision } : {}),
    };
    const sample = files.slice(0, 200);
    const inventory = {
        totalFiles: files.length,
        inspectedFiles: files.length,
        totalBytes,
        languages,
        sample,
        excluded: DEFAULT_EXCLUDES,
        truncated: inventoryFiles.truncated,
    };
    return { target, scope, inventory, files, warnings, ...(diffFiles ? { diffFiles } : {}) };
}
function safeRemote(value) {
    try {
        if (value.includes('://')) {
            const url = new URL(value);
            url.username = '';
            url.password = '';
            url.search = '';
            url.hash = '';
            return url.toString();
        }
        return value.split(/[?#]/, 1)[0] || undefined;
    }
    catch {
        return undefined;
    }
}
async function collectFiles(rootPath, options, includePaths, excludePaths, gitRepo, changedPaths) {
    const exclude = [...DEFAULT_EXCLUDES, ...excludePaths];
    if (gitRepo) {
        const tracked = await trackedFiles(rootPath, options.signal);
        const status = await statusEntries(rootPath, options.signal);
        const untracked = status.filter((entry) => entry.code === '??').map((entry) => entry.path);
        const all = Array.from(new Set([...tracked, ...untracked]));
        let scoped = all.filter((path) => !matchesAny(path, exclude));
        if (changedPaths)
            scoped = scoped.filter((path) => changedPaths.has(path));
        if (includePaths.length > 0 && !(includePaths.length === 1 && (includePaths[0] === '.' || includePaths[0] === './'))) {
            scoped = scoped.filter((path) => matchesScopePath(path, includePaths));
        }
        scoped = scoped.filter((path) => !isProbablyBinary(path));
        return { files: scoped.slice(0, options.maxFiles), truncated: scoped.length > options.maxFiles };
    }
    return listFiles(rootPath, { maxFiles: options.maxFiles, exclude, include: includePaths.filter((value) => value !== '.' && value !== './').length > 0 ? includePaths : undefined, filter: (path) => !isProbablyBinary(path), signal: options.signal });
}
function displayNameFor(rootPath, remote) {
    if (remote) {
        const cleaned = remote.replace(/\.git$/, '').replace(/^[a-z]+:\/\//, '').replace(/^git@([^:]+):/, '$1/');
        const parts = cleaned.split('/').filter(Boolean);
        if (parts.length >= 2)
            return parts.slice(-2).join('/');
    }
    const name = basename(rootPath);
    return name.length > 0 ? name : rootPath;
}
export async function resolveDiff(rootPath, options) {
    const head = options.head ?? await headRevision(rootPath, options.signal);
    const files = await changedFiles(rootPath, { base: options.diffTarget, head, staged: options.staged, workingTree: options.workingTree, signal: options.signal });
    return { files, ...(options.diffTarget ? { base: options.diffTarget } : {}), ...(head ? { head } : {}), workingTree: options.workingTree === true || (!options.diffTarget && !options.staged) };
}
/** Read one source line for anchor derivation without trusting it as instructions. */
export async function readEvidenceLine(source, path, line, maxBytes) {
    if (!Number.isFinite(line) || line < 1)
        return undefined;
    const lines = await readEvidenceFileLines(source, path, maxBytes);
    if (!lines)
        return undefined;
    const value = lines[Math.trunc(line) - 1];
    return value === undefined ? undefined : truncate(normalizeLine(value), 400);
}
/**
 * Read many evidence lines with one hardened open per source file. The old
 * per-line reader repeated the lstat/open/realpath verification and re-read the
 * file prefix for every requested line, so a draft citing several lines of one
 * file paid that cost repeatedly.
 */
export async function readEvidenceLines(source, requests, maxBytes) {
    const byPath = new Map();
    for (const request of requests) {
        if (!Number.isFinite(request.line) || request.line < 1)
            continue;
        const line = Math.trunc(request.line);
        const bucket = byPath.get(request.path);
        if (bucket) {
            if (!bucket.includes(line))
                bucket.push(line);
        }
        else
            byPath.set(request.path, [line]);
    }
    const result = new Map();
    const groups = [...byPath.entries()];
    const concurrency = 8;
    for (let index = 0; index < groups.length; index += concurrency) {
        await Promise.all(groups.slice(index, index + concurrency).map(async ([path, lineNumbers]) => {
            const lines = await readEvidenceFileLines(source, path, maxBytes);
            if (!lines)
                return;
            for (const line of lineNumbers) {
                const value = lines[line - 1];
                if (value !== undefined)
                    result.set(path + ':' + line, truncate(normalizeLine(value), 400));
            }
        }));
    }
    return result;
}
/** Hardened single-file read shared by the line readers. */
async function readEvidenceFileLines(source, path, maxBytes) {
    const maxPrefixBytes = Math.trunc(Math.min(maxBytes, 256 * 1024));
    if (typeof source !== 'string' && source.kind === 'git_diff' && !source.workingTree) {
        const revision = source.headRevision ?? source.revision;
        if (!revision)
            return undefined;
        let clean;
        try {
            clean = sanitizeRelative(path);
        }
        catch {
            return undefined;
        }
        const prefix = await revisionFilePrefix(source.rootPath, revision, clean, maxPrefixBytes);
        return prefix?.toString('utf8').split('\n');
    }
    const rootPath = typeof source === 'string' ? source : source.rootPath;
    const { open } = await import('node:fs/promises');
    const { constants } = await import('node:fs');
    if (typeof path !== 'string' || path.length === 0)
        return undefined;
    let absolute;
    try {
        absolute = joinWithin(rootPath, path);
    }
    catch {
        return undefined;
    }
    const realRoot = await realpath(rootPath).catch(() => undefined);
    if (!realRoot)
        return undefined;
    let handle;
    try {
        const before = await lstat(absolute).catch(() => undefined);
        if (!before || !before.isFile())
            return undefined;
        const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
        handle = await open(absolute, flags);
        const opened = await handle.stat();
        if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
            return undefined;
        // Parent directories are not covered by O_NOFOLLOW, so a symlinked parent
        // could still redirect the read outside the target. Resolve the opened
        // path and require it to stay inside the real target root and to still
        // name the inode we actually opened.
        const canonical = await realpath(absolute).catch(() => undefined);
        if (!canonical || !isWithin(realRoot, canonical))
            return undefined;
        const current = await lstat(canonical).catch(() => undefined);
        if (!current || !current.isFile() || current.dev !== opened.dev || current.ino !== opened.ino || current.size !== opened.size)
            return undefined;
        const buffer = Buffer.alloc(maxPrefixBytes);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        return buffer.subarray(0, bytesRead).toString('utf8').split('\n');
    }
    catch {
        return undefined;
    }
    finally {
        await handle?.close().catch(() => undefined);
    }
}
