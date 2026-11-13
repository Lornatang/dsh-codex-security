import { stat } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { ensureDir, isProbablyBinary, languageOf, listFiles, matchesAny, normalizeLine, sha256, truncate } from './util.js';
import { changedFiles, currentBranch, headRevision, remoteUrl, repoRoot, resolveRevision, statusEntries, trackedFiles, worktreeDigest } from './git.js';
const DEFAULT_EXCLUDES = ['.git/**', 'node_modules/**', 'dist/**', 'build/**', 'out/**', 'coverage/**', '.next/**', '.nuxt/**', 'vendor/**', 'target/**', '.venv/**', '__pycache__/**', '*.min.js', '*.min.css', '*.map', '*.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'composer.lock', 'go.sum'];
const LOCKFILES = new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'composer.lock', 'go.sum']);
export async function resolveTarget(options) {
    const requested = resolve(options.targetPath && options.targetPath.length > 0 ? options.targetPath : process.cwd());
    const repo = await repoRoot(requested);
    const rootPath = repo ?? requested;
    await ensureDir(rootPath);
    const gitRepo = repo !== undefined;
    const includePaths = (options.includePaths ?? []).map((value) => value.trim()).filter(Boolean);
    const excludePaths = (options.excludePaths ?? []).map((value) => value.trim()).filter(Boolean);
    const scope = { includePaths: includePaths.length > 0 ? includePaths : ['.'], excludePaths };
    const warnings = [];
    const status = gitRepo ? await statusEntries(rootPath) : [];
    const dirty = status.length > 0;
    const revision = gitRepo ? await headRevision(rootPath) : undefined;
    const baseRevision = options.diffTarget ? await resolveRevision(rootPath, options.diffTarget) : undefined;
    if (options.diffTarget && !baseRevision)
        warnings.push('diff target could not be resolved: ' + options.diffTarget);
    let kind = 'directory_snapshot';
    if (gitRepo)
        kind = options.diffTarget || options.workingTree ? 'git_diff' : 'git_worktree';
    if (!gitRepo && options.diffTarget)
        warnings.push('diff scans require a git repository; falling back to a directory snapshot');
    const files = (await collectFiles(rootPath, options, includePaths, excludePaths, gitRepo)).filter((path) => !isProbablyBinary(path));
    if (files.length === 0)
        warnings.push('no reviewable text files matched the requested scope');
    if (files.length >= options.maxFiles)
        warnings.push('inventory truncated at maxFiles=' + options.maxFiles);
    let totalBytes = 0;
    const languages = {};
    const sizes = new Map();
    for (const file of files) {
        try {
            const info = await stat(resolve(rootPath, file));
            totalBytes += info.size;
            sizes.set(file, info.size);
        }
        catch { /* file disappeared between listing and stat */ }
        const language = languageOf(file);
        languages[language] = (languages[language] ?? 0) + 1;
    }
    let snapshotDigest;
    if (gitRepo && revision) {
        const digest = options.diffTarget || options.workingTree ? await worktreeDigest(rootPath) : sha256('clean:' + revision);
        snapshotDigest = 'codex-security-snapshot/v1:sha256:' + digest;
    }
    else {
        const hash = sha256(files.map((file) => file + '\u0000' + (sizes.get(file) ?? 0)).join('\n') + '\u0000' + totalBytes);
        snapshotDigest = 'codex-security-snapshot/v1:sha256:' + hash;
    }
    const targetId = 'target_' + sha256(kind + '\u0000' + rootPath + '\u0000' + (revision ?? '') + '\u0000' + (options.diffTarget ?? '')).slice(0, 24);
    const target = {
        kind,
        targetId,
        displayName: displayNameFor(rootPath, gitRepo ? await remoteUrl(rootPath) : undefined),
        rootPath,
        snapshotDigest,
        dirty,
        ...(gitRepo ? { remote: await remoteUrl(rootPath) } : {}),
        ...(revision ? { revision } : {}),
        ...(gitRepo ? { branch: await currentBranch(rootPath) } : {}),
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
        truncated: files.length >= options.maxFiles,
    };
    return { target, scope, inventory, files, warnings };
}
async function collectFiles(rootPath, options, includePaths, excludePaths, gitRepo) {
    const exclude = [...DEFAULT_EXCLUDES, ...excludePaths];
    if (gitRepo) {
        const tracked = await trackedFiles(rootPath);
        const status = await statusEntries(rootPath);
        const untracked = status.filter((entry) => entry.code === '??').map((entry) => entry.path);
        const all = Array.from(new Set([...tracked, ...untracked]));
        let scoped = all.filter((path) => !matchesAny(path, exclude));
        if (includePaths.length > 0 && !(includePaths.length === 1 && (includePaths[0] === '.' || includePaths[0] === './'))) {
            scoped = scoped.filter((path) => includePaths.some((pattern) => path === pattern || path.startsWith(pattern.replace(/\/$/, '') + '/') || matchesAny(path, [pattern])));
        }
        return scoped.slice(0, options.maxFiles);
    }
    const listed = await listFiles(rootPath, { maxFiles: options.maxFiles, exclude, include: includePaths.filter((value) => value !== '.' && value !== './').length > 0 ? includePaths : undefined });
    return listed.files;
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
    const head = await headRevision(rootPath);
    const files = await changedFiles(rootPath, { base: options.diffTarget, staged: options.staged, workingTree: options.workingTree });
    return { files, base: options.diffTarget, head, workingTree: options.workingTree === true || (!options.diffTarget && !options.staged) };
}
/** Read one source line for anchor derivation without trusting it as instructions. */
export async function readEvidenceLine(rootPath, path, line, maxBytes) {
    const { open } = await import('node:fs/promises');
    if (!Number.isFinite(line) || line < 1)
        return undefined;
    const absolute = resolve(rootPath, path);
    let handle;
    try {
        handle = await open(absolute, 'r');
        const buffer = Buffer.alloc(Math.min(maxBytes, 256 * 1024));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const text = buffer.subarray(0, bytesRead).toString('utf8');
        const lines = text.split('\n');
        const value = lines[line - 1];
        return value === undefined ? undefined : truncate(normalizeLine(value), 400);
    }
    catch {
        return undefined;
    }
    finally {
        await handle?.close().catch(() => undefined);
    }
}
