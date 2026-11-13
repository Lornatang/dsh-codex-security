import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { join } from 'node:path';
const run = promisify(execFile);
const MAX_BUFFER = 64 * 1024 * 1024;
export async function git(root, args, timeoutMs = 60000) {
    try {
        const result = await run('git', args, { cwd: root, timeout: timeoutMs, maxBuffer: MAX_BUFFER, windowsHide: true });
        return { ok: true, stdout: String(result.stdout), stderr: String(result.stderr) };
    }
    catch (error) {
        const failed = error;
        return { ok: false, stdout: String(failed.stdout ?? ''), stderr: String(failed.stderr ?? failed.message ?? 'git failed') };
    }
}
export async function gitString(root, args, timeoutMs) {
    const result = await git(root, args, timeoutMs);
    return result.ok ? result.stdout.trim() : undefined;
}
export async function isGitRepo(root) {
    return (await gitString(root, ['rev-parse', '--is-inside-work-tree'])) === 'true';
}
export async function repoRoot(path) {
    return gitString(path, ['rev-parse', '--show-toplevel']);
}
export async function headRevision(root) {
    return gitString(root, ['rev-parse', 'HEAD']);
}
export async function currentBranch(root) {
    return gitString(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
}
export async function remoteUrl(root) {
    return gitString(root, ['config', '--get', 'remote.origin.url']);
}
export async function resolveRevision(root, ref) {
    return gitString(root, ['rev-parse', '--verify', ref + '^{commit}']);
}
export async function statusEntries(root) {
    const result = await git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']);
    if (!result.ok)
        return [];
    const items = [];
    const parts = result.stdout.split('\u0000').filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
        const entry = parts[i];
        const code = entry.slice(0, 2);
        const path = entry.slice(3);
        if (!path)
            continue;
        // Renames emit an extra path entry in porcelain v1 -z output.
        if (code.startsWith('R') || code.startsWith('C'))
            i += 1;
        items.push({ code, path });
    }
    return items;
}
export async function trackedFiles(root) {
    const result = await git(root, ['ls-files', '-z']);
    if (!result.ok)
        return [];
    return result.stdout.split('\u0000').filter(Boolean);
}
export async function changedFiles(root, options) {
    const args = ['diff', '--name-status', '-z', '--find-renames'];
    if (options.staged)
        args.push('--cached');
    if (options.base) {
        const resolved = await resolveRevision(root, options.base);
        if (!resolved)
            throw new Error('codex-security: invalid diff base: ' + options.base);
        if (options.workingTree) {
            const mergeBase = await gitString(root, ['merge-base', resolved, 'HEAD']);
            if (!mergeBase)
                throw new Error('codex-security: cannot resolve merge base: ' + options.base);
            args.push(mergeBase);
        }
        else {
            args.push(resolved + '...HEAD');
        }
    }
    else if (!options.staged) {
        args.push('HEAD');
    }
    const result = await git(root, args);
    if (!result.ok)
        throw new Error('codex-security: git diff failed: ' + result.stderr.trim());
    const parts = result.stdout.split('\u0000').filter(Boolean);
    const files = [];
    for (let i = 0; i < parts.length; i++) {
        const status = parts[i];
        const path = parts[i + 1];
        if (!path)
            break;
        i += 1;
        if (status.startsWith('R') || status.startsWith('C')) {
            const next = parts[i + 1];
            i += 1;
            files.push({ status: status.charAt(0), path: next ?? path, oldPath: path });
        }
        else {
            files.push({ status: status.charAt(0), path });
        }
    }
    if (options.workingTree && !options.staged) {
        const seen = new Set(files.map((file) => file.path));
        for (const entry of await statusEntries(root)) {
            if (entry.code === '??' && !seen.has(entry.path))
                files.push({ status: 'A', path: entry.path });
        }
    }
    return files;
}
/** Digest of the working tree diff including untracked files, used for snapshot identity. */
export async function worktreeDigest(root) {
    const hash = createHash('sha256');
    const status = await git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']);
    hash.update('status\u0000' + (status.ok ? status.stdout : ''));
    const diff = await git(root, ['diff', 'HEAD']);
    hash.update('diff\u0000' + (diff.ok ? diff.stdout : diff.stderr));
    const staged = await git(root, ['diff', '--cached']);
    hash.update('staged\u0000' + (staged.ok ? staged.stdout : ''));
    const untracked = await git(root, ['ls-files', '--others', '--exclude-standard', '-z']);
    if (untracked.ok) {
        const names = untracked.stdout.split('\u0000').filter(Boolean).sort();
        for (const name of names)
            hash.update('untracked\u0000' + name + '\u0000' + (await fileDigest(join(root, name)) ?? 'unavailable'));
    }
    return hash.digest('hex');
}
export async function fileDigest(path) {
    try {
        const hash = createHash('sha256');
        for await (const chunk of createReadStream(path))
            hash.update(chunk);
        return hash.digest('hex');
    }
    catch {
        return undefined;
    }
}
