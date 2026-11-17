import { createHash, randomBytes } from 'node:crypto';
import { link, mkdir, open, readFile, readdir, realpath, rename, rm } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
export function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
}
/** A workspace's identity must not depend on its current revision or scan mode. */
export function stableTargetId(rootPath) {
    return 'target_sha256_' + sha256('local-workspace\u0000' + resolve(rootPath));
}
export function nowIso() {
    return new Date().toISOString();
}
export function newId(prefix, hexChars = 24) {
    return prefix + randomBytes(Math.ceil(hexChars / 2)).toString('hex').slice(0, hexChars);
}
export function shortId(value, length = 8) {
    return value.slice(0, length);
}
export async function ensureDir(path) {
    await mkdir(path, { recursive: true, mode: 0o700 });
}
export async function writeFileAtomic(path, data) {
    await ensureDir(dirname(path));
    const tmp = join(dirname(path), '.' + process.pid + '.' + randomBytes(12).toString('hex') + '.tmp');
    const handle = await open(tmp, 'wx', 0o600);
    try {
        try {
            await handle.writeFile(data);
        }
        finally {
            await handle.close();
        }
        const deadline = Date.now() + 2000;
        let pause = 10;
        for (;;) {
            try {
                await rename(tmp, path);
                break;
            }
            catch (error) {
                const code = error.code;
                if (process.platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(code ?? '') || Date.now() >= deadline)
                    throw error;
                await delay(pause);
                pause = Math.min(100, pause * 2);
            }
        }
    }
    catch (error) {
        await rm(tmp, { force: true }).catch(() => undefined);
        throw error;
    }
}
/** Publish a complete file without ever replacing an existing destination. */
export async function writeFileExclusive(path, data) {
    const tmp = join(dirname(path), '.' + process.pid + '.' + randomBytes(12).toString('hex') + '.tmp');
    const handle = await open(tmp, 'wx', 0o600);
    try {
        try {
            await handle.writeFile(data);
        }
        finally {
            await handle.close();
        }
        try {
            await link(tmp, path);
        }
        catch (error) {
            // Some writable filesystems do not support hard links.
            if (!['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS'].includes(error.code ?? ''))
                throw error;
            const destination = await open(path, 'wx', 0o600);
            try {
                await destination.writeFile(data);
            }
            finally {
                await destination.close();
            }
        }
    }
    finally {
        await rm(tmp, { force: true });
    }
}
/** Resolve symlinked ancestors even when the final path does not yet exist. */
export async function canonicalProspectivePath(path) {
    let current = resolve(path);
    const suffix = [];
    for (;;) {
        try {
            return resolve(await realpath(current), ...suffix);
        }
        catch (error) {
            if (error.code !== 'ENOENT')
                throw error;
            const parent = dirname(current);
            if (parent === current)
                throw error;
            suffix.unshift(basename(current));
            current = parent;
        }
    }
}
export async function writeJsonAtomic(path, value) {
    await writeFileAtomic(path, JSON.stringify(value, null, 2) + '\n');
}
export async function readJson(path) {
    try {
        return JSON.parse(await readFile(path, 'utf8'));
    }
    catch (error) {
        if (error.code === 'ENOENT')
            return undefined;
        if (error instanceof SyntaxError)
            return undefined;
        throw error;
    }
}
export async function readText(path, limit = 1024 * 1024) {
    let handle;
    try {
        handle = await open(path, 'r');
        const size = Math.max(0, Math.floor(limit));
        const buffer = Buffer.alloc(size);
        const { bytesRead } = await handle.read(buffer, 0, size, 0);
        return buffer.subarray(0, bytesRead).toString('utf8');
    }
    catch (error) {
        if (error.code === 'ENOENT')
            return undefined;
        throw error;
    }
    finally {
        await handle?.close().catch(() => undefined);
    }
}
export async function readFullText(path) {
    try {
        return await readFile(path, 'utf8');
    }
    catch (error) {
        if (error.code === 'ENOENT')
            return undefined;
        throw error;
    }
}
export function posixRelative(root, path) {
    return relative(root, path).split(sep).join('/');
}
/** Reject absolute paths, drive letters and .. segments; return a normalized posix relative path. */
export function sanitizeRelative(input) {
    if (typeof input !== 'string' || input.length === 0)
        throw new Error('path must be a non-empty string');
    if (isAbsolute(input) || /^[A-Za-z]:[\\/]/.test(input))
        throw new Error('path must be relative: ' + input);
    const normalized = normalize(input.split('\\').join('/')).split(sep).join('/');
    const parts = normalized.split('/').filter(Boolean);
    if (parts.includes('..'))
        throw new Error('path must not contain ..: ' + input);
    if (parts.length === 0)
        throw new Error('path must not be empty');
    return parts.join('/');
}
export function isWithin(parent, child) {
    const rel = relative(resolve(parent), resolve(child));
    return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel));
}
export function joinWithin(root, relPath) {
    const safe = sanitizeRelative(relPath);
    const joined = resolve(root, safe);
    if (!isWithin(root, joined))
        throw new Error('path escapes the allowed root: ' + relPath);
    return joined;
}
/** Convert a gitignore-style glob into a RegExp matched against a posix relative path. */
export function globToRegExp(pattern) {
    let value = pattern.trim();
    if (value.startsWith('./'))
        value = value.slice(2);
    let negate = false;
    if (value.startsWith('!')) {
        negate = true;
        value = value.slice(1);
    }
    if (value.endsWith('/'))
        value += '**';
    const anchored = value.includes('/');
    let out = '';
    for (let i = 0; i < value.length; i++) {
        const char = value[i];
        if (char === '*') {
            if (value[i + 1] === '*') {
                out += '.*';
                i += 1;
                if (value[i + 1] === '/')
                    i += 1;
            }
            else
                out += '[^/]*';
        }
        else if (char === '?')
            out += '[^/]';
        else if ('\\^$+.()|{}[]'.includes(char))
            out += '\\' + char;
        else
            out += char;
    }
    // Collapse adjacent identical quantifiers so crafted globs cannot trigger catastrophic backtracking.
    out = out.replace(/(?:\.\*){2,}/g, '.*').replace(/(?:\[\^\/\]\*){2,}/g, '[^/]*');
    const prefix = anchored ? '^' : '(?:^|.*/)';
    const re = new RegExp(prefix + out + '$');
    return negate ? new RegExp('^(?!' + re.source.replace(/^\^/, '') + ').*$') : re;
}
const GLOB_CACHE = new Map();
const GLOB_CACHE_LIMIT = 4096;
const GLOB_MAX_LENGTH = 1024;
/** Compile a glob once into tokens; matching uses a linear-time DP that cannot backtrack exponentially. */
function compileGlob(pattern) {
    const cached = GLOB_CACHE.get(pattern);
    if (cached !== undefined || GLOB_CACHE.has(pattern))
        return cached ?? null;
    let compiled = null;
    try {
        let value = pattern.trim();
        if (value.length > GLOB_MAX_LENGTH)
            throw new Error('glob pattern too long');
        if (value.startsWith('./'))
            value = value.slice(2);
        let negate = false;
        if (value.startsWith('!')) {
            negate = true;
            value = value.slice(1);
        }
        if (value.endsWith('/'))
            value += '**';
        const anchored = value.includes('/');
        const tokens = [];
        let literal = '';
        const flush = () => { if (literal) {
            tokens.push({ kind: 'literal', value: literal });
            literal = '';
        } };
        for (let i = 0; i < value.length; i++) {
            const char = value[i];
            if (char === '*') {
                if (value[i + 1] === '*') {
                    flush();
                    tokens.push({ kind: 'globstar' });
                    i += 1;
                    if (value[i + 1] === '/')
                        i += 1;
                }
                else {
                    flush();
                    tokens.push({ kind: 'star' });
                }
            }
            else if (char === '?') {
                flush();
                tokens.push({ kind: 'qmark' });
            }
            else
                literal += char;
        }
        flush();
        compiled = { negate, anchored, tokens };
    }
    catch {
        compiled = null;
    }
    if (GLOB_CACHE.size >= GLOB_CACHE_LIMIT)
        GLOB_CACHE.clear();
    GLOB_CACHE.set(pattern, compiled);
    return compiled;
}
/** Full-match a token sequence against str in O(tokens x length) time (no catastrophic backtracking). */
function globBodyMatch(tokens, str) {
    const n = str.length;
    let dp = new Uint8Array(n + 1);
    dp[0] = 1;
    for (const token of tokens) {
        const next = new Uint8Array(n + 1);
        if (token.kind === 'literal') {
            const lit = token.value;
            const len = lit.length;
            for (let j = 0; j + len <= n; j++)
                if (dp[j] && str.startsWith(lit, j))
                    next[j + len] = 1;
        }
        else if (token.kind === 'qmark') {
            for (let j = 0; j < n; j++)
                if (dp[j] && str[j] !== '/')
                    next[j + 1] = 1;
        }
        else if (token.kind === 'star') {
            next[0] = dp[0] ?? 0;
            for (let j = 1; j <= n; j++)
                next[j] = (dp[j] ?? 0) || (str[j - 1] !== '/' && (next[j - 1] ?? 0) ? 1 : 0);
        }
        else {
            next[0] = dp[0] ?? 0;
            for (let j = 1; j <= n; j++)
                next[j] = (dp[j] ?? 0) || (next[j - 1] ?? 0);
        }
        dp = next;
    }
    return dp[n] === 1;
}
function globPositiveMatch(compiled, path) {
    if (compiled.anchored)
        return globBodyMatch(compiled.tokens, path);
    if (globBodyMatch(compiled.tokens, path))
        return true;
    for (let i = 0; i < path.length; i++)
        if (path[i] === '/' && globBodyMatch(compiled.tokens, path.slice(i + 1)))
            return true;
    return false;
}
export function matchesAny(relPath, patterns) {
    const path = relPath.split(sep).join('/');
    for (const pattern of patterns) {
        if (!pattern)
            continue;
        const compiled = compileGlob(pattern);
        if (!compiled)
            continue;
        const matched = globPositiveMatch(compiled, path);
        if (compiled.negate ? !matched : matched)
            return true;
    }
    return false;
}
/** Match either a directory path and its descendants, or an explicit glob. */
export function matchesScopePath(relPath, patterns) {
    return patterns.some((pattern) => {
        const clean = pattern.replace(/^\.\//, '').replace(/\/$/, '');
        return clean === '' || clean === '.' || relPath === clean || relPath.startsWith(clean + '/') || matchesAny(relPath, [pattern]);
    });
}
const BINARY_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.tar', '.jar', '.war', '.class', '.so', '.dylib', '.dll', '.exe', '.bin', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.mp4', '.mov', '.webm', '.wasm', '.sqlite', '.db', '.pyc', '.o', '.a', '.node', '.snap', '.avif', '.bmp']);
export function isProbablyBinary(path) {
    const dot = path.lastIndexOf('.');
    return dot >= 0 && BINARY_EXTENSIONS.has(path.slice(dot).toLowerCase());
}
export function languageOf(path) {
    const dot = path.lastIndexOf('.');
    if (dot < 0)
        return 'other';
    const ext = path.slice(dot).toLowerCase();
    const map = {
        '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
        '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
        '.py': 'python', '.go': 'go', '.rs': 'rust', '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin',
        '.rb': 'ruby', '.php': 'php', '.c': 'c', '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.hpp': 'cpp',
        '.cs': 'csharp', '.swift': 'swift', '.m': 'objective-c', '.mm': 'objective-c', '.scala': 'scala',
        '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ps1': 'powershell', '.sql': 'sql',
        '.yml': 'yaml', '.yaml': 'yaml', '.json': 'json', '.toml': 'toml', '.xml': 'xml', '.html': 'html',
        '.vue': 'vue', '.svelte': 'svelte', '.dart': 'dart', '.lua': 'lua', '.pl': 'perl', '.r': 'r',
        '.tf': 'terraform', '.proto': 'protobuf', '.graphql': 'graphql', '.md': 'markdown',
    };
    return map[ext] ?? 'other';
}
export function slugify(value, max = 48) {
    const slug = value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').replace(/--+/g, '-').slice(0, max);
    return slug || 'finding';
}
export function compareSeverity(a, b) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    return (order[a] ?? 9) - (order[b] ?? 9);
}
export function truncate(value, max) {
    return value.length <= max ? value : value.slice(0, Math.max(0, max - 1)) + '\u2026';
}
export function formatBytes(value) {
    if (value < 1024)
        return value + ' B';
    if (value < 1024 * 1024)
        return (value / 1024).toFixed(1) + ' KB';
    return (value / (1024 * 1024)).toFixed(1) + ' MB';
}
export async function listFiles(root, options) {
    const files = [];
    const excluded = [];
    const symlinks = [];
    let truncated = false;
    const walk = async (dir, relBase) => {
        options.signal?.throwIfAborted();
        if (truncated)
            return;
        let entries;
        try {
            entries = await readdir(dir, { withFileTypes: true });
        }
        catch (error) {
            throw new Error('codex-security: cannot enumerate target directory: ' + dir, { cause: error });
        }
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            options.signal?.throwIfAborted();
            if (truncated)
                return;
            const rel = relBase ? relBase + '/' + entry.name : entry.name;
            if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.hg' || entry.name === '.svn') {
                excluded.push(rel);
                continue;
            }
            if (matchesAny(rel, options.exclude)) {
                excluded.push(rel);
                continue;
            }
            if (entry.isSymbolicLink()) {
                excluded.push(rel);
                symlinks.push(rel);
                continue;
            }
            if (entry.isDirectory()) {
                await walk(join(dir, entry.name), rel);
                continue;
            }
            if (!entry.isFile())
                continue;
            if (options.include && options.include.length > 0 && !matchesScopePath(rel, options.include))
                continue;
            if (options.filter && !options.filter(rel))
                continue;
            if (files.length >= options.maxFiles) {
                truncated = true;
                return;
            }
            files.push(rel);
        }
    };
    await walk(root, '');
    return { files, truncated, excluded, symlinks };
}
export function normalizeLine(value) {
    return value.replace(/\s+/g, ' ').trim();
}
