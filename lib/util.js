import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';
export function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
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
    const tmp = join(dirname(path), '.' + process.pid + '.' + Date.now() + '.' + randomBytes(4).toString('hex') + '.tmp');
    try {
        await writeFile(tmp, data);
        await rename(tmp, path);
    }
    catch (error) {
        await rm(tmp, { force: true }).catch(() => undefined);
        throw error;
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
    try {
        const value = await readFile(path);
        return value.subarray(0, limit).toString('utf8');
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
    const prefix = anchored ? '^' : '(?:^|.*/)';
    const re = new RegExp(prefix + out + '$');
    return negate ? new RegExp('^(?!' + re.source.replace(/^\^/, '') + ').*$') : re;
}
export function matchesAny(relPath, patterns) {
    const path = relPath.split(sep).join('/');
    for (const pattern of patterns) {
        if (!pattern)
            continue;
        try {
            if (globToRegExp(pattern).test(path))
                return true;
        }
        catch { /* ignore malformed pattern */ }
    }
    return false;
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
    let truncated = false;
    const walk = async (dir, relBase) => {
        if (truncated)
            return;
        let entries;
        try {
            entries = await readdir(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
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
                continue;
            }
            if (entry.isDirectory()) {
                await walk(join(dir, entry.name), rel);
                continue;
            }
            if (!entry.isFile())
                continue;
            if (options.include && options.include.length > 0 && !matchesAny(rel, options.include))
                continue;
            if (files.length >= options.maxFiles) {
                truncated = true;
                return;
            }
            files.push(rel);
        }
    };
    await walk(root, '');
    return { files, truncated, excluded };
}
export function normalizeLine(value) {
    return value.replace(/\s+/g, ' ').trim();
}
