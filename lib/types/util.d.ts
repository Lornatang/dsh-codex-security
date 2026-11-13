export declare function sha256(value: string | Uint8Array): string;
export declare function nowIso(): string;
export declare function newId(prefix: string, hexChars?: number): string;
export declare function shortId(value: string, length?: number): string;
export declare function ensureDir(path: string): Promise<void>;
export declare function writeFileAtomic(path: string, data: string | Uint8Array): Promise<void>;
export declare function writeJsonAtomic(path: string, value: unknown): Promise<void>;
export declare function readJson<T>(path: string): Promise<T | undefined>;
export declare function readText(path: string, limit?: number): Promise<string | undefined>;
export declare function posixRelative(root: string, path: string): string;
/** Reject absolute paths, drive letters and .. segments; return a normalized posix relative path. */
export declare function sanitizeRelative(input: string): string;
export declare function isWithin(parent: string, child: string): boolean;
export declare function joinWithin(root: string, relPath: string): string;
/** Convert a gitignore-style glob into a RegExp matched against a posix relative path. */
export declare function globToRegExp(pattern: string): RegExp;
export declare function matchesAny(relPath: string, patterns: string[]): boolean;
/** Match either a directory path and its descendants, or an explicit glob. */
export declare function matchesScopePath(relPath: string, patterns: string[]): boolean;
export declare function isProbablyBinary(path: string): boolean;
export declare function languageOf(path: string): string;
export declare function slugify(value: string, max?: number): string;
export declare function compareSeverity(a: string, b: string): number;
export declare function truncate(value: string, max: number): string;
export declare function formatBytes(value: number): string;
export declare function listFiles(root: string, options: {
    maxFiles: number;
    exclude: string[];
    include?: string[];
    filter?: (path: string) => boolean;
    followSymlinks?: boolean;
}): Promise<{
    files: string[];
    truncated: boolean;
    excluded: string[];
}>;
export declare function normalizeLine(value: string): string;
