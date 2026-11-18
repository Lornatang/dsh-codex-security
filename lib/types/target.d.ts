import type { InventoryInfo, ScopeInfo, TargetInfo } from './types.js';
export interface ResolveTargetOptions {
    targetPath?: string;
    includePaths?: string[];
    excludePaths?: string[];
    diffTarget?: string;
    workingTree?: boolean;
    maxFiles: number;
    maxFileBytes: number;
    signal?: AbortSignal;
}
export interface ResolvedTarget {
    target: TargetInfo;
    scope: ScopeInfo;
    inventory: InventoryInfo;
    files: string[];
    diffFiles?: DiffSnapshot['files'];
    warnings: string[];
}
export declare function resolveTarget(options: ResolveTargetOptions): Promise<ResolvedTarget>;
export interface DiffSnapshot {
    files: {
        status: string;
        path: string;
        oldPath?: string;
    }[];
    base?: string;
    head?: string;
    workingTree: boolean;
}
export declare function resolveDiff(rootPath: string, options: {
    diffTarget?: string;
    staged?: boolean;
    workingTree?: boolean;
}): Promise<DiffSnapshot>;
/** Read one source line for anchor derivation without trusting it as instructions. */
export declare function readEvidenceLine(rootPath: string, path: string, line: number, maxBytes: number): Promise<string | undefined>;
/**
 * Read many evidence lines with one hardened open per source file. The old
 * per-line reader repeated the lstat/open/realpath verification and re-read the
 * file prefix for every requested line, so a draft citing several lines of one
 * file paid that cost repeatedly.
 */
export declare function readEvidenceLines(rootPath: string, requests: {
    path: string;
    line: number;
}[], maxBytes: number): Promise<Map<string, string>>;
