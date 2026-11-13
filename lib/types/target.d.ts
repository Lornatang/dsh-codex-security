import type { InventoryInfo, ScopeInfo, TargetInfo } from './types.js';
export interface ResolveTargetOptions {
    targetPath?: string;
    includePaths?: string[];
    excludePaths?: string[];
    diffTarget?: string;
    workingTree?: boolean;
    maxFiles: number;
    maxFileBytes: number;
}
export interface ResolvedTarget {
    target: TargetInfo;
    scope: ScopeInfo;
    inventory: InventoryInfo;
    files: string[];
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
