export interface GitResult {
    ok: boolean;
    stdout: string;
    stderr: string;
}
export declare function git(root: string, args: string[], timeoutMs?: number, signal?: AbortSignal): Promise<GitResult>;
export declare function gitString(root: string, args: string[], timeoutMs?: number, signal?: AbortSignal): Promise<string | undefined>;
export declare function repoRoot(path: string, signal?: AbortSignal): Promise<string | undefined>;
export declare function headRevision(root: string, signal?: AbortSignal): Promise<string | undefined>;
export declare function currentBranch(root: string, signal?: AbortSignal): Promise<string | undefined>;
export declare function remoteUrl(root: string, signal?: AbortSignal): Promise<string | undefined>;
export declare function resolveRevision(root: string, ref: string, signal?: AbortSignal): Promise<string | undefined>;
export interface StatusEntry {
    code: string;
    path: string;
}
export declare function statusEntries(root: string, signal?: AbortSignal): Promise<StatusEntry[]>;
export declare function trackedFiles(root: string, signal?: AbortSignal): Promise<string[]>;
export interface ChangedFile {
    status: string;
    path: string;
    oldPath?: string;
}
export declare function changedFiles(root: string, options: {
    base?: string;
    staged?: boolean;
    workingTree?: boolean;
}): Promise<ChangedFile[]>;
export declare function fileDigest(path: string, signal?: AbortSignal): Promise<string | undefined>;
