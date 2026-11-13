export interface GitResult {
    ok: boolean;
    stdout: string;
    stderr: string;
}
export declare function git(root: string, args: string[], timeoutMs?: number): Promise<GitResult>;
export declare function gitString(root: string, args: string[], timeoutMs?: number): Promise<string | undefined>;
export declare function isGitRepo(root: string): Promise<boolean>;
export declare function repoRoot(path: string): Promise<string | undefined>;
export declare function headRevision(root: string): Promise<string | undefined>;
export declare function currentBranch(root: string): Promise<string | undefined>;
export declare function remoteUrl(root: string): Promise<string | undefined>;
export declare function resolveRevision(root: string, ref: string): Promise<string | undefined>;
export interface StatusEntry {
    code: string;
    path: string;
}
export declare function statusEntries(root: string): Promise<StatusEntry[]>;
export declare function trackedFiles(root: string): Promise<string[]>;
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
/** Digest of the working tree diff including untracked files, used for snapshot identity. */
export declare function worktreeDigest(root: string): Promise<string>;
export declare function fileDigest(path: string): Promise<string | undefined>;
