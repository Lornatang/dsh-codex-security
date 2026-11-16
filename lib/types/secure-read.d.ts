type Identity = {
    dev: bigint;
    ino: bigint;
};
/** Require an exact portable relative path; never normalize away traversal. */
export declare function workerSourcePath(value: string): string;
export declare function sourceRootIdentity(root: string): {
    path: string;
    identity: Identity;
};
/** Read through pinned handles, then verify the exact bytes against the bound snapshot. */
export declare function readWorkerSource(root: string, path: string, maxBytes: number, identity: Identity, expectedHash?: string): Buffer;
/** Hash oversized files through the same pinned handles without exposing their contents. */
export declare function digestWorkerSource(root: string, path: string, identity: Identity, signal?: AbortSignal): Promise<string>;
export {};
