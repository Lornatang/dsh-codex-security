export interface StateLockOptions {
    signal?: AbortSignal;
    timeoutMs?: number;
}
/**
 * Hold SQLite's OS-backed writer lock on a persistent local lock database.
 * The database is never removed; the OS releases the lock on process exit.
 */
export declare function acquireStateLock(path: string, options?: StateLockOptions): Promise<() => void>;
