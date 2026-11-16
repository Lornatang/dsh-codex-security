import type { TargetInfo } from './types.js';
export interface WorkerSnapshot {
    rootPath: string;
    maxFileBytes: number;
    files: Record<string, {
        sha256: string;
    }>;
    rootIdentity?: {
        dev: string;
        ino: string;
    };
    unavailable?: {
        path: string;
        reason: string;
    }[];
    observedDigests?: Record<string, string>;
}
export interface StepPosition {
    turn: number;
    step: number;
}
export interface ReceiptRange {
    start: number;
    end: number;
    total: number;
    position?: StepPosition;
}
/** Compact adjacent chunks conservatively using their latest model step. */
export declare function mergeReceiptRanges(ranges: ReceiptRange[], next: ReceiptRange): ReceiptRange[];
/** Capture exact source bytes without allowing links or paths outside the target. */
export declare function captureWorkerSnapshot(rootPath: string, paths: string[], maxFileBytes: number, signal?: AbortSignal): Promise<WorkerSnapshot>;
/** Verify that the secure per-file capture is exactly the target originally bound. */
export declare function assertWorkerSnapshotMatches(target: TargetInfo, paths: string[], snapshot: WorkerSnapshot): void;
/** Bind each worker to a fixed target and exact file digests. */
export declare class WorkerRegistry {
    private readonly workers;
    reserve(childId: string, snapshot: WorkerSnapshot, options?: {
        allowUnpositionedReceipts?: boolean;
    }): void;
    release(childId: string): void;
    has(childId: string): boolean;
    list(childId: string): string[];
    receipts(childId: string): string[];
    acceptFinalStep(childId: string, position: StepPosition): void;
    read(childId: string, path: string): Promise<string>;
    private readText;
    readChunk(childId: string, path: string, offset: number): Promise<{
        path: string;
        content: string;
        offset: number;
        nextOffset: number | null;
        totalLength: number;
    }>;
    /** Verify each delivered chunk against the snapshot before counting its covered range. */
    acceptChunk(childId: string, value: {
        path: string;
        content: string;
        offset: number;
        nextOffset: number | null;
        totalLength: number;
    }, position?: StepPosition): void;
    /** Called only after the host accepts the tool's authoritative result. */
    acceptRead(childId: string, path: string, content: string): void;
    private binding;
}
interface GuardContext {
    tools: {
        guard(callback: (execution: {
            name: string;
        }) => string | undefined): () => void;
    };
}
/** Install in the persistent worker preset, so resumed child sessions remain confined. */
export declare function installWorkerGuard(ctx: GuardContext): () => void;
interface WorkerExecution {
    name: string;
    callId?: string;
    agent?: {
        id?: string;
        session?: {
            snapshotEvents?: () => readonly {
                type: string;
                data?: Record<string, unknown>;
            }[];
        };
    };
    arguments?: unknown;
}
interface WorkerToolsContext {
    tools: {
        register(definition: Record<string, unknown>, options: {
            when: (context: {
                agent: {
                    id?: string;
                };
            }) => boolean;
        }): () => void;
    };
    on(event: string, listener: (execution: WorkerExecution, result: {
        isError: boolean;
        value?: unknown;
        content?: {
            type: string;
            text?: string;
        }[];
    }) => void): (() => void) | undefined;
}
/** Register worker-only tools; ordinary agents never receive them in their tool set. */
export declare function registerWorkerTools(ctx: WorkerToolsContext, registry: WorkerRegistry): () => void;
export {};
