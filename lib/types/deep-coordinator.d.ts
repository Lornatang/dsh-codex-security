import { WorkerRegistry } from './deep-worker.js';
import type { SecurityService } from './service.js';
type Json = Record<string, unknown>;
export interface DeepActor {
    agent: {
        id: string;
    };
    signal?: AbortSignal;
}
export interface DeepActivation {
    childId: string;
    result: Promise<{
        stopReason: string;
        structured?: unknown;
    }>;
    dispose(): Promise<void>;
}
export interface DeepHost {
    ensureReady(): Promise<void>;
    start(request: {
        childId: string;
        agent: DeepActor['agent'];
        signal: AbortSignal;
        prompt: string;
        outputSchema: object;
    }): Promise<DeepActivation>;
}
/** Public status omits the recovery-claim digest, source snapshots and worker output. */
export declare function readDeepStatus(service: SecurityService, scanId: string, actor: DeepActor): Promise<Json>;
/** Whether a Deep journal exists for a scan id, without disclosing its contents. */
export declare function hasDeepJournal(service: SecurityService, scanId: string): Promise<boolean>;
/** Owns a Deep campaign until it seals or is interrupted. State lives on disk, not in this instance. */
export declare class DeepCoordinator {
    private readonly service;
    private readonly registry;
    private readonly host;
    private readonly running;
    private readonly controllers;
    private readonly disposing;
    constructor(service: SecurityService, registry: WorkerRegistry, host: DeepHost);
    private journalPath;
    private lockPath;
    private transitionPath;
    private cancelPath;
    private save;
    private read;
    private authorize;
    start(args: Json, actor: DeepActor): Promise<Json>;
    resume(args: Json, actor: DeepActor): Promise<Json>;
    cancel(args: Json, actor: DeepActor): Promise<Json>;
    wait(scanId: string): Promise<void>;
    /** Authorize mutable post-scan metadata against the owning campaign. */
    mutateManaged<T>(args: Json, actor: DeepActor, action: () => Promise<T>): Promise<T>;
    dispose(): Promise<void>;
    private launch;
    private managed;
    private syncProgress;
    private verifyStartRoot;
    private cancelOwned;
    private failOwned;
    private initializeSnapshot;
    private worker;
    private processResult;
    private failChild;
    private processFailure;
    private merge;
    private finish;
    private finishUnlocked;
    private updateNoNew;
    private run;
}
export {};
