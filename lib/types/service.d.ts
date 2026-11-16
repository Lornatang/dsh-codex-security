import type { Config } from './config.js';
import type { PluginContext } from './types.js';
import { ScanStore } from './store.js';
import type { WorkerSnapshot } from './deep-worker.js';
export declare const FORMATS: readonly ["sarif", "json", "csv", "markdown"];
export type ExportFormat = (typeof FORMATS)[number];
type Json = Record<string, unknown>;
export interface SecurityServiceOptions {
    config?: Partial<Config>;
    patchPath?: string;
}
export declare class SecurityService {
    readonly store: ScanStore;
    readonly config: Config;
    private readonly ctx;
    private readonly scanLocks;
    private readonly managedInvocations;
    constructor(ctx: PluginContext, options?: SecurityServiceOptions);
    /** Serialize complete read-modify-write operations across instances and processes. */
    private withScanLock;
    /** Internal capability: tool-provided JSON cannot grant access to a managed scan. */
    withManagedAccess<T>(args: Json, operation: () => Promise<T>): Promise<T>;
    private requireRunningScan;
    private ready;
    private requireScan;
    status(): Promise<Json>;
    publicConfig(): Json;
    inspectSetup(): Promise<Json>;
    inspectTarget(args: Json): Promise<Json>;
    startDefaultScan(args: Json): Promise<Json>;
    startScan(args: Json, kind: 'standard' | 'prompt-only' | 'deep', options?: {
        scanId?: string;
        managedParent?: string;
        signal?: AbortSignal;
    }): Promise<Json>;
    private scanInstructions;
    private promptOnlyPrompt;
    getScanContext(args: Json): Promise<Json>;
    private countBy;
    updateScanContext(args: Json): Promise<Json>;
    private updateScanContextUnlocked;
    updateScanProgress(args: Json): Promise<Json>;
    /** Set an absolute count from the durable coordinator journal after a restart. */
    setManagedProgress(args: Json): Promise<void>;
    private updateScanProgressUnlocked;
    recordScanDraft(args: Json, options?: {
        workerSnapshot: WorkerSnapshot;
        signal?: AbortSignal;
    }): Promise<Json>;
    private recordScanDraftUnlocked;
    private collectEvidenceLines;
    private collectBoundEvidenceLines;
    recordDiscoveryCandidates(args: Json): Promise<Json>;
    private recordDiscoveryCandidatesUnlocked;
    private severityOf;
    listCandidates(args: Json): Promise<Json>;
    recordCandidateValidations(args: Json): Promise<Json>;
    private recordCandidateValidationsUnlocked;
    recordCandidateAttackPaths(args: Json): Promise<Json>;
    private recordCandidateAttackPathsUnlocked;
    saveArtifact(args: Json): Promise<Json>;
    private saveArtifactUnlocked;
    readArtifact(args: Json): Promise<Json>;
    completeScan(args: Json, options?: {
        signal?: AbortSignal;
    }): Promise<Json>;
    private completeScanUnlocked;
    failScan(args: Json): Promise<Json>;
    private failScanUnlocked;
    cancelScan(args: Json): Promise<Json>;
    private cancelScanUnlocked;
    listScans(args: Json): Promise<Json>;
    getScan(args: Json): Promise<Json>;
    private findingsWithStatus;
    listFindings(args: Json): Promise<Json>;
    setFindingTriage(args: Json): Promise<Json>;
    private setFindingTriageUnlocked;
    setFindingRemediation(args: Json): Promise<Json>;
    private setFindingRemediationUnlocked;
    exportContent(scanId: string, format: string): Promise<{
        content: string;
        mediaType: string;
        filename: string;
        count: number;
        policy?: Json;
    }>;
    exportFindings(args: Json): Promise<Json>;
    prepareReviewItems(args: Json): Promise<Json>;
    private prepareReviewItemsUnlocked;
    listReviewItems(args: Json): Promise<Json>;
    updateReviewItem(args: Json): Promise<Json>;
    compareScans(args: Json): Promise<Json>;
}
export {};
