import type { Config } from './config.js';
import type { PluginContext } from './types.js';
import { ScanStore } from './store.js';
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
    constructor(ctx: PluginContext, options?: SecurityServiceOptions);
    private ready;
    private requireScan;
    status(): Promise<Json>;
    publicConfig(): Json;
    inspectSetup(): Promise<Json>;
    inspectTarget(args: Json): Promise<Json>;
    startScan(args: Json, kind: 'standard' | 'prompt-only' | 'deep'): Promise<Json>;
    private scanInstructions;
    private promptOnlyPrompt;
    getScanContext(args: Json): Promise<Json>;
    private countBy;
    updateScanContext(args: Json): Promise<Json>;
    updateScanProgress(args: Json): Promise<Json>;
    recordScanDraft(args: Json): Promise<Json>;
    private collectEvidenceLines;
    recordDiscoveryCandidates(args: Json): Promise<Json>;
    private severityOf;
    listCandidates(args: Json): Promise<Json>;
    recordCandidateValidations(args: Json): Promise<Json>;
    recordCandidateAttackPaths(args: Json): Promise<Json>;
    saveArtifact(args: Json): Promise<Json>;
    readArtifact(args: Json): Promise<Json>;
    completeScan(args: Json): Promise<Json>;
    failScan(args: Json): Promise<Json>;
    cancelScan(args: Json): Promise<Json>;
    listScans(args: Json): Promise<Json>;
    getScan(args: Json): Promise<Json>;
    private findingsWithStatus;
    listFindings(args: Json): Promise<Json>;
    setFindingTriage(args: Json): Promise<Json>;
    setFindingRemediation(args: Json): Promise<Json>;
    exportContent(scanId: string, format: string): Promise<{
        content: string;
        mediaType: string;
        filename: string;
        count: number;
        policy?: Json;
    }>;
    exportFindings(args: Json): Promise<Json>;
    prepareReviewItems(args: Json): Promise<Json>;
    listReviewItems(args: Json): Promise<Json>;
    compareScans(args: Json): Promise<Json>;
}
export {};
