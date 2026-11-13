import type { Finding, ScanRecord, ScanSummary, TriageEntry } from './types.js';
export interface ScanIndex {
    version: 1;
    scans: Record<string, ScanSummary & {
        repoKey: string;
    }>;
}
export interface CreateScanInput {
    scanId: string;
    mode: ScanRecord['mode'];
    promptOnly: boolean;
    target: ScanRecord['target'];
    scope: ScanRecord['scope'];
    inventory: ScanRecord['inventory'];
    diffFiles?: ScanRecord['diffFiles'];
    budget?: ScanRecord['budget'];
    notes?: string;
    threatModel?: ScanRecord['threatModel'];
    previousScanId?: string;
    warnings: string[];
}
export declare function defaultStateDir(patchPath: string | undefined, configured: string): string;
export declare function repoKeyFor(rootPath: string): string;
export declare function summarize(record: ScanRecord): ScanSummary;
export declare class ScanStore {
    readonly stateDir: string;
    private indexCache;
    private queue;
    constructor(stateDir: string);
    private get indexPath();
    scanDir(record: Pick<ScanRecord, 'repoKey' | 'scanId'>): string;
    init(): Promise<void>;
    private serialize;
    loadIndex(): Promise<ScanIndex>;
    private rebuildIndex;
    saveIndex(index: ScanIndex): Promise<void>;
    create(input: CreateScanInput): Promise<ScanRecord>;
    private writeRecord;
    get(scanId: string): Promise<{
        record: ScanRecord;
        dir: string;
    } | undefined>;
    update(scanId: string, mutate: (record: ScanRecord) => void): Promise<ScanRecord>;
    writeScanFile(scanId: string, name: string, value: unknown): Promise<string>;
    readScanFile<T>(scanId: string, name: string): Promise<T | undefined>;
    list(): Promise<ScanSummary[]>;
    saveArtifact(scanId: string, relativePath: string, content: string, mediaType: string): Promise<{
        path: string;
        bytes: number;
        sha256: string;
        mediaType: string;
    }>;
    readArtifact(scanId: string, relativePath: string, limit: number): Promise<{
        path: string;
        content: string;
        bytes: number;
        truncated: boolean;
    }>;
    listArtifacts(scanId: string): Promise<{
        path: string;
        bytes: number;
    }[]>;
    readTriage(scanId: string): Promise<Record<string, TriageEntry>>;
    setTriage(scanId: string, entry: TriageEntry): Promise<TriageEntry>;
    readFindings(scanId: string): Promise<Finding[]>;
}
