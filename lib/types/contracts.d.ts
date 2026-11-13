import type { CoverageDocument, DraftFinding, DraftReviewState, Finding, FindingsDocument, ScanDraftInput, ScanRecord, Severity, FindingStatus } from './types.js';
export declare function normalizeRuleId(value: string): string;
export declare function normalizeAnchor(ruleId: string, path: string, lineText?: string, instance?: string): string;
export declare function fingerprintFor(ruleId: string, path: string, anchor: string, instance?: string): string;
export declare function idsFor(ruleId: string, path: string, anchor: string, instance?: string, startLine?: number): {
    findingId: string;
    occurrenceId: string;
    primary: string;
};
export declare function normalizeSeverity(input: DraftFinding['severity']): Finding['severity'];
export declare function normalizeConfidence(input: DraftFinding['confidence']): Finding['confidence'];
export declare function normalizeLocation(input: {
    path: string;
    startLine: number;
    endLine?: number;
    role?: string;
}): {
    path: string;
    startLine: number;
    endLine?: number;
    role?: string;
};
export interface NormalizeFindingOptions {
    rootPath: string;
    evidenceLines?: Map<string, string>;
}
export declare function normalizeFinding(scanId: string, input: DraftFinding, options: NormalizeFindingOptions): Finding;
export declare function validateDraft(input: unknown): ScanDraftInput;
export declare function buildFindingsDocument(scanId: string, findings: Finding[]): FindingsDocument;
export declare function severityCounts(findings: Finding[]): Record<Severity, number>;
export declare function sortedFindings(findings: Finding[]): Finding[];
export declare function buildCoverage(scan: ScanRecord, reviewState: DraftReviewState, modeOverride?: string): CoverageDocument;
export declare function policyGate(findings: Finding[], threshold: string): {
    threshold: string;
    status: 'pass' | 'fail';
    failing: number;
};
export declare function renderReport(scan: ScanRecord, findings: Finding[], coverage: CoverageDocument, options: {
    sealedAt: string;
    threatModel?: Record<string, unknown> | string;
}): string;
export declare function toSarif(scan: ScanRecord, findings: Finding[]): Record<string, unknown>;
export declare function toCsv(findings: Finding[]): string;
export declare function findingStatusOf(entry?: {
    status?: FindingStatus;
}): FindingStatus;
