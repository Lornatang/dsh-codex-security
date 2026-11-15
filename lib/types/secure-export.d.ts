export interface SecureExportOptions {
    requestedOutput: string;
    requested: boolean;
    scanId: string;
    extension: string;
    content: string;
    validate(output: string): Promise<void>;
    /** Internal test barriers; never exposed through the tool interface. */
    onPhase?(phase: 'pinned' | 'before-mkdir' | 'before-publish' | 'after-publish' | 'before-cleanup'): Promise<void>;
}
/** Re-resolve protected locations and retain their original directory identities. */
export declare function createExportValidator(options: {
    requestedOutput: string;
    allowedRoots: readonly string[];
    scanRoot: string;
    gitDirs: readonly string[];
    allowOutside: boolean;
    resolveGitDirs?(): Promise<readonly string[]>;
}): Promise<(output: string) => Promise<void>>;
/** Pin the output directory object before applying policy or mutating the tree. */
export declare function writeSecureExport(options: SecureExportOptions): Promise<string>;
