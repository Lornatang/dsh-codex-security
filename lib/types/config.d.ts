import z from '@deepseek-ai/schemastery';
export interface Config {
    stateDir: string;
    maxFiles: number;
    maxFileBytes: number;
    defaultMode: 'standard' | 'prompt-only' | 'deep';
    failOnSeverity: 'informational' | 'low' | 'medium' | 'high' | 'critical' | 'off';
    allowExportOutsideWorkspace: boolean;
    maxScanAgeDays: number;
    deepWorkers: number;
    deepMaxDiscoveryRuns: number;
}
export declare const DEFAULT_CONFIG: Config;
export declare const Config: z<Schemastery.ObjectS<NoInfer<{
    stateDir: z<string, string, "defined">;
    maxFiles: z<number, number, "defined">;
    maxFileBytes: z<number, number, "defined">;
    defaultMode: z<"standard" | "prompt-only" | "deep", "standard" | "prompt-only" | "deep", "defined">;
    failOnSeverity: z<"informational" | "low" | "medium" | "high" | "critical" | "off", "informational" | "low" | "medium" | "high" | "critical" | "off", "defined">;
    allowExportOutsideWorkspace: z<boolean, boolean, "defined">;
    maxScanAgeDays: z<number, number, "defined">;
    deepWorkers: z<number, number, "defined">;
    deepMaxDiscoveryRuns: z<number, number, "defined">;
}>>, Schemastery.ObjectT<NoInfer<{
    stateDir: z<string, string, "defined">;
    maxFiles: z<number, number, "defined">;
    maxFileBytes: z<number, number, "defined">;
    defaultMode: z<"standard" | "prompt-only" | "deep", "standard" | "prompt-only" | "deep", "defined">;
    failOnSeverity: z<"informational" | "low" | "medium" | "high" | "critical" | "off", "informational" | "low" | "medium" | "high" | "critical" | "off", "defined">;
    allowExportOutsideWorkspace: z<boolean, boolean, "defined">;
    maxScanAgeDays: z<number, number, "defined">;
    deepWorkers: z<number, number, "defined">;
    deepMaxDiscoveryRuns: z<number, number, "defined">;
}>>, "plain">;
