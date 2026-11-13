import z from '@deepseek-ai/schemastery';
export const DEFAULT_CONFIG = {
    stateDir: '',
    maxFiles: 5000,
    maxFileBytes: 1048576,
    defaultMode: 'standard',
    failOnSeverity: 'high',
    allowExportOutsideWorkspace: false,
    maxScanAgeDays: 30,
    deepWorkers: 4,
    deepMaxDiscoveryRuns: 40,
};
export const Config = z.object({
    stateDir: z.string().default(''),
    maxFiles: z.number().step(1).min(1).max(200000).default(5000),
    maxFileBytes: z.number().step(1).min(1024).max(64 * 1024 * 1024).default(1048576),
    defaultMode: z.string().default('standard'),
    failOnSeverity: z.string().default('high'),
    allowExportOutsideWorkspace: z.boolean().default(false),
    maxScanAgeDays: z.number().step(1).min(1).max(3650).default(30),
    deepWorkers: z.number().step(1).min(1).max(32).default(4),
    deepMaxDiscoveryRuns: z.number().step(1).min(1).max(10000).default(40),
});
