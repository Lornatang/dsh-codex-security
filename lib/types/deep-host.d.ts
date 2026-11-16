import type { DeepActivation, DeepHost } from './deep-coordinator.js';
interface Provider {
    inheritsParentContext: boolean;
    prepareContinuable?: unknown;
    capabilities: {
        agentPreset?: boolean;
        outputSchema?: boolean;
        depthLimit?: boolean;
    };
}
export interface DshSubagents {
    getProvider(name: string): Provider | undefined;
    startActivation(spec: Record<string, unknown>): Promise<DeepActivation>;
}
export interface DshPresets {
    register(definition: Record<string, unknown>): Promise<() => Promise<void>>;
    resolve(id: string): Promise<{
        id: string;
        broken?: string;
    }>;
}
/** Use only DSH's local, fresh-context activation with a persistent restricted preset. */
export declare class DshWorkerHost implements DeepHost {
    private readonly subagents;
    private readonly presets;
    private registration?;
    constructor(subagents: DshSubagents, presets: DshPresets);
    ensureReady(): Promise<void>;
    start(request: Parameters<DeepHost['start']>[0]): Promise<DeepActivation>;
    dispose(): Promise<void>;
}
export {};
