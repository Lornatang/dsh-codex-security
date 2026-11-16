export declare const name = "codex-security-worker-preset";
export declare const inject: string[];
interface WorkerPresetContext {
    tools: {
        guard(callback: (execution: {
            name: string;
        }) => string | undefined): () => void;
    };
    effect(callback: () => () => void, label?: string): () => void;
}
/** A worker's own preset retains this guard on cold resume. */
export declare function apply(ctx: WorkerPresetContext): void;
declare const _default: {
    name: string;
    inject: string[];
    apply: typeof apply;
};
export default _default;
